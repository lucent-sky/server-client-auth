#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "crypto_utils.h"

#define DEFAULT_PORT 54321
#define BACKLOG 8
#define USER_DB_FILE "user_db.txt"
#define TMP_DB_FILE  "user_db.txt.tmp"
#define MAX_LINE 1024

typedef struct User {
    char username[USERNAME_LEN];
    UserRole role;
    char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
    struct User* next;
} User;

static User* user_list = NULL;

static ssize_t send_all(int fd, const void* buf, size_t len) {
    size_t total = 0;
    const char* p = (const char*)buf;
    while (total < len) {
        ssize_t n = send(fd, p + total, len - total, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return total;
}

static ssize_t recv_all(int fd, void* buf, size_t len) {
    size_t total = 0;
    char* p = (char*)buf;
    while (total < len) {
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        total += n;
    }
    return total;
}

static User* find_user(const char* username) {
    User* cur = user_list;
    while (cur) {
        if (strncmp(cur->username, username, USERNAME_LEN) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}
static int add_user_node(const char* username, UserRole role,
                         const char* salt_hex, const unsigned char* hash_bytes) {
    if (find_user(username)) return -1;

    User* u = (User*)calloc(1, sizeof(User));
    if (!u) return -1;

    strncpy(u->username, username, USERNAME_LEN-1);
    u->username[USERNAME_LEN-1] = '\0';
    u->role = role;
    strncpy(u->salt, salt_hex, SALT_LEN-1);
    u->salt[SALT_LEN-1] = '\0';
    memcpy(u->hash, hash_bytes, HASH_LEN);

    u->next = user_list;
    user_list = u;
    return 0;
}

static void free_user_list(void) {
    User* cur = user_list;
    while (cur) {
        User* nxt = cur->next;
        free(cur);
        cur = nxt;
    }
    user_list = NULL;
}

int load_database(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        perror("fopen user_db");
        return -1;
    }

    char line[MAX_LINE];
    int line_no = 0;

    free_user_list();

    while (fgets(line, sizeof(line), f)) {
        line_no++;
        char* nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (line[0] == '\0' || line[0] == '#') continue;

        char *username, *role_s, *salt_s, *hexhash;
        username = strtok(line, ":");
        role_s   = strtok(NULL, ":");
        salt_s   = strtok(NULL, ":");
        hexhash  = strtok(NULL, ":");

        if (!username || !role_s || !salt_s || !hexhash) {
            fprintf(stderr, "Malformed line %d in %s\n", line_no, path);
            continue;
        }

        if (strlen(username) >= USERNAME_LEN ||
            strlen(salt_s) >= SALT_LEN ||
            strlen(hexhash) != HASH_LEN*2) {
            fprintf(stderr, "Invalid field sizes in line %d\n", line_no);
            continue;
        }

        UserRole role = ROLE_USER;
        if (strcmp(role_s, "ADMIN") == 0) role = ROLE_ADMIN;
        else if (strcmp(role_s, "USER") == 0) role = ROLE_USER;
        else {
            fprintf(stderr, "Unknown role in line %d\n", line_no);
            continue;
        }

        unsigned char hash_bytes[HASH_LEN];
        if (hex_to_bytes(hexhash, hash_bytes) != HASH_LEN) {
            fprintf(stderr, "Invalid hash encoding in line %d\n", line_no);
            continue;
        }

        if (add_user_node(username, role, salt_s, hash_bytes) != 0) {
            fprintf(stderr, "Failed to add user from line %d\n", line_no);
            continue;
        }
    }

    fclose(f);
    return 0;
}

int save_database(const char* path) {
    FILE* f = fopen(TMP_DB_FILE, "w");
    if (!f) {
        perror("fopen tmp db");
        return -1;
    }

    User* cur = user_list;
    char hexbuf[HASH_LEN*2 + 1];

    while (cur) {
        bytes_to_hex(cur->hash, HASH_LEN, hexbuf);
        const char* role_s = (cur->role == ROLE_ADMIN) ? "ADMIN" : "USER";
        if (fprintf(f, "%s:%s:%s:%s\n", cur->username, role_s, cur->salt, hexbuf) < 0) {
            perror("fprintf tmp db");
            fclose(f);
            unlink(TMP_DB_FILE);
            return -1;
        }
        cur = cur->next;
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(TMP_DB_FILE, path) != 0) {
        perror("rename tmp db");
        unlink(TMP_DB_FILE);
        return -1;
    }

    return 0;
}

static void send_server_response_and_close(int client_fd, int success, const char* msg) {
    ServerResponse resp;
    resp.success = success;
    strncpy(resp.message, msg, MSG_LEN-1);
    resp.message[MSG_LEN-1] = '\0';
    send_all(client_fd, &resp, sizeof(resp));
}

static int str_to_role(const char* s, UserRole* out) {
    if (strcmp(s, "USER") == 0) { *out = ROLE_USER; return 0; }
    if (strcmp(s, "ADMIN") == 0) { *out = ROLE_ADMIN; return 0; }
    return -1;
}

static void build_listusers_message(char* buff, size_t len) {
    buff[0] = '\0';
    User* cur = user_list;
    size_t used = 0;
    while (cur) {
        const char* role_s = (cur->role == ROLE_ADMIN) ? "ADMIN" : "USER";
        int n = snprintf(buff + used, (used < len) ? (len - used) : 0,
                         "%s : %s\n", cur->username, role_s);
        if (n <= 0) break;
        used += n;
        if (used >= len) break;
        cur = cur->next;
    }
    if (used == 0) snprintf(buff, len, "(no users)\n");
}

static void handle_command_loop(int client_fd, User* authed_user) {
    while (1) {
        ClientCommand cmd;
        if (recv_all(client_fd, &cmd, sizeof(cmd)) <= 0) {
            break;
        }

        ServerResponse resp;
        resp.success = 0;
        resp.message[0] = '\0';

        int is_admin = (authed_user->role == ROLE_ADMIN);

        switch (cmd.type) {
            case CMD_ADDUSER:
                if (!is_admin) {
                    resp.success = 0;
                    strncpy(resp.message, "ERROR: Permission denied.", MSG_LEN-1);
                    send_all(client_fd, &resp, sizeof(resp));
                    break;
                } else {
                    if (strlen(cmd.arg1) == 0 || strlen(cmd.arg2) == 0) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: Missing username or password.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    char salt_buf[SALT_LEN];
                    generate_salt(salt_buf, sizeof(salt_buf));

                    unsigned char hashed[HASH_LEN];
                    hash_password_salted(cmd.arg2, salt_buf, hashed);

                    if (add_user_node(cmd.arg1, ROLE_USER, salt_buf, hashed) != 0) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: User already exists or memory error.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    if (save_database(USER_DB_FILE) != 0) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: Failed to persist user database.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    resp.success = 1;
                    strncpy(resp.message, "OK: User added.", MSG_LEN-1);
                    send_all(client_fd, &resp, sizeof(resp));
                    break;
                }

            case CMD_LISTUSERS:
                {
                    char msg[MSG_LEN];
                    build_listusers_message(msg, sizeof(msg));
                    resp.success = 1;
                    strncpy(resp.message, msg, MSG_LEN-1);
                    send_all(client_fd, &resp, sizeof(resp));
                }
                break;

            case CMD_SETROLE:
                if (!is_admin) {
                    resp.success = 0;
                    strncpy(resp.message, "ERROR: Permission denied.", MSG_LEN-1);
                    send_all(client_fd, &resp, sizeof(resp));
                    break;
                } else {
                    User* target = find_user(cmd.arg1);
                    if (!target) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: User not found.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    UserRole new_role;
                    if (str_to_role(cmd.arg2, &new_role) != 0) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: Invalid role. Use USER or ADMIN.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    target->role = new_role;
                    if (save_database(USER_DB_FILE) != 0) {
                        resp.success = 0;
                        strncpy(resp.message, "ERROR: Failed to persist user database.", MSG_LEN-1);
                        send_all(client_fd, &resp, sizeof(resp));
                        break;
                    }
                    resp.success = 1;
                    strncpy(resp.message, "OK: Role updated.", MSG_LEN-1);
                    send_all(client_fd, &resp, sizeof(resp));
                }
                break;

            case CMD_EXIT:
                resp.success = 1;
                strncpy(resp.message, "Goodbye.", MSG_LEN-1);
                send_all(client_fd, &resp, sizeof(resp));
                return;

            default:
                resp.success = 0;
                strncpy(resp.message, "ERROR: Invalid command.", MSG_LEN-1);
                send_all(client_fd, &resp, sizeof(resp));
                break;
        }
    }
}

static void handle_client(int client_fd) {
    ClientRequest creq;
    ssize_t r = recv_all(client_fd, &creq, sizeof(creq));
    printf("DEBUG(server): sizeof(ClientRequest)=%zu recv_all returned=%zd\n",
           sizeof(ClientRequest), (ssize_t)r);

    if (r <= 0) {
        printf("DEBUG(server): client closed connection or error while reading ClientRequest\n");
        close(client_fd);
        return;
    }

    creq.username[USERNAME_LEN-1] = '\0';
    printf("DEBUG(server): received username='%s'\n", creq.username);

    User* u = find_user(creq.username);
    if (!u) {
        send_server_response_and_close(client_fd, 0, "ERROR: Unknown user.");
        close(client_fd);
        return;
    }

    ServerChallenge sch;
    memset(&sch, 0, sizeof(sch));
    generate_nonce(sch.nonce, NONCE_LEN);
    strncpy(sch.salt, u->salt, SALT_LEN-1);
    sch.salt[SALT_LEN-1] = '\0';

    if (send_all(client_fd, &sch, sizeof(sch)) <= 0) {
        close(client_fd);
        return;
    }

    ClientResponse cresp;
    if (recv_all(client_fd, &cresp, sizeof(cresp)) <= 0) {
        close(client_fd);
        return;
    }

    unsigned char expected[HASH_LEN];
    compute_response(sch.nonce, u->hash, expected);

    if (memcmp(expected, cresp.response, HASH_LEN) != 0) {
        send_server_response_and_close(client_fd, 0, "ERROR: Authentication failed.");
        close(client_fd);
        return;
    }

    char welcome_msg[MSG_LEN];
    snprintf(welcome_msg, sizeof(welcome_msg),
             "Welcome %s. Role=%s",
             u->username,
             (u->role == ROLE_ADMIN ? "ADMIN" : "USER"));

    ServerResponse wresp;
    wresp.success = 1;
    strncpy(wresp.message, welcome_msg, MSG_LEN-1);
    wresp.message[MSG_LEN-1] = '\0';

    if (send_all(client_fd, &wresp, sizeof(wresp)) <= 0) {
        close(client_fd);
        return;
    }

    handle_command_loop(client_fd, u);
    close(client_fd);
}


static void debug_users(void){
    User* cur = user_list;
    int i = 0;
    printf("DEBUG: users in memory:\n");
    while (cur) {
        char hash_hex[HASH_LEN*2 + 1];
        bytes_to_hex(cur->hash, HASH_LEN, hash_hex);
        printf("  [%d] username='%s' role=%s salt='%s' hash_prefix=%.*s\n",
               i, cur->username,
               (cur->role==ROLE_ADMIN) ? "ADMIN" : "USER",
               cur->salt, 12, hash_hex);
        cur = cur->next;
        i++;
    }
    if (i==0) printf("  (none)\n");
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    if (argc >= 2) {
        port = atoi(argv[1]);
        if (port <= 0) port = DEFAULT_PORT;
    }

    if (load_database(USER_DB_FILE) != 0) {
        fprintf(stderr, "Failed to load user database. Exiting.\n");
        return 1;
    }

    debug_users();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    if (listen(sockfd, BACKLOG) < 0) {
        perror("listen");
        close(sockfd);
        return 1;
    }

    printf("Server listening on port %d\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &addrlen);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        char ipbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ipbuf, sizeof(ipbuf));
        printf("Connection from %s:%d\n", ipbuf, ntohs(client_addr.sin_port));

        handle_client(client_fd);

        printf("Connection closed for %s:%d\n", ipbuf, ntohs(client_addr.sin_port));
    }

    close(sockfd);
    free_user_list();
    return 0;
}

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>

#define USERNAME_LEN 32
#define SALT_LEN 33 //only needs to be 17; 16 + null character - extra just in case
#define HASH_LEN 32
#define NONCE_LEN 32
#define MSG_LEN 256

typedef enum{
    ROLE_USER = 0,
    ROLE_ADMIN = 1
} UserRole;

typedef struct{
    char username[USERNAME_LEN];
} ClientRequest;

typedef struct{
    char salt[SALT_LEN]; //6-8 characters + null terminator (set to 16, as suggested by chatGPT)
    unsigned char nonce[NONCE_LEN];
} ServerChallenge;

typedef struct{
    unsigned char response[HASH_LEN];
} ClientResponse;

typedef enum{
    CMD_ADDUSER,
    CMD_LISTUSERS,
    CMD_SETROLE,
    CMD_EXIT,
    CMD_INVALID
} CommandType;

typedef struct{
    CommandType type;
    char arg1[32];
    char arg2[32];
} ClientCommand;

typedef struct{
    int success;
    char message[MSG_LEN];
} ServerResponse;

#endif

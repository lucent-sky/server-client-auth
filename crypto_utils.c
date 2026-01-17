#include "crypto_utils.h"
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void hash_password_salted(const char* password,
                          const char* salt,
                          unsigned char* hash_output)
{
    unsigned char buffer[256];
    size_t plen = strlen(password);
    size_t slen = strlen(salt);

    memcpy(buffer, password, plen);
    memcpy(buffer + plen, salt, slen);

    SHA256(buffer, plen + slen, hash_output);
}

void compute_response(const unsigned char* nonce,
                      const unsigned char* salted_hash,
                      unsigned char* response_output)
{
    unsigned char combined[NONCE_LEN + HASH_LEN];

    memcpy(combined, nonce, NONCE_LEN);
    memcpy(combined + NONCE_LEN, salted_hash, HASH_LEN);

    SHA256(combined, NONCE_LEN + HASH_LEN, response_output);
}

void generate_salt(char* salt_buffer, int len)
{
    static const char hexchars[] = "0123456789abcdef";
    for (int i = 0; i < len - 1; i++)
        salt_buffer[i] = hexchars[rand() % 16];

    salt_buffer[len - 1] = '\0';
}

void generate_nonce(unsigned char* nonce_buffer, int len)
{
    for (int i = 0; i < len; i++)
        nonce_buffer[i] = rand() % 256;
}

void bytes_to_hex(const unsigned char* bytes, int len, char* hex_out)
{
    static const char* hex = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        hex_out[i * 2]     = hex[(bytes[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[bytes[i] & 0xF];
    }
    hex_out[len * 2] = '\0';
}

int hex_to_bytes(const char* hex, unsigned char* bytes_out)
{
    int len = strlen(hex);
    if (len % 2 != 0)
        return -1;  // must be even number of chars

    int byte_len = len / 2;

    for (int i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + 2*i, "%2x", &byte_val) != 1)
            return -1;
        bytes_out[i] = (unsigned char)byte_val;
    }

    return byte_len;
}

void print_hex(const unsigned char* bytes, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x", bytes[i]);
    printf("\n");
}

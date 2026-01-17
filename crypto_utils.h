#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/sha.h>
#define HASH_LEN 32
#define NONCE_LEN 32
#define SALT_LEN 33 //once again suggested by chatGPT

void hash_password_salted(const char* password, const char* salt, unsigned char* hash_output);

void compute_response(const unsigned char* nonce, const unsigned char* hash, unsigned char* response_output);

void generate_nonce(unsigned char* nonce_buffer, int len);

void generate_salt(char* salt_buffer, int len);

void print_hex(const unsigned char* bytes, int len);

void bytes_to_hex(const unsigned char* bytes, int len, char* hex_out);

int hex_to_bytes(const char* hex, unsigned char* bytes_out);

#endif

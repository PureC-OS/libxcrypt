#pragma once
#include <stddef.h>
#include <stdint.h>
#define PURECRYPT_SALT_MAX 16
#define PURECRYPT_PASS_MAX 512
#define PURECRYPT_HASH_MAX 128
#define PURECRYPT_ROUNDS_DEFAULT 5000u
#define PURECRYPT_ROUNDS_MIN 1000u
#define PURECRYPT_ROUNDS_MAX 999999999u
int purecrypt_hash(const char *password, const char *salt, unsigned rounds, char out[PURECRYPT_HASH_MAX]);
int purecrypt_verify(const char *password, const char *expected);
void purecrypt_gensalt(const uint8_t raw16[16], char salt_out[17]);
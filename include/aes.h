#pragma once
#include <stddef.h>
#include <stdint.h>
#define PURE_AES_BLOCK_LEN 16
typedef struct { uint32_t rk[44]; } pure_aes128_ctx;
void pure_aes128_init(pure_aes128_ctx *ctx, const uint8_t key[16]);
void pure_aes128_encrypt(const pure_aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
void pure_aes128_decrypt(const pure_aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16]);
int pure_aes_wrap(const uint8_t kek[16], const uint8_t *plain, size_t len, uint8_t *out);
int pure_aes_unwrap(const uint8_t kek[16], const uint8_t *cipher, size_t len, uint8_t *out);

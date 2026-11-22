#pragma once
#include <stddef.h>
#include <stdint.h>
#define PURE_SHA1_DIGEST_LEN 20
#define PURE_SHA1_BLOCK_LEN 64
typedef struct { uint32_t h[5]; uint64_t total_len; uint8_t buf[PURE_SHA1_BLOCK_LEN]; size_t buflen; } pure_sha1_ctx;
void pure_sha1_init(pure_sha1_ctx *ctx);
void pure_sha1_update(pure_sha1_ctx *ctx, const uint8_t *data, size_t len);
void pure_sha1_final(pure_sha1_ctx *ctx, uint8_t out[PURE_SHA1_DIGEST_LEN]);
void pure_sha1(const uint8_t *data, size_t len, uint8_t out[PURE_SHA1_DIGEST_LEN]);
void pure_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                    uint8_t out[PURE_SHA1_DIGEST_LEN]);
void pure_hmac_sha1_vec(const uint8_t *key, size_t key_len, size_t count, const uint8_t *const *data,
                        const size_t *lens, uint8_t out[PURE_SHA1_DIGEST_LEN]);
void pure_pbkdf2_sha1(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t out_len);
void pure_prf_sha1(const uint8_t *key, size_t key_len, const char *label, const uint8_t *data,
                   size_t data_len, uint8_t *out, size_t out_len);

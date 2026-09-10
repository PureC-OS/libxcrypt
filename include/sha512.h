#pragma once
/* Freestanding SHA-512 (FIPS 180-4). No libc, no malloc, integer-only
 * (safe for kernel -mgeneral-regs-only). */
#include <stddef.h>
#include <stdint.h>

#define PURE_SHA512_DIGEST_LEN 64
#define PURE_SHA512_BLOCK_LEN 128

typedef struct {
    uint64_t h[8];
    uint64_t total_len;              /* bytes absorbed so far */
    uint8_t buf[PURE_SHA512_BLOCK_LEN];
    size_t buflen;
} pure_sha512_ctx;

void pure_sha512_init(pure_sha512_ctx *ctx);
void pure_sha512_update(pure_sha512_ctx *ctx, const uint8_t *data, size_t len);
void pure_sha512_final(pure_sha512_ctx *ctx, uint8_t out[PURE_SHA512_DIGEST_LEN]);

/* One-shot helper. */
void pure_sha512(const uint8_t *data, size_t len,
                 uint8_t out[PURE_SHA512_DIGEST_LEN]);

/* out must hold 129 bytes (128 hex chars + NUL). */
void pure_sha512_hex(const uint8_t digest[PURE_SHA512_DIGEST_LEN],
                     char out[129]);

/* Constant-time helpers (safe for secrets). */
void pure_memzero(void *p, size_t n);
int pure_memeq(const void *a, const void *b, size_t n);

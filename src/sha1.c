#include "sha1.h"
#include "sha512.h"

static uint32_t rol(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static void block(pure_sha1_ctx *ctx, const uint8_t *p)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) | ((uint32_t)p[i * 4 + 2] << 8) |
               (uint32_t)p[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = t;
    }
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    pure_memzero(w, sizeof(w));
}

void pure_sha1_init(pure_sha1_ctx *ctx)
{
    ctx->h[0] = 0x67452301;
    ctx->h[1] = 0xEFCDAB89;
    ctx->h[2] = 0x98BADCFE;
    ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xC3D2E1F0;
    ctx->total_len = 0;
    ctx->buflen = 0;
}

void pure_sha1_update(pure_sha1_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->total_len += len;
    while (len) {
        size_t take = PURE_SHA1_BLOCK_LEN - ctx->buflen;
        if (take > len)
            take = len;
        for (size_t i = 0; i < take; i++)
            ctx->buf[ctx->buflen + i] = data[i];
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == PURE_SHA1_BLOCK_LEN) {
            block(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void pure_sha1_final(pure_sha1_ctx *ctx, uint8_t out[PURE_SHA1_DIGEST_LEN])
{
    uint64_t bits = ctx->total_len * 8;
    uint8_t pad = 0x80;
    pure_sha1_update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx->buflen != 56)
        pure_sha1_update(ctx, &zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++)
        len[i] = (uint8_t)(bits >> (56 - 8 * i));
    pure_sha1_update(ctx, len, 8);
    for (int i = 0; i < 5; i++) {
        out[i * 4] = (uint8_t)(ctx->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)ctx->h[i];
    }
    pure_memzero(ctx, sizeof(*ctx));
}

void pure_sha1(const uint8_t *data, size_t len, uint8_t out[PURE_SHA1_DIGEST_LEN])
{
    pure_sha1_ctx ctx;
    pure_sha1_init(&ctx);
    pure_sha1_update(&ctx, data, len);
    pure_sha1_final(&ctx, out);
}

void pure_hmac_sha1_vec(const uint8_t *key, size_t key_len, size_t count, const uint8_t *const *data,
                        const size_t *lens, uint8_t out[PURE_SHA1_DIGEST_LEN])
{
    uint8_t k[PURE_SHA1_BLOCK_LEN] = {0};
    if (key_len > PURE_SHA1_BLOCK_LEN)
        pure_sha1(key, key_len, k);
    else
        for (size_t i = 0; i < key_len; i++)
            k[i] = key[i];
    uint8_t pad[PURE_SHA1_BLOCK_LEN];
    pure_sha1_ctx ctx;
    for (int i = 0; i < PURE_SHA1_BLOCK_LEN; i++)
        pad[i] = k[i] ^ 0x36;
    pure_sha1_init(&ctx);
    pure_sha1_update(&ctx, pad, sizeof(pad));
    for (size_t i = 0; i < count; i++)
        pure_sha1_update(&ctx, data[i], lens[i]);
    uint8_t inner[PURE_SHA1_DIGEST_LEN];
    pure_sha1_final(&ctx, inner);
    for (int i = 0; i < PURE_SHA1_BLOCK_LEN; i++)
        pad[i] = k[i] ^ 0x5c;
    pure_sha1_init(&ctx);
    pure_sha1_update(&ctx, pad, sizeof(pad));
    pure_sha1_update(&ctx, inner, sizeof(inner));
    pure_sha1_final(&ctx, out);
    pure_memzero(k, sizeof(k));
    pure_memzero(pad, sizeof(pad));
    pure_memzero(inner, sizeof(inner));
}

void pure_hmac_sha1(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len,
                    uint8_t out[PURE_SHA1_DIGEST_LEN])
{
    pure_hmac_sha1_vec(key, key_len, 1, &data, &len, out);
}

void pure_pbkdf2_sha1(const uint8_t *password, size_t password_len, const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t *out, size_t out_len)
{
    uint32_t index = 1;
    while (out_len) {
        uint8_t counter[4] = {(uint8_t)(index >> 24), (uint8_t)(index >> 16), (uint8_t)(index >> 8),
                              (uint8_t)index};
        const uint8_t *parts[2] = {salt, counter};
        size_t lens[2] = {salt_len, 4};
        uint8_t u[PURE_SHA1_DIGEST_LEN], t[PURE_SHA1_DIGEST_LEN];
        pure_hmac_sha1_vec(password, password_len, 2, parts, lens, u);
        for (int i = 0; i < PURE_SHA1_DIGEST_LEN; i++)
            t[i] = u[i];
        for (uint32_t it = 1; it < iterations; it++) {
            pure_hmac_sha1(password, password_len, u, sizeof(u), u);
            for (int i = 0; i < PURE_SHA1_DIGEST_LEN; i++)
                t[i] ^= u[i];
        }
        size_t take = out_len < PURE_SHA1_DIGEST_LEN ? out_len : PURE_SHA1_DIGEST_LEN;
        for (size_t i = 0; i < take; i++)
            out[i] = t[i];
        out += take;
        out_len -= take;
        index++;
        pure_memzero(u, sizeof(u));
        pure_memzero(t, sizeof(t));
    }
}

void pure_prf_sha1(const uint8_t *key, size_t key_len, const char *label, const uint8_t *data,
                   size_t data_len, uint8_t *out, size_t out_len)
{
    size_t label_len = 0;
    while (label[label_len])
        label_len++;
    uint8_t zero = 0, counter = 0;
    const uint8_t *parts[4] = {(const uint8_t *)label, &zero, data, &counter};
    size_t lens[4] = {label_len, 1, data_len, 1};
    uint8_t hash[PURE_SHA1_DIGEST_LEN];
    while (out_len) {
        pure_hmac_sha1_vec(key, key_len, 4, parts, lens, hash);
        size_t take = out_len < PURE_SHA1_DIGEST_LEN ? out_len : PURE_SHA1_DIGEST_LEN;
        for (size_t i = 0; i < take; i++)
            out[i] = hash[i];
        out += take;
        out_len -= take;
        counter++;
    }
    pure_memzero(hash, sizeof(hash));
}

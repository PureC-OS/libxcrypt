#include "aes.h"
#include "sha512.h"

static uint8_t sbox[256], inv_sbox[256];
static int tables_ready;

static uint8_t xtime(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

static uint8_t mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return r;
}

static void build_tables(void)
{
    uint8_t p = 1, q = 1;
    do {
        p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0));
        q ^= (uint8_t)(q << 1);
        q ^= (uint8_t)(q << 2);
        q ^= (uint8_t)(q << 4);
        if (q & 0x80)
            q ^= 0x09;
        uint8_t x = (uint8_t)(q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^
                              ((q << 4) | (q >> 4)));
        sbox[p] = (uint8_t)(x ^ 0x63);
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++)
        inv_sbox[sbox[i]] = (uint8_t)i;
    tables_ready = 1;
}

void pure_aes128_init(pure_aes128_ctx *ctx, const uint8_t key[16])
{
    if (!tables_ready)
        build_tables();
    for (int i = 0; i < 4; i++)
        ctx->rk[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16) |
                     ((uint32_t)key[4 * i + 2] << 8) | key[4 * i + 3];
    uint8_t rcon = 1;
    for (int i = 4; i < 44; i++) {
        uint32_t t = ctx->rk[i - 1];
        if (i % 4 == 0) {
            t = (t << 8) | (t >> 24);
            t = ((uint32_t)sbox[t >> 24] << 24) | ((uint32_t)sbox[(t >> 16) & 0xFF] << 16) |
                ((uint32_t)sbox[(t >> 8) & 0xFF] << 8) | sbox[t & 0xFF];
            t ^= (uint32_t)rcon << 24;
            rcon = xtime(rcon);
        }
        ctx->rk[i] = ctx->rk[i - 4] ^ t;
    }
}

static void add_round_key(uint8_t s[16], const uint32_t *rk)
{
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[4 * c + r] ^= (uint8_t)(rk[c] >> (24 - 8 * r));
}

static void shift_rows(uint8_t s[16], int inverse)
{
    uint8_t t[16];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) {
            int src = inverse ? (c - r + 4) % 4 : (c + r) % 4;
            t[4 * c + r] = s[4 * src + r];
        }
    for (int i = 0; i < 16; i++)
        s[i] = t[i];
}

static void mix_columns(uint8_t s[16], int inverse)
{
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
        if (!inverse) {
            s[4 * c] = (uint8_t)(mul(a0, 2) ^ mul(a1, 3) ^ a2 ^ a3);
            s[4 * c + 1] = (uint8_t)(a0 ^ mul(a1, 2) ^ mul(a2, 3) ^ a3);
            s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ mul(a2, 2) ^ mul(a3, 3));
            s[4 * c + 3] = (uint8_t)(mul(a0, 3) ^ a1 ^ a2 ^ mul(a3, 2));
        } else {
            s[4 * c] = (uint8_t)(mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9));
            s[4 * c + 1] = (uint8_t)(mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13));
            s[4 * c + 2] = (uint8_t)(mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11));
            s[4 * c + 3] = (uint8_t)(mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14));
        }
    }
}

void pure_aes128_encrypt(const pure_aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    for (int i = 0; i < 16; i++)
        s[i] = in[i];
    add_round_key(s, ctx->rk);
    for (int round = 1; round <= 10; round++) {
        for (int i = 0; i < 16; i++)
            s[i] = sbox[s[i]];
        shift_rows(s, 0);
        if (round != 10)
            mix_columns(s, 0);
        add_round_key(s, ctx->rk + 4 * round);
    }
    for (int i = 0; i < 16; i++)
        out[i] = s[i];
    pure_memzero(s, sizeof(s));
}

void pure_aes128_decrypt(const pure_aes128_ctx *ctx, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16];
    for (int i = 0; i < 16; i++)
        s[i] = in[i];
    add_round_key(s, ctx->rk + 40);
    for (int round = 9; round >= 0; round--) {
        shift_rows(s, 1);
        for (int i = 0; i < 16; i++)
            s[i] = inv_sbox[s[i]];
        add_round_key(s, ctx->rk + 4 * round);
        if (round != 0)
            mix_columns(s, 1);
    }
    for (int i = 0; i < 16; i++)
        out[i] = s[i];
    pure_memzero(s, sizeof(s));
}

int pure_aes_wrap(const uint8_t kek[16], const uint8_t *plain, size_t len, uint8_t *out)
{
    if (len < 16 || len % 8)
        return -1;
    size_t n = len / 8;
    pure_aes128_ctx ctx;
    pure_aes128_init(&ctx, kek);
    uint8_t a[8], b[16];
    for (int i = 0; i < 8; i++)
        a[i] = 0xA6;
    for (size_t i = 0; i < len; i++)
        out[8 + i] = plain[i];
    for (uint32_t j = 0; j < 6; j++)
        for (size_t i = 1; i <= n; i++) {
            for (int k = 0; k < 8; k++) {
                b[k] = a[k];
                b[8 + k] = out[8 * i + k];
            }
            pure_aes128_encrypt(&ctx, b, b);
            uint64_t t = (uint64_t)n * j + i;
            for (int k = 0; k < 8; k++)
                a[k] = (uint8_t)(b[k] ^ (uint8_t)(t >> (56 - 8 * k)));
            for (int k = 0; k < 8; k++)
                out[8 * i + k] = b[8 + k];
        }
    for (int i = 0; i < 8; i++)
        out[i] = a[i];
    pure_memzero(&ctx, sizeof(ctx));
    pure_memzero(b, sizeof(b));
    return 0;
}

int pure_aes_unwrap(const uint8_t kek[16], const uint8_t *cipher, size_t len, uint8_t *out)
{
    if (len < 24 || len % 8)
        return -1;
    size_t n = len / 8 - 1;
    pure_aes128_ctx ctx;
    pure_aes128_init(&ctx, kek);
    uint8_t a[8], b[16];
    for (int i = 0; i < 8; i++)
        a[i] = cipher[i];
    for (size_t i = 0; i < n * 8; i++)
        out[i] = cipher[8 + i];
    for (int j = 5; j >= 0; j--)
        for (size_t i = n; i >= 1; i--) {
            uint64_t t = (uint64_t)n * (uint32_t)j + i;
            for (int k = 0; k < 8; k++) {
                b[k] = (uint8_t)(a[k] ^ (uint8_t)(t >> (56 - 8 * k)));
                b[8 + k] = out[8 * (i - 1) + k];
            }
            pure_aes128_decrypt(&ctx, b, b);
            for (int k = 0; k < 8; k++) {
                a[k] = b[k];
                out[8 * (i - 1) + k] = b[8 + k];
            }
        }
    pure_memzero(&ctx, sizeof(ctx));
    pure_memzero(b, sizeof(b));
    for (int i = 0; i < 8; i++)
        if (a[i] != 0xA6) {
            pure_memzero(out, n * 8);
            return -1;
        }
    return 0;
}

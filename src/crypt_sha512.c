/* SHA512-crypt ("$6$") password hashing, Ulrich Drepper spec.
 * Freestanding: own string helpers, stack buffers only, secrets wiped. */
#include "purecrypt.h"
#include "sha512.h"

static const char itoa64[] =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static size_t pstrlen(const char *s) {
    size_t n = 0;
    while (s[n])
        n++;
    return n;
}

static int salt_ok(const char *salt, size_t *out_len) {
    size_t n = pstrlen(salt);
    if (n == 0 || n > PURECRYPT_SALT_MAX)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = salt[i];
        int ok = (c == '.' || c == '/') ||
                 (c >= '0' && c <= '9') ||
                 (c >= 'A' && c <= 'Z') ||
                 (c >= 'a' && c <= 'z');
        if (!ok)
            return 0;
    }
    *out_len = n;
    return 1;
}

/* b64 encoding of the final digest, Drepper permutation. */
static void encode_hash(const uint8_t alt[64], char out86[86]) {
    static const uint8_t perm[21][3] = {
        {0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4},
        {47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51},
        {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35},
        {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19},
        {62, 20, 41}
    };
    char *p = out86;
    for (int i = 0; i < 21; i++) {
        unsigned w = ((unsigned)alt[perm[i][0]] << 16) |
                     ((unsigned)alt[perm[i][1]] << 8) |
                     ((unsigned)alt[perm[i][2]]);
        for (int k = 0; k < 4; k++) {
            *p++ = itoa64[w & 0x3f];
            w >>= 6;
        }
    }
    /* Leftover byte 63 -> 2 chars. */
    unsigned w = alt[63];
    *p++ = itoa64[w & 0x3f];
    *p++ = itoa64[(w >> 6) & 0x3f];
}

/* Core "$6$" computation shared by hash() and verify(). */
static int crypt_body(const char *pw, size_t pw_len,
                      const char *salt, size_t salt_len,
                      unsigned long rounds,
                      char hash86[86], unsigned long *rounds_used) {
    uint8_t alt[64], dp[64], tmp[64];
    uint8_t p_bytes[PURECRYPT_PASS_MAX];
    uint8_t s_bytes[PURECRYPT_SALT_MAX];
    pure_sha512_ctx ctx;
    size_t cnt, i;

    /* 1. Alternate sum: SHA512(pw + salt + pw). */
    pure_sha512_init(&ctx);
    pure_sha512_update(&ctx, (const uint8_t *)pw, pw_len);
    pure_sha512_update(&ctx, (const uint8_t *)salt, salt_len);
    pure_sha512_update(&ctx, (const uint8_t *)pw, pw_len);
    pure_sha512_final(&ctx, alt);

    /* 2. Intermediate: pw + salt + pw_len bytes of alt (+ bit loop). */
    pure_sha512_init(&ctx);
    pure_sha512_update(&ctx, (const uint8_t *)pw, pw_len);
    pure_sha512_update(&ctx, (const uint8_t *)salt, salt_len);
    for (cnt = pw_len; cnt > 64; cnt -= 64)
        pure_sha512_update(&ctx, alt, 64);
    pure_sha512_update(&ctx, alt, cnt);
    for (cnt = pw_len; cnt > 0; cnt >>= 1) {
        if (cnt & 1)
            pure_sha512_update(&ctx, alt, 64);
        else
            pure_sha512_update(&ctx, (const uint8_t *)pw, pw_len);
    }
    pure_sha512_final(&ctx, dp);

    /* 3. Byte sequence P: SHA512(pw repeated pw_len times), cycled. */
    pure_sha512_init(&ctx);
    for (cnt = pw_len; cnt > 0; cnt--)
        pure_sha512_update(&ctx, (const uint8_t *)pw, pw_len);
    pure_sha512_final(&ctx, tmp);
    for (i = 0; i < pw_len; i++)
        p_bytes[i] = tmp[i % 64];

    /* 4. Byte sequence S: SHA512(salt repeated salt_len times), cycled. */
    pure_sha512_init(&ctx);
    for (cnt = salt_len; cnt > 0; cnt--)
        pure_sha512_update(&ctx, (const uint8_t *)salt, salt_len);
    pure_sha512_final(&ctx, tmp);
    for (i = 0; i < salt_len; i++)
        s_bytes[i] = tmp[i % 64];
    pure_memzero(tmp, sizeof(tmp));

    /* 5. Stretching rounds. */
    for (cnt = 0; cnt < rounds; cnt++) {
        pure_sha512_init(&ctx);
        if (cnt & 1)
            pure_sha512_update(&ctx, p_bytes, pw_len);
        else
            pure_sha512_update(&ctx, dp, 64);
        if (cnt % 3 != 0)
            pure_sha512_update(&ctx, s_bytes, salt_len);
        if (cnt % 7 != 0)
            pure_sha512_update(&ctx, p_bytes, pw_len);
        if (cnt & 1)
            pure_sha512_update(&ctx, dp, 64);
        else
            pure_sha512_update(&ctx, p_bytes, pw_len);
        pure_sha512_final(&ctx, dp);
    }

    pure_memzero(p_bytes, sizeof(p_bytes));
    pure_memzero(s_bytes, sizeof(s_bytes));
    pure_memzero(alt, sizeof(alt));

    encode_hash(dp, hash86);
    pure_memzero(dp, sizeof(dp));
    if (rounds_used)
        *rounds_used = rounds;
    return 0;
}

/* Decimal append helper; returns 0 on overflow. */
static int append_ulong(char *dst, size_t cap, size_t *pos, unsigned long v) {
    char tmp[16];
    int n = 0;
    if (v == 0)
        tmp[n++] = '0';
    else {
        while (v > 0 && n < (int)sizeof(tmp))
            tmp[n++] = (char)('0' + (v % 10)), v /= 10;
        if (v != 0)
            return 0;
        /* reverse */
        for (int a = 0, b = n - 1; a < b; a++, b--) {
            char t = tmp[a];
            tmp[a] = tmp[b];
            tmp[b] = t;
        }
    }
    if (*pos + (size_t)n + 1 > cap)
        return 0;
    for (int k = 0; k < n; k++)
        dst[(*pos)++] = tmp[k];
    return 1;
}

int purecrypt_hash(const char *password, const char *salt, unsigned rounds,
                   char out[PURECRYPT_HASH_MAX]) {
    size_t pw_len, salt_len;
    unsigned long r;
    char hash86[86];
    size_t pos = 0;

    if (!password || !salt || !out)
        return -1;
    pw_len = pstrlen(password);
    if (pw_len > PURECRYPT_PASS_MAX)
        return -1;
    if (!salt_ok(salt, &salt_len))
        return -1;
    r = rounds == 0 ? PURECRYPT_ROUNDS_DEFAULT : rounds;
    if (r < PURECRYPT_ROUNDS_MIN || r > PURECRYPT_ROUNDS_MAX)
        return -1;

    crypt_body(password, pw_len, salt, salt_len, r, hash86, NULL);

    out[pos++] = '$';
    out[pos++] = '6';
    out[pos++] = '$';
    if (r != PURECRYPT_ROUNDS_DEFAULT) {
        const char *tag = "rounds=";
        while (*tag)
            out[pos++] = *tag++;
        if (!append_ulong(out, PURECRYPT_HASH_MAX, &pos, r)) {
            pure_memzero(hash86, sizeof(hash86));
            pure_memzero(out, PURECRYPT_HASH_MAX);
            return -1;
        }
        out[pos++] = '$';
    }
    for (size_t k = 0; k < salt_len; k++)
        out[pos++] = salt[k];
    out[pos++] = '$';
    for (int k = 0; k < 86; k++)
        out[pos++] = hash86[k];
    out[pos] = '\0';
    pure_memzero(hash86, sizeof(hash86));
    return 0;
}

/* Parse "$6$[rounds=N$]salt$hash". Returns 0 on success. */
static int parse_setting(const char *s, const char **salt, size_t *salt_len,
                         unsigned long *rounds, const char **hash) {
    const char *p;
    if (!s || s[0] != '$' || s[1] != '6' || s[2] != '$')
        return -1;
    p = s + 3;
    *rounds = PURECRYPT_ROUNDS_DEFAULT;
    if (p[0] == 'r') {
        /* rounds=N$ */
        const char *tag = "rounds=";
        for (int k = 0; k < 7; k++)
            if (p[k] != tag[k])
                return -1;
        p += 7;
        unsigned long r = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            r = r * 10 + (unsigned long)(*p - '0');
            if (r > PURECRYPT_ROUNDS_MAX)
                return -1;
            p++;
            digits++;
        }
        if (digits == 0 || *p != '$')
            return -1;
        if (r < PURECRYPT_ROUNDS_MIN)
            return -1;
        *rounds = r;
        p++;
    }
    *salt = p;
    while (*p && *p != '$')
        p++;
    *salt_len = (size_t)(p - *salt);
    if (*salt_len == 0 || *salt_len > PURECRYPT_SALT_MAX || *p != '$')
        return -1;
    /* validate salt charset (bounded, no strlen needed) */
    {
        size_t dummy = *salt_len;
        char tmp[PURECRYPT_SALT_MAX + 1];
        for (size_t k = 0; k < *salt_len; k++)
            tmp[k] = (*salt)[k];
        tmp[*salt_len] = '\0';
        if (!salt_ok(tmp, &dummy))
            return -1;
    }
    *hash = p + 1;
    if (pstrlen(*hash) != 86)
        return -1;
    return 0;
}

int purecrypt_verify(const char *password, const char *expected) {
    const char *salt, *hash;
    size_t pw_len, salt_len;
    unsigned long rounds;
    char saltbuf[PURECRYPT_SALT_MAX + 1];
    char hash86[86];
    int eq;

    if (!password || !expected)
        return -1;
    pw_len = pstrlen(password);
    if (pw_len > PURECRYPT_PASS_MAX)
        return -1;
    if (parse_setting(expected, &salt, &salt_len, &rounds, &hash) != 0)
        return -1;
    for (size_t k = 0; k < salt_len; k++)
        saltbuf[k] = salt[k];
    saltbuf[salt_len] = '\0';

    crypt_body(password, pw_len, saltbuf, salt_len, rounds, hash86, NULL);
    pure_memzero(saltbuf, sizeof(saltbuf));

    /* Constant-time compare over the 86-char hash body. */
    eq = pure_memeq(hash86, hash, 86);
    pure_memzero(hash86, sizeof(hash86));
    return eq ? 1 : 0;
}

void purecrypt_gensalt(const uint8_t raw16[16], char salt_out[17]) {
    for (int i = 0; i < 16; i++)
        salt_out[i] = itoa64[raw16[i] & 0x3f];
    salt_out[16] = '\0';
}

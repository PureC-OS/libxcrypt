/* Host-only test: FIPS 180-4 SHA-512 vectors through the public API. */
#include <stdio.h>
#include <string.h>
#include "sha512.h"

static int fails = 0;

static void check(const char *name, const uint8_t *msg, size_t len,
                  const char *want_hex) {
    uint8_t d[64];
    char hex[129];
    pure_sha512(msg, len, d);
    pure_sha512_hex(d, hex);
    if (strcmp(hex, want_hex) != 0) {
        printf("FAIL %s\n  got  %s\n  want %s\n", name, hex, want_hex);
        fails++;
    } else {
        printf("ok %s\n", name);
    }
}

static void check_streaming(void) {
    /* Same "abc" fed byte-by-byte must match one-shot. */
    uint8_t a[64], b[64];
    pure_sha512_ctx ctx;
    pure_sha512((const uint8_t *)"abc", 3, a);
    pure_sha512_init(&ctx);
    pure_sha512_update(&ctx, (const uint8_t *)"a", 1);
    pure_sha512_update(&ctx, (const uint8_t *)"b", 1);
    pure_sha512_update(&ctx, (const uint8_t *)"c", 1);
    pure_sha512_final(&ctx, b);
    if (memcmp(a, b, 64) != 0) {
        printf("FAIL streaming\n");
        fails++;
    } else {
        printf("ok streaming\n");
    }
}

int main(void) {
    static const char m112[] =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    static uint8_t m1000[1000];
    uint8_t big[1000000 / 1000 * 1000];
    (void)big;
    memset(m1000, 'a', sizeof(m1000));

    check("empty", (const uint8_t *)"", 0,
          "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715"
          "dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    check("abc", (const uint8_t *)"abc", 3,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    check("112-char", (const uint8_t *)m112, 112,
          "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299ae"
          "adb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    /* 1M x 'a' in chunks (multi-block + padding edge). */
    {
        pure_sha512_ctx ctx;
        uint8_t d[64];
        char hex[129];
        pure_sha512_init(&ctx);
        for (int i = 0; i < 1000; i++)
            pure_sha512_update(&ctx, m1000, sizeof(m1000));
        pure_sha512_final(&ctx, d);
        pure_sha512_hex(d, hex);
        const char *want =
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
        if (strcmp(hex, want) != 0) {
            printf("FAIL 1M-a\n  got  %s\n  want %s\n", hex, want);
            fails++;
        } else {
            printf("ok 1M-a\n");
        }
    }
    check_streaming();

    if (fails == 0)
        printf("ALL SHA512 TESTS PASSED\n");
    return fails != 0;
}

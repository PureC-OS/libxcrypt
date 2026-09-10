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
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static uint8_t m1000[1000];
    uint8_t big[1000000 / 1000 * 1000];
    (void)big;
    memset(m1000, 'a', sizeof(m1000));

    check("empty", (const uint8_t *)"", 0,
          "cf83e1357eefb8bdf1542850dd721d64c437d2743fef"
          "dd3792e9327f2341c2fc19d8aa3ed5c9d5c0551e5cc7c9a3d84b9bb5c521b9b5ff6938cc9d865a");
    check("abc", (const uint8_t *)"abc", 3,
          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
          "2192992a274fc1a836ba3c23a3fbac4198ae6534ca456c00c9249dd47e8f27b8f6fb0527");
    check("112-char", (const uint8_t *)m112, 112,
          "204a8fc6dda82f0a0ced784f9d79330e7d92d6576231d"
          "f0d191323c796b7e5b4c7243e8ef8d377ded0f33b63f9a875a4b9f10f2264d1a3cd9c647");
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
            "e718483d0ce769644e2e42c7fe15b4ac9f006b85412204daa279fb1c508d5e"
            "adb8e739e9f2d5e1479f941b6e2f1f73d1f7fb05b8eb48b442a6da8a112b7f1f55";
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

#include "aes.h"
#include "sha1.h"
#include <stdio.h>
#include <string.h>

static int fails;

static void hex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        sscanf(s + 2 * i, "%2hhx", &out[i]);
}

static void check(const char *name, const uint8_t *got, const char *want)
{
    size_t n = strlen(want) / 2;
    uint8_t w[128];
    hex(want, w, n);
    int ok = memcmp(got, w, n) == 0;
    printf("%-22s %s\n", name, ok ? "ok" : "FAIL");
    fails += !ok;
}

int main(void)
{
    uint8_t out[128];
    pure_sha1((const uint8_t *)"abc", 3, out);
    check("sha1 abc", out, "a9993e364706816aba3e25717850c26c9cd0d89d");

    uint8_t big[1000];
    memset(big, 'a', sizeof(big));
    pure_sha1_ctx ctx;
    pure_sha1_init(&ctx);
    for (int i = 0; i < 1000; i++)
        pure_sha1_update(&ctx, big, sizeof(big));
    pure_sha1_final(&ctx, out);
    check("sha1 million a", out, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");

    uint8_t key[20];
    memset(key, 0x0b, sizeof(key));
    pure_hmac_sha1(key, 20, (const uint8_t *)"Hi There", 8, out);
    check("hmac-sha1 rfc2202 1", out, "b617318655057264e28bc0b6fb378c8ef146be00");
    uint8_t aa[80];
    memset(aa, 0xaa, sizeof(aa));
    pure_hmac_sha1(aa, 80, (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54, out);
    check("hmac-sha1 rfc2202 6", out, "aa4ae5e15272d00e95705637ce8a3b55ed402112");

    pure_pbkdf2_sha1((const uint8_t *)"password", 8, (const uint8_t *)"IEEE", 4, 4096, out, 32);
    check("psk password/IEEE", out, "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e");
    pure_pbkdf2_sha1((const uint8_t *)"ThisIsAPassword", 15, (const uint8_t *)"ThisIsASSID", 11, 4096, out, 32);
    check("psk ThisIsAPassword", out, "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af");

    const char *data = "what do ya want for nothing?";
    pure_prf_sha1((const uint8_t *)"Jefe", 4, "prefix", (const uint8_t *)data, strlen(data), out, 64);
    check("prf-512 802.11i", out,
          "51f4de5b33f249adf81aeb713a3c20f4fe631446fabdfa58244759ae58ef9009"
          "a99abf4eac2ca5fa87e692c440eb40023e7babb206d61de7b92f41529092b8fc");

    uint8_t k[16], pt[16];
    hex("000102030405060708090a0b0c0d0e0f", k, 16);
    hex("00112233445566778899aabbccddeeff", pt, 16);
    pure_aes128_ctx actx;
    pure_aes128_init(&actx, k);
    pure_aes128_encrypt(&actx, pt, out);
    check("aes128 fips197 enc", out, "69c4e0d86a7b0430d8cdb78070b4c55a");
    pure_aes128_decrypt(&actx, out, out);
    check("aes128 fips197 dec", out, "00112233445566778899aabbccddeeff");

    pure_aes_wrap(k, pt, 16, out);
    check("aes wrap rfc3394", out, "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
    uint8_t back[16];
    int r = pure_aes_unwrap(k, out, 24, back);
    check("aes unwrap rfc3394", back, "00112233445566778899aabbccddeeff");
    out[3] ^= 1;
    int bad = pure_aes_unwrap(k, out, 24, back);
    printf("%-22s %s\n", "aes unwrap tamper", (r == 0 && bad != 0) ? "ok" : "FAIL");
    fails += !(r == 0 && bad != 0);

    printf(fails ? "%d FAILED\n" : "all passed\n", fails);
    return fails != 0;
}

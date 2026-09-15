#include <crypt.h>
#include <stdio.h>
#include <string.h>
#include "purecrypt.h"

static int fails = 0;

static void check_vec(const char *pw, const char *salt, unsigned rounds) {
    char ours[PURECRYPT_HASH_MAX];
    struct crypt_data cd;
    char setting[64];
    const char *ref;

    memset(&cd, 0, sizeof(cd));
    if (rounds == 0 || rounds == PURECRYPT_ROUNDS_DEFAULT)
        snprintf(setting, sizeof(setting), "$6$%s$", salt);
    else
        snprintf(setting, sizeof(setting), "$6$rounds=%u$%s$", rounds, salt);

    if (purecrypt_hash(pw, salt, rounds, ours) != 0) {
        printf("FAIL hash() rejected pw=%s salt=%s rounds=%u\n", pw, salt,
               rounds);
        fails++;
        return;
    }
    ref = crypt_r(pw, setting, &cd);
    if (!ref) {
        printf("FAIL crypt_r failed for %s\n", setting);
        fails++;
        return;
    }
    if (strcmp(ours, ref) != 0) {
        printf("FAIL mismatch pw=%s salt=%s rounds=%u\n  ours %s\n  ref  %s\n",
               pw, salt, rounds, ours, ref);
        fails++;
        return;
    }
    if (purecrypt_verify(pw, ref) != 1) {
        printf("FAIL verify() rejected own hash %s\n", ref);
        fails++;
        return;
    }
    if (purecrypt_verify("wrong-password-xyz", ref) != 0) {
        printf("FAIL verify() accepted wrong password for %s\n", ref);
        fails++;
        return;
    }
    printf("ok pw=%s salt=%s rounds=%u\n", pw, salt, rounds);
}

static void check_rejects(void) {
    char out[PURECRYPT_HASH_MAX];
    if (purecrypt_hash("pw", "bad!salt", 0, out) == 0) {
        printf("FAIL accepted bad salt charset\n");
        fails++;
    } else {
        printf("ok reject bad salt\n");
    }
    if (purecrypt_hash("pw", "0123456789abcdefg", 0, out) == 0) {
        printf("FAIL accepted 17-char salt\n");
        fails++;
    } else {
        printf("ok reject long salt\n");
    }
    if (purecrypt_verify("pw", "$6$short") != -1) {
        printf("FAIL accepted malformed setting\n");
        fails++;
    } else {
        printf("ok reject malformed\n");
    }
    {
        char good[PURECRYPT_HASH_MAX];
        purecrypt_hash("secret", "saltsaltsaltsalt", 1000, good);
        good[20] = (good[20] == 'A' ? 'B' : 'A');
        if (purecrypt_verify("secret", good) != 0) {
            printf("FAIL accepted tampered hash\n");
            fails++;
        } else {
            printf("ok reject tampered\n");
        }
    }
    {
        uint8_t raw[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        char s[17];
        purecrypt_gensalt(raw, s);
        if (memcmp(s, "./0123456789ABCD", 17) != 0) {
            printf("FAIL gensalt got %s\n", s);
            fails++;
        } else {
            printf("ok gensalt\n");
        }
    }
}

int main(void) {
    check_vec("", "abcd", 1000);
    check_vec("a", "x", 1000);
    check_vec("password", "saltsalt", 1000);
    check_vec("hello world", "./0123456789ABCD", 1000);
    check_vec("longer password with spaces 123!", "s", 1000);
    check_vec("pw", "abcdefghijklmnop", 0); /* default 5000 */
    check_vec("pw", "abcdefghijklmnop", 5000);
    check_vec("boundary-55-bytes-01234567890123456789012345678901", "salt12",
              1000);
    check_vec("boundary-56-bytes-012345678901234567890123456789012", "salt12",
              1000);
    check_vec("x", "y", 1001);
    check_rejects();

    if (fails == 0)
        printf("ALL CRYPT TESTS PASSED\n");
    return fails != 0;
}

# libpurecrypt

Freestanding SHA-512 + `$6$` (SHA512-crypt) password hashing for PureC OS.
No libc, no malloc, no RNG inside — integer-only, so the same sources
compile for the kernel (`-mgeneral-regs-only`), userspace, and host tests.

## Layout

```
include/sha512.h        raw SHA-512 (init/update/final/one-shot/hex)
include/purecrypt.h     password API: hash / verify / gensalt
src/sha512.c            FIPS 180-4, K-table derived, verified vs vectors
src/crypt_sha512.c      SHA512-crypt, byte-identical to glibc crypt("$6$")
test/test_sha512.c      host test: FIPS vectors
test/test_crypt.c       host test: differential vs glibc crypt_r
```

## API

```c
#include "purecrypt.h"

char out[PURECRYPT_HASH_MAX];
purecrypt_hash("secret", "somesalt", 0, out);      /* rounds=0 -> 5000 */
/* out = "$6$somesalt$..." */

int ok = purecrypt_verify("secret", out);          /* 1 match, 0 no, -1 bad */

uint8_t rnd[16]; /* fill from kernel RNG / /dev/urandom */
char salt[17];
purecrypt_gensalt(rnd, salt);
purecrypt_hash("secret", salt, 10000, out);
```

Limits: password ≤ 512 bytes, salt ≤ 16 chars of `[./0-9A-Za-z]`,
rounds 1000..999999999. Secrets are wiped (`pure_memzero`), comparison is
constant-time. `verify()` truncates overlong salts exactly like glibc.

## Build

```sh
make        # x86_64-elf-gcc, freestanding -> build/libpurecrypt.a
make test   # host gcc: FIPS vectors + differential test vs glibc -lcrypt
make clean
```

## Kernel integration (clone sources, not the .a)

In `src/kernel/Makefile` (or wherever kernel objects are listed):

```make
CRYPT_SRCS := $(ROOT_DIR)/libxcrypt/src/sha512.c \
              $(ROOT_DIR)/libxcrypt/src/crypt_sha512.c
CPPFLAGS   += -I$(ROOT_DIR)/libxcrypt/include
# compile $(CRYPT_SRCS) with $(KERNEL_CFLAGS) like other kernel .c files
```

Userspace links `build/libpurecrypt.a` instead.

## Verification

- `test_sha512`: FIPS 180-4 vectors (`""`, `"abc"`, 112-byte, 1M×`'a'`),
  cross-checked with `sha512sum`(1)/OpenSSL/Wikipedia.
- `test_crypt`: 10 password/salt/rounds combos byte-identical to glibc
  `crypt_r("$6$...")`, plus wrong-password/tampered/malformed rejects.

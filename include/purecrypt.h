#pragma once
/* Password hashing for PureC OS: SHA512-crypt (glorified "$6$",
 * Ulrich Drepper spec), compatible with glibc crypt().
 *
 * Freestanding: no libc, no malloc, no RNG inside. The caller supplies
 * randomness for salts (kernel: your RNG; userspace: /dev/urandom etc).
 * All buffers are caller-owned, secrets are wiped, comparison is
 * constant-time. Integer-only: kernel-safe (-mgeneral-regs-only). */
#include <stddef.h>
#include <stdint.h>

#define PURECRYPT_SALT_MAX 16
#define PURECRYPT_PASS_MAX 512
#define PURECRYPT_HASH_MAX 128 /* "$6$rounds=999999999$<16>$<86>" + NUL fits */
#define PURECRYPT_ROUNDS_DEFAULT 5000u
#define PURECRYPT_ROUNDS_MIN 1000u
#define PURECRYPT_ROUNDS_MAX 999999999u

/* Hash password. salt: up to 16 chars of [./0-9A-Za-z].
 * rounds==0 selects PURECRYPT_ROUNDS_DEFAULT. Returns 0 on success,
 * -1 on bad input (salt charset, password too long, out==NULL). */
int purecrypt_hash(const char *password, const char *salt, unsigned rounds,
                   char out[PURECRYPT_HASH_MAX]);

/* Verify password against a "$6$..." string. Returns 1 on match,
 * 0 on mismatch, -1 on malformed input. Comparison is constant-time
 * over the hash body. */
int purecrypt_verify(const char *password, const char *expected);

/* Build a 16-char salt string from 16 caller-supplied random bytes.
 * salt_out must hold 17 bytes. Always succeeds. */
void purecrypt_gensalt(const uint8_t raw16[16], char salt_out[17]);

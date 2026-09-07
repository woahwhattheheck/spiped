/* Synthetic-key observer for PR437. Link the real liball.a and retain the
 * real zeroing implementation. Never read a stack buffer after its return. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "insecure_memzero.h"
#include "proto_crypt.h"
#include "sha256.h"

static const char *mode, *keypath;
static FILE *target;
static int in_secret, in_dhmac, injected, allocation_attempted;
static long fail_after;
static size_t bytes_read, initialized;
static void *secret_allocation;
static uint8_t *read_buffer, *derived_buffer;
static void (*real_zero)(volatile void *, size_t);
static unsigned buffer_wipes, buffer_nonzero_before, buffer_bad_after;
static unsigned secret_wipes, secret_bad_after, secret_frees;
static unsigned derived_wipes, derived_bad_after, derived_matches, copied_before_wipe;
static unsigned close_calls, read_calls, pbkdf_calls, allocation_failures;
static uint8_t saved_derived[64], output_l[32], output_r[32];
static int direction;

FILE *__real_fopen(const char *, const char *);
size_t __real_fread(void *, size_t, size_t, FILE *);
int __real_feof(FILE *);
int __real_fclose(FILE *);
void *__real_malloc(size_t);
void __real_free(void *);
void __real_PBKDF2_SHA256(const uint8_t *, size_t, const uint8_t *, size_t,
    uint64_t, uint8_t *, size_t);

void *__wrap_malloc(size_t n)
{
    void *p;
    int first = in_secret && !allocation_attempted;
    if (first) {
        allocation_attempted = 1;
        if (n != 32) abort();
        if (strcmp(mode, "malloc-error") == 0) {
            allocation_failures++;
            errno = ENOMEM;
            return NULL;
        }
    }
    p = __real_malloc(n);
    if (first) secret_allocation = p;
    return p;
}

void __wrap_free(void *p)
{
    if (p && p == secret_allocation) secret_frees++;
    __real_free(p);
}

FILE *__wrap_fopen(const char *path, const char *access)
{
    FILE *f;
    if (in_secret && strcmp(path, keypath) == 0 &&
        strcmp(mode, "open-error") == 0) {
        errno = EACCES;
        return NULL;
    }
    f = __real_fopen(path, access);
    if (in_secret && strcmp(path, keypath) == 0) target = f;
    return f;
}

size_t __wrap_fread(void *p, size_t size, size_t count, FILE *f)
{
    size_t n, remaining;
    if (!in_secret || f != target) return __real_fread(p, size, count, f);
    if (size != 1 || count != BUFSIZ) abort();
    if (read_buffer && read_buffer != p) abort();
    read_buffer = p;
    read_calls++;
    if (strcmp(mode, "read-error") == 0) {
        if (bytes_read >= (size_t)fail_after) {
            injected = 1;
            errno = EIO;
            return 0;
        }
        remaining = (size_t)fail_after - bytes_read;
        if (count > remaining) count = remaining;
    }
    n = __real_fread(p, size, count, f);
    bytes_read += n;
    if (n > initialized) initialized = n;
    return n;
}

int __wrap_feof(FILE *f)
{
    if (in_secret && f == target && injected) return 0;
    return __real_feof(f);
}

int __wrap_fclose(FILE *f)
{
    int rc, ours = in_secret && f == target;
    rc = __real_fclose(f);
    if (ours) {
        close_calls++;
        if (strcmp(mode, "close-error") == 0) {
            errno = EIO;
            return EOF;
        }
    }
    return rc;
}

void __wrap_PBKDF2_SHA256(const uint8_t *password, size_t plen,
    const uint8_t *salt, size_t slen, uint64_t iterations, uint8_t *out, size_t n)
{
    if (in_dhmac) {
        if (n != 64 || iterations != 1 || plen != 32 || slen != 64) abort();
        derived_buffer = out;
        pbkdf_calls++;
    }
    __real_PBKDF2_SHA256(password, plen, salt, slen, iterations, out, n);
    if (in_dhmac) memcpy(saved_derived, out, n);
}

static unsigned nonzero(volatile const uint8_t *p, size_t n)
{
    unsigned result = 0;
    size_t i;
    for (i = 0; i < n; i++) result += p[i] != 0;
    return result;
}

static void observe_zero(volatile void *p, size_t n)
{
    int is_buffer = in_secret && p == read_buffer && n == BUFSIZ;
    int is_derived = in_dhmac && p == derived_buffer && n == 64;
    int is_secret = p == secret_allocation && n == 32;
    if (is_buffer) {
        buffer_wipes++;
        /* Only inspect bytes which fread actually initialized. */
        buffer_nonzero_before += nonzero(p, initialized);
    }
    if (is_derived) {
        derived_wipes++;
        if (memcmp((const void *)p, saved_derived, 64) == 0) derived_matches++;
        if (memcmp(direction ? output_r : output_l, saved_derived, 32) == 0 &&
            memcmp(direction ? output_l : output_r, saved_derived + 32, 32) == 0)
            copied_before_wipe++;
    }
    if (is_secret) secret_wipes++;
    real_zero(p, n);
    if (is_buffer) buffer_bad_after += nonzero(p, n);
    if (is_derived) derived_bad_after += nonzero(p, n);
    if (is_secret) secret_bad_after += nonzero(p, n);
}

static void hexout(const uint8_t *p, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
}

int main(int argc, char **argv)
{
    struct proto_secret *key;
    uint8_t nonce_l[32], nonce_r[32];
    char *end;
    int success;
    size_t i;
    if (argc == 2 && strcmp(argv[1], "--bufsiz") == 0) {
        printf("%d\n", BUFSIZ);
        return 0;
    }
    if (argc != 5) return 2;
    mode = argv[1];
    keypath = argv[2];
    fail_after = strtol(argv[3], &end, 10);
    if (*end || fail_after < 0) return 2;
    direction = (int)strtol(argv[4], &end, 10);
    if (*end || (direction != 0 && direction != 1)) return 2;
    if (strcmp(keypath, "-") == 0) target = stdin;
    real_zero = insecure_memzero_ptr;
    insecure_memzero_ptr = observe_zero;
    in_secret = 1;
    key = proto_crypt_secret(keypath);
    in_secret = 0;
    success = key != NULL;
    if (key) {
        for (i = 0; i < 32; i++) {
            nonce_l[i] = (uint8_t)i;
            nonce_r[i] = (uint8_t)(i + 32);
        }
        in_dhmac = 1;
        proto_crypt_dhmac(key, nonce_l, nonce_r, output_l, output_r, direction);
        in_dhmac = 0;
        proto_crypt_secret_free(key);
    }
    insecure_memzero_ptr = real_zero;
    printf("{\"success\":%d,\"bufsiz\":%d,\"bytes_read\":%zu,\"initialized\":%zu,"
        "\"read_calls\":%u,\"close_calls\":%u,\"injected_read_error\":%d,"
        "\"allocation_failures\":%u,\"buffer_wipes\":%u,\"buffer_nonzero_before\":%u,"
        "\"buffer_bad_after\":%u,\"secret_wipes\":%u,\"secret_bad_after\":%u,"
        "\"secret_frees\":%u,\"pbkdf_calls\":%u,\"derived_wipes\":%u,"
        "\"derived_bad_after\":%u,\"derived_matches\":%u,\"copied_before_wipe\":%u,"
        "\"output_l\":\"",
        success, BUFSIZ, bytes_read, initialized, read_calls, close_calls, injected,
        allocation_failures, buffer_wipes, buffer_nonzero_before, buffer_bad_after,
        secret_wipes, secret_bad_after, secret_frees, pbkdf_calls, derived_wipes,
        derived_bad_after, derived_matches, copied_before_wipe);
    hexout(output_l, 32);
    printf("\",\"output_r\":\"");
    hexout(output_r, 32);
    printf("\"}\n");
    return 0;
}

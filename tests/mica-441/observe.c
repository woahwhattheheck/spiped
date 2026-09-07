/* PR441: exact-source handshake with real local networking and crypto.
 * Heap-cookie bytes are initialized to a known test pattern to avoid reading
 * uninitialized memory on early failures. No memory is read after free. */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "events.h"
#include "insecure_memzero.h"
#ifndef MICA_HANDSHAKE_SOURCE
#error Define MICA_HANDSHAKE_SOURCE as the exact source path
#endif
#include MICA_HANDSHAKE_SOURCE

struct observation {
    struct handshake_cookie *h;
    int side, freed, wipes, x_ready, mac_ready;
    unsigned before, after, at_free, x_before, mac_before;
    int pending_at_wipe, pending_at_free, callback_at_wipe, callback_at_free;
    const char *reason;
};
struct operation {
    void *handle;
    struct handshake_cookie *h;
    int (*fn)(void *, ssize_t);
    int active, read;
};
static struct observation obs[2];
static struct operation ops[32];
static int observations, operations, expect_allocation, inside_start, canceling;
static int start_side, role, callback_status, callback_count[2], callback_success[2];
static int sockets[2] = {-1, -1}, expired, read_cancels, write_cancels;
static int packet_roundtrips, corrupted_packets_rejected, allocation_failures;
static const char *mode;
static struct proto_keys *keys_c[2], *keys_s[2];
static void (*real_zero)(volatile void *, size_t);

void *__real_malloc(size_t);
void __real_free(void *);
int __real_crypto_entropy_read(uint8_t *, size_t);
void *__real_network_read(int, uint8_t *, size_t, size_t, int (*)(void *, ssize_t), void *);
void *__real_network_write(int, const uint8_t *, size_t, size_t, int (*)(void *, ssize_t), void *);
void __real_network_read_cancel(void *);
void __real_network_write_cancel(void *);
void __real_proto_crypt_dhmac(const struct proto_secret *, const uint8_t *, const uint8_t *, uint8_t *, uint8_t *, int);
int __real_proto_crypt_dh_generate(uint8_t *, uint8_t *, const uint8_t *, int);
int __real_proto_crypt_mkkeys(const struct proto_secret *, const uint8_t *, const uint8_t *,
    const uint8_t *, const uint8_t *, int, int, struct proto_keys **, struct proto_keys **);

static unsigned nonzero(volatile const uint8_t *p, size_t n)
{
    size_t i; unsigned count = 0;
    for (i = 0; i < n; i++) count += p[i] != 0;
    return count;
}
static struct observation *find_h(const volatile void *p)
{
    int i;
    for (i = 0; i < observations; i++) if (!obs[i].freed && obs[i].h == p) return &obs[i];
    return NULL;
}
static int pending(struct handshake_cookie *h)
{
    int i, count = 0;
    for (i = 0; i < operations; i++) if (ops[i].h == h) count += ops[i].active;
    return count;
}
static void private_counts(struct observation *o)
{
    if (o->x_ready) o->x_before = nonzero(o->h->x, sizeof(o->h->x));
    if (o->mac_ready) o->mac_before = nonzero(o->h->dhmac_local, sizeof(o->h->dhmac_local)) +
        nonzero(o->h->dhmac_remote, sizeof(o->h->dhmac_remote));
}
void *__wrap_malloc(size_t n)
{
    void *p;
    if (!expect_allocation) return __real_malloc(n);
    expect_allocation = 0;
    assert(n == sizeof(struct handshake_cookie));
    if (strcmp(mode, "malloc-fail") == 0) {
        allocation_failures++; errno = ENOMEM; return NULL;
    }
    p = __real_malloc(n);
    assert(p && observations < 2);
    memset(p, 0xa5, n); /* Test initialization, not alleged production secrets. */
    obs[observations++] = (struct observation){.h=p, .side=start_side};
    return p;
}
void __wrap_free(void *p)
{
    struct observation *o = find_h(p);
    if (o) {
        o->at_free = nonzero(p, sizeof(struct handshake_cookie));
        o->pending_at_free = pending(o->h);
        o->callback_at_free = callback_count[o->side];
        if (!o->wipes) private_counts(o);
        o->reason = inside_start ? "initial" : canceling ? "cancel" :
                    callback_success[o->side] ? "done" : "fail";
        o->freed = 1;
    }
    __real_free(p);
}
static void observe_zero(volatile void *p, size_t n)
{
    struct observation *o = find_h(p);
    if (o) {
        assert(n == sizeof(struct handshake_cookie));
        o->wipes++;
        o->before = nonzero(p, n);
        o->pending_at_wipe = pending(o->h);
        o->callback_at_wipe = callback_count[o->side];
        private_counts(o);
    }
    real_zero(p, n);
    if (o) o->after = nonzero(p, n);
}
int __wrap_crypto_entropy_read(uint8_t *p, size_t n)
{
    if (inside_start && strcmp(mode, "entropy-fail") == 0) { errno = EIO; return -1; }
    return __real_crypto_entropy_read(p, n);
}
static int network_bridge(void *cookie, ssize_t n)
{
    struct operation *o = cookie;
    assert(o->active);
    o->active = 0;
    return o->fn(o->h, n);
}
void *__wrap_network_read(int fd, uint8_t *p, size_t n, size_t minimum,
    int (*fn)(void *, ssize_t), void *cookie)
{
    struct operation *o;
    void *handle;
    if (inside_start && strcmp(mode, "read-fail") == 0) { errno = ENOMEM; return NULL; }
    assert(find_h(cookie) && operations < 32);
    o = &ops[operations++];
    *o = (struct operation){.h=cookie, .fn=fn, .read=1};
    handle = __real_network_read(fd, p, n, minimum, network_bridge, o);
    assert(handle);
    o->handle = handle; o->active = 1;
    return handle;
}
void *__wrap_network_write(int fd, const uint8_t *p, size_t n, size_t minimum,
    int (*fn)(void *, ssize_t), void *cookie)
{
    struct operation *o;
    void *handle;
    if (inside_start && strcmp(mode, "write-fail") == 0) { errno = ENOMEM; return NULL; }
    assert(find_h(cookie) && operations < 32);
    o = &ops[operations++];
    *o = (struct operation){.h=cookie, .fn=fn};
    handle = __real_network_write(fd, p, n, minimum, network_bridge, o);
    assert(handle);
    o->handle = handle; o->active = 1;
    return handle;
}
void __wrap_network_read_cancel(void *cookie)
{
    int i;
    for (i = 0; i < operations; i++) if (ops[i].active && ops[i].handle == cookie) {
        assert(ops[i].read);
        __real_network_read_cancel(cookie);
        ops[i].active = 0; read_cancels++; return;
    }
    abort();
}
void __wrap_network_write_cancel(void *cookie)
{
    int i;
    for (i = 0; i < operations; i++) if (ops[i].active && ops[i].handle == cookie) {
        assert(!ops[i].read);
        __real_network_write_cancel(cookie);
        ops[i].active = 0; write_cancels++; return;
    }
    abort();
}
void __wrap_proto_crypt_dhmac(const struct proto_secret *k, const uint8_t *l,
    const uint8_t *r, uint8_t *out_l, uint8_t *out_r, int decr)
{
    int i;
    __real_proto_crypt_dhmac(k, l, r, out_l, out_r, decr);
    for (i = 0; i < observations; i++) if (!obs[i].freed && out_l == obs[i].h->dhmac_local)
        obs[i].mac_ready = 1;
}
int __wrap_proto_crypt_dh_generate(uint8_t *yh, uint8_t *x, const uint8_t *mac, int nopfs)
{
    int i, rc = __real_proto_crypt_dh_generate(yh, x, mac, nopfs);
    if (!rc && !nopfs) for (i = 0; i < observations; i++)
        if (!obs[i].freed && x == obs[i].h->x) obs[i].x_ready = 1;
    return rc;
}
int __wrap_proto_crypt_mkkeys(const struct proto_secret *k, const uint8_t *l, const uint8_t *r,
    const uint8_t *yh, const uint8_t *x, int nopfs, int decr,
    struct proto_keys **c, struct proto_keys **s)
{
    if (strcmp(mode, "mkkeys-fail") == 0) { errno = ENOMEM; return -1; }
    return __real_proto_crypt_mkkeys(k, l, r, yh, x, nopfs, decr, c, s);
}
static int completion(void *cookie, struct proto_keys *c, struct proto_keys *s)
{
    int id = (int)(uintptr_t)cookie;
    assert(id == 0 || id == 1);
    assert(callback_count[id] == 0);
    assert((c == NULL) == (s == NULL));
    callback_count[id]++;
    callback_success[id] = c != NULL;
    keys_c[id] = c; keys_s[id] = s;
    if (!c && sockets[id] >= 0) { assert(close(sockets[id]) == 0); sockets[id] = -1; }
    return callback_status;
}
static int timer_done(void *cookie) { (void)cookie; expired = 1; return 0; }
static void drive(int target, int until_mac)
{
    void *timer;
    int steps = 0;
    expired = 0;
    timer = events_timer_register_double(timer_done, NULL, 2.0);
    assert(timer);
    while ((until_mac ? !obs[0].mac_ready : callback_count[0]+callback_count[1] < target) && !expired) {
        int rc = events_run();
        assert(rc == 0 || rc == 7 || rc == -1);
        assert(++steps < 100);
    }
    assert(!expired);
    events_timer_cancel(timer);
}
static void quiet_check(void)
{
    int before = callback_count[0] + callback_count[1];
    int steps = 0;
    expired = 0;
    assert(events_timer_register_double(timer_done, NULL, 0.002));
    while (!expired) { assert(events_run() == 0); assert(++steps < 100); }
    assert(callback_count[0] + callback_count[1] == before);
}
static void *begin(int id, int decr, int nopfs, int requirepfs, const struct proto_secret *k)
{
    void *h;
    inside_start = 1; expect_allocation = 1; start_side = id;
    h = proto_handshake(sockets[id], decr, nopfs, requirepfs, k, completion, (void *)(uintptr_t)id);
    inside_start = 0;
    return h;
}
static void packet_checks(void)
{
    static const size_t lengths[] = {1, 31, 32, 1023, 1024};
    uint8_t plain[1024], wire[PCRYPT_ESZ], damaged[PCRYPT_ESZ], out[1024];
    size_t i, j, n;
    int direction;
    struct proto_keys *sender, *receiver;
    for (direction = 0; direction < 2; direction++) {
        sender = direction ? keys_s[1] : keys_c[0];
        receiver = direction ? keys_s[0] : keys_c[1];
        assert(sender && receiver);
        for (i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
            n = lengths[i];
            for (j = 0; j < n; j++) plain[j] = (uint8_t)(j * 17 + i);
            proto_crypt_enc(plain, n, wire, sender);
            memcpy(damaged, wire, sizeof(wire)); damaged[sizeof(wire)-1] ^= 1;
            assert(proto_crypt_dec(damaged, out, receiver) == -1);
            corrupted_packets_rejected++;
            assert(proto_crypt_dec(wire, out, receiver) == (ssize_t)n);
            assert(memcmp(out, plain, n) == 0);
            packet_roundtrips++;
        }
    }
}
int main(int argc, char **argv)
{
    struct proto_secret *k[2] = {NULL, NULL};
    void *h[2] = {NULL, NULL};
    uint8_t remote_nonce[32];
    int i, pair, initial_failure, total_pending = 0;
    if (argc != 6) return 2;
    mode = argv[1]; role = atoi(argv[2]); callback_status = atoi(argv[3]);
    if ((role != 0 && role != 1) || (callback_status != 0 && callback_status != 7)) return 2;
    pair = strcmp(mode, "success-pfs") == 0 || strcmp(mode, "success-weak") == 0 ||
           strcmp(mode, "wrong-secret") == 0 || strcmp(mode, "pfs-reject") == 0 ||
           strcmp(mode, "mkkeys-fail") == 0;
    initial_failure = strcmp(mode, "malloc-fail") == 0 || strcmp(mode, "entropy-fail") == 0 ||
           strcmp(mode, "write-fail") == 0 || strcmp(mode, "read-fail") == 0;
    assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    for (i = 0; i < 2; i++) assert(fcntl(sockets[i], F_SETFL, O_NONBLOCK) == 0);
    k[0] = proto_crypt_secret(argv[4]); assert(k[0]);
    if (pair) { k[1] = proto_crypt_secret(strcmp(mode, "wrong-secret") == 0 ? argv[5] : argv[4]); assert(k[1]); }
    real_zero = insecure_memzero_ptr; insecure_memzero_ptr = observe_zero;
    if (pair) {
        int weak = strcmp(mode, "success-weak") == 0;
        int reject = strcmp(mode, "pfs-reject") == 0;
        h[0] = begin(0, 0, weak || reject, !weak && !reject, k[0]);
        h[1] = begin(1, 1, weak, !weak, k[1]);
        assert(h[0] && h[1]);
        drive(2, 0);
        if (callback_success[0] && callback_success[1]) packet_checks();
    } else {
        h[0] = begin(0, role, 0, 1, k[0]);
        if (initial_failure) { assert(!h[0]); quiet_check(); }
        else if (strcmp(mode, "cancel-start") == 0) {
            assert(h[0]); canceling = 1; proto_handshake_cancel(h[0]); canceling = 0; quiet_check();
        } else {
            assert(h[0]);
            if (strcmp(mode, "cancel-dh") == 0 || strcmp(mode, "eof-dh") == 0) {
                for (i = 0; i < 32; i++) remote_nonce[i] = (uint8_t)(i+1);
                assert(write(sockets[1], remote_nonce, 32) == 32);
            }
            if (strcmp(mode, "cancel-dh") == 0) {
                drive(0, 1); assert(!obs[0].freed);
                canceling = 1; proto_handshake_cancel(h[0]); canceling = 0; quiet_check();
            } else {
                assert(strcmp(mode, "eof-nonce") == 0 || strcmp(mode, "eof-dh") == 0);
                assert(shutdown(sockets[1], SHUT_WR) == 0); drive(1, 0);
            }
        }
    }
    for (i = 0; i < observations; i++) assert(obs[i].freed);
    for (i = 0; i < operations; i++) total_pending += ops[i].active;
    assert(total_pending == 0);
    insecure_memzero_ptr = real_zero;
    for (i = 0; i < 2; i++) {
        proto_crypt_free(keys_c[i]); proto_crypt_free(keys_s[i]); proto_crypt_secret_free(k[i]);
        if (sockets[i] >= 0) assert(close(sockets[i]) == 0);
    }
    printf("{\"cookie_size\":%zu,\"allocation_failures\":%d,\"callbacks\":[%d,%d],"
           "\"success\":[%d,%d],\"read_cancels\":%d,\"write_cancels\":%d,"
           "\"pending_operations\":%d,\"packet_roundtrips\":%d,"
           "\"corrupted_packets_rejected\":%d,\"cookies\":[",
           sizeof(struct handshake_cookie), allocation_failures, callback_count[0], callback_count[1],
           callback_success[0], callback_success[1], read_cancels, write_cancels, total_pending,
           packet_roundtrips, corrupted_packets_rejected);
    for (i = 0; i < observations; i++) {
        struct observation *o = &obs[i];
        if (i) printf(",");
        printf("{\"side\":%d,\"freed\":%d,\"wipes\":%d,\"before_wipe\":%u,\"after_wipe\":%u,"
               "\"nonzero_at_free\":%u,\"pending_at_wipe\":%d,\"pending_at_free\":%d,"
               "\"callback_at_wipe\":%d,\"callback_at_free\":%d,\"reason\":\"%s\","
               "\"x_generated\":%d,\"mac_derived\":%d,\"x_nonzero_before_clear\":%u,\"mac_nonzero_before_clear\":%u}",
               o->side, o->freed, o->wipes, o->before, o->after, o->at_free,
               o->pending_at_wipe, o->pending_at_free, o->callback_at_wipe, o->callback_at_free,
               o->reason, o->x_ready, o->mac_ready, o->x_before, o->mac_before);
    }
    printf("]}\n");
    return 0;
}

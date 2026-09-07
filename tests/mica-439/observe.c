/* Exact-source PR439 observer. Actual pthread worker, mutex, socketpair,
 * event registration/cancellation, and event dispatch remain in use.
 * Only resolver results and chosen allocation/register/signal errors are
 * injected. Synthetic .invalid names are never sent to an external resolver. */
#include <assert.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>

#ifndef MICA_DNSTHREAD_SOURCE
#error Define MICA_DNSTHREAD_SOURCE as the exact checkout source path
#endif
#include MICA_DNSTHREAD_SOURCE

#define MAX_TRACKED 32
struct allocation { void *p; int live; };
struct snapshot {
    int rc, error, state_before_unlock, active, addresses, registers, signals;
    char trace[64];
};
struct callback_cookie { int id; };

static DNSTHREAD current;
static pthread_t main_thread;
static int in_request, fault, dns_failure, callback_return, active_listener;
static int state_before_unlock, reg_calls, signal_calls, cancel_calls;
static int signal_successes, joined, manual_cleanup;
static int addr_count, result_count, addr_frees, result_frees;
static int manual_addr_frees, manual_result_frees;
static struct allocation addresses[MAX_TRACKED], results[MAX_TRACKED];
static atomic_int wait_entries, resolver_started, resolver_allowed;
static char trace_text[64];
static size_t trace_length;
static int callback_count, callback_ids[MAX_TRACKED], callback_errors[MAX_TRACKED];
static int callback_nonnull[MAX_TRACKED], event_returns[MAX_TRACKED];
static struct callback_cookie cookies[MAX_TRACKED];

char *__real_strdup(const char *);
void __real_free(void *);
int __real_events_network_register(int (*)(void *), void *, int, int);
int __real_events_network_cancel(int, int);
int __real_pthread_cond_signal(pthread_cond_t *);
int __real_pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __real_pthread_join(pthread_t, void **);

static int is_main(void) { return pthread_equal(pthread_self(), main_thread); }
static void trace(char c)
{
    if (!in_request || !is_main()) return;
    assert(trace_length + 1 < sizeof(trace_text));
    trace_text[trace_length++] = c;
    trace_text[trace_length] = 0;
}
static int live_count(struct allocation *list, int n)
{
    int i, count = 0;
    for (i = 0; i < n; i++) count += list[i].live;
    return count;
}
static long milliseconds(void)
{
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}
static void wait_nonzero(atomic_int *value)
{
    long end = milliseconds() + 2000;
    const struct timespec delay = {0, 1000000};
    while (!atomic_load(value)) {
        assert(milliseconds() < end);
        nanosleep(&delay, NULL);
    }
}

char *__wrap_strdup(const char *s)
{
    char *p;
    if (!in_request || !is_main()) return __real_strdup(s);
    trace('D');
    if (fault == 1) { errno = ENOMEM; return NULL; }
    p = __real_strdup(s);
    assert(p && addr_count < MAX_TRACKED);
    addresses[addr_count++] = (struct allocation){p, 1};
    return p;
}
void __wrap_free(void *p)
{
    int i;
    for (i = 0; i < addr_count; i++) {
        if (p && addresses[i].live && addresses[i].p == p) {
            addresses[i].live = 0;
            if (manual_cleanup) manual_addr_frees++;
            else { addr_frees++; trace('F'); }
            break;
        }
    }
    for (i = 0; i < result_count; i++) {
        if (p && results[i].live && results[i].p == p) {
            results[i].live = 0;
            if (manual_cleanup) manual_result_frees++;
            else result_frees++;
            break;
        }
    }
    __real_free(p);
}
int __wrap_events_network_register(int (*fn)(void *), void *cookie, int fd, int op)
{
    int rc;
    if (in_request && is_main()) {
        trace('R'); reg_calls++;
        assert(cookie == current && fd == current->wakeupsock[1]);
        assert(op == EVENTS_NETWORK_OP_READ);
        if (fault == 2) { errno = ENOMEM; return -1; }
    }
    rc = __real_events_network_register(fn, cookie, fd, op);
    if (rc == 0) active_listener = 1;
    return rc;
}
int __wrap_events_network_cancel(int fd, int op)
{
    int rc;
    if (in_request && is_main()) {
        trace('C'); cancel_calls++;
        assert(current->state == THREAD_SLEEPING);
    }
    rc = __real_events_network_cancel(fd, op);
    if (rc == 0) active_listener = 0;
    return rc;
}
int __wrap_pthread_cond_signal(pthread_cond_t *cv)
{
    int rc;
    if (in_request && is_main() && cv == &current->cv) {
        trace('S'); signal_calls++;
        assert(current->state == THREAD_HASWORK);
        if (fault == 3) return EINVAL;
        rc = __real_pthread_cond_signal(cv);
        if (rc == 0) signal_successes++;
        return rc;
    }
    return __real_pthread_cond_signal(cv);
}
int __wrap_pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mtx)
{
    atomic_fetch_add(&wait_entries, 1);
    return __real_pthread_cond_wait(cv, mtx);
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mtx)
{
    if (in_request && is_main() && current && mtx == &current->mtx)
        state_before_unlock = current->state;
    return __real_pthread_mutex_unlock(mtx);
}
int __wrap_pthread_join(pthread_t thread, void **value)
{
    joined++;
    return __real_pthread_join(thread, value);
}
struct sock_addr **__wrap_sock_resolve(const char *name)
{
    struct sock_addr **answer;
    /* The input is read only while the exact worker owns its live address. */
    assert(strstr(name, ".invalid:") != NULL);
    atomic_fetch_add(&resolver_started, 1);
    wait_nonzero(&resolver_allowed);
    if (dns_failure) { errno = EHOSTUNREACH; return NULL; }
    answer = calloc(1, sizeof(*answer));
    assert(answer && result_count < MAX_TRACKED);
    results[result_count++] = (struct allocation){answer, 1};
    return answer;
}

static int user_callback(void *cookie, struct sock_addr **sas)
{
    int n = callback_count++;
    assert(n < MAX_TRACKED);
    active_listener = 0; /* The real event loop's registration was one-shot. */
    callback_ids[n] = ((struct callback_cookie *)cookie)->id;
    callback_errors[n] = errno;
    callback_nonnull[n] = sas != NULL;
    if (sas) { assert(sas[0] == NULL); free(sas); }
    return callback_return;
}
static struct snapshot request(int injected_fault, int id)
{
    struct snapshot s;
    int before_reg = reg_calls, before_signal = signal_calls;
    fault = injected_fault;
    trace_length = 0;
    trace_text[0] = 0;
    state_before_unlock = -99;
    cookies[id].id = id;
    in_request = 1;
    errno = 0;
    s.rc = dnsthread_resolveone(current, "mica-synthetic.invalid:443",
                              user_callback, &cookies[id]);
    s.error = errno;
    in_request = 0;
    s.state_before_unlock = state_before_unlock;
    s.active = active_listener;
    s.addresses = live_count(addresses, addr_count);
    s.registers = reg_calls - before_reg;
    s.signals = signal_calls - before_signal;
    strcpy(s.trace, trace_text);
    return s;
}
static void await_byte(void)
{
    struct pollfd p = {current->wakeupsock[1], POLLIN, 0};
    int rc;
    do { rc = poll(&p, 1, 2000); } while (rc < 0 && errno == EINTR);
    assert(rc == 1 && (p.revents & POLLIN));
}
static void dispatch(void)
{
    int before = callback_count, rc;
    await_byte();
    errno = 0;
    rc = events_run();
    assert(callback_count == before + 1);
    event_returns[before] = rc;
}
static void print_snapshot(const char *name, struct snapshot *s)
{
    printf("\"%s\":{\"rc\":%d,\"errno\":%d,\"state_before_unlock\":%d,"
           "\"listener_active\":%d,\"addresses_live\":%d,\"register_calls\":%d,"
           "\"signal_calls\":%d,\"trace\":\"%s\"}", name, s->rc, s->error,
           s->state_before_unlock, s->active, s->addresses, s->registers,
           s->signals, s->trace);
}
int main(int argc, char **argv)
{
    struct snapshot first, retry, extra;
    pthread_t worker;
    int mode, rounds, i, orphan_byte = 0, orphan_state = -1;
    int live_addr_before_cleanup, live_results_before_cleanup;
    uint8_t zero;
    if (argc != 5) return 2;
    mode = atoi(argv[1]); dns_failure = atoi(argv[2]);
    callback_return = atoi(argv[3]); rounds = atoi(argv[4]);
    if (mode < 0 || mode > 3 || dns_failure < 0 || dns_failure > 1 ||
        (callback_return != 0 && callback_return != 7) || rounds < 1 || rounds > 3) return 2;
    main_thread = pthread_self();
    current = dnsthread_spawn();
    assert(current);
    worker = current->thr;
    /* Entry is announced with the real worker mutex still held. The next
     * request cannot acquire it until pthread_cond_wait releases it. */
    wait_nonzero(&wait_entries);
    first = request(mode, 0);
    retry = request(0, 1);
    atomic_store(&resolver_allowed, 1);
    if (active_listener) {
        dispatch();
        for (i = 1; i < rounds; i++) {
            extra = request(0, i + 1);
            assert(extra.rc == 0 && extra.error != EALREADY && extra.active);
            dispatch();
        }
    } else if (signal_successes) {
        /* Old registration failure: let its real worker finish, record the
         * unowned completion byte, but never invoke an absent callback. */
        await_byte();
        assert(pthread_mutex_lock(&current->mtx) == 0);
        orphan_state = current->state;
        assert(read(current->wakeupsock[1], &zero, 1) == 1);
        orphan_byte = 1;
        assert(pthread_mutex_unlock(&current->mtx) == 0);
    }
    assert(!active_listener);
    /* kill() joins internally only when the worker was sleeping. */
    assert(dnsthread_kill(current) == 0);
    if (!joined) { assert(__real_pthread_join(worker, NULL) == 0); joined++; }
    current = NULL;
    live_addr_before_cleanup = live_count(addresses, addr_count);
    live_results_before_cleanup = live_count(results, result_count);
    /* Clean test-created old-revision leaks only AFTER recording them and
     * joining the worker. These frees are separate from production frees. */
    manual_cleanup = 1;
    for (i = 0; i < addr_count; i++) if (addresses[i].live) free(addresses[i].p);
    for (i = 0; i < result_count; i++) if (results[i].live) free(results[i].p);
    printf("{");
    print_snapshot("first", &first); printf(","); print_snapshot("retry", &retry);
    printf(",\"callbacks\":[");
    for (i = 0; i < callback_count; i++) {
        if (i) printf(",");
        printf("{\"cookie_id\":%d,\"errno\":%d,\"nonnull_result\":%d,\"event_return\":%d}",
               callback_ids[i], callback_errors[i], callback_nonnull[i], event_returns[i]);
    }
    printf("],\"resolver_calls\":%d,\"cancellations\":%d,\"orphan_byte\":%d,"
           "\"orphan_state\":%d,\"address_allocations\":%d,\"production_address_frees\":%d,"
           "\"addresses_live_before_manual_cleanup\":%d,\"results_live_before_manual_cleanup\":%d,"
           "\"production_result_frees\":%d,\"manual_address_frees\":%d,"
           "\"manual_result_frees\":%d,\"joins\":%d}\n",
           atomic_load(&resolver_started), cancel_calls, orphan_byte, orphan_state,
           addr_count, addr_frees, live_addr_before_cleanup, live_results_before_cleanup,
           result_frees, manual_addr_frees, manual_result_frees, joined);
    return 0;
}

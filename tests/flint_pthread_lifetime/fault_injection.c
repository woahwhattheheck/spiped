/* FLINT: deterministic error-path test, not a natural libc-failure claim.
 * Real pthreads/allocations are used. Link --wrap replaces only the selected
 * primitive's one parent-side call; all other calls delegate to real libc.
 */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pthread_create_blocking_np.h"
#include "warnp.h"

static int mode;
static int armed;
static pthread_t parent_thread;
static sem_t entered;
static sem_t release_worker;
static _Atomic int injected;
static _Atomic int routine_entered;
static _Atomic int routine_cleanups;
static _Atomic int seen_value;

struct payload { int value; };

static void wait_sem(sem_t *s) {
    int rc;
    do { rc = sem_wait(s); } while (rc != 0 && errno == EINTR);
    assert(rc == 0);
}

static int take_fault(int target, int require_worker) {
    if (!armed || mode != target || !pthread_equal(pthread_self(), parent_thread))
        return 0;
    if (atomic_exchange(&injected, 1))
        return 0;
    /* Makes lifetime evidence deterministic: callback owns payload and has
     * installed its cancellation cleanup before the parent sees the error. */
    if (require_worker)
        wait_sem(&entered);
    return 1;
}

int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __wrap_pthread_mutex_unlock(pthread_mutex_t *m) {
    if (take_fault(1, 1)) return EPERM; /* Deliberately does NOT unlock. */
    return __real_pthread_mutex_unlock(m);
}
int __real_pthread_cond_destroy(pthread_cond_t *);
int __wrap_pthread_cond_destroy(pthread_cond_t *c) {
    if (take_fault(2, 1)) return EBUSY;
    return __real_pthread_cond_destroy(c);
}
int __real_pthread_mutex_destroy(pthread_mutex_t *);
int __wrap_pthread_mutex_destroy(pthread_mutex_t *m) {
    if (take_fault(3, 1)) return EBUSY;
    return __real_pthread_mutex_destroy(m);
}
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg) {
    if (take_fault(4, 0)) return EAGAIN;
    return __real_pthread_create(t, a, fn, arg);
}
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a) {
    if (take_fault(5, 0)) return ENOMEM;
    return __real_pthread_mutex_init(m, a);
}
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a) {
    if (take_fault(6, 0)) return ENOMEM;
    return __real_pthread_cond_init(c, a);
}
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *m) {
    if (take_fault(7, 0)) return EINVAL;
    return __real_pthread_mutex_lock(m);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n) {
    if (take_fault(8, 0)) { errno = ENOMEM; return NULL; }
    return __real_malloc(n);
}

static void cleanup(void *arg) {
    atomic_fetch_add(&routine_cleanups, 1);
    free(arg);
}
static void *worker(void *arg) {
    struct payload *p = arg;
    pthread_cleanup_push(cleanup, arg);
    atomic_store(&routine_entered, 1);
    assert(sem_post(&entered) == 0);
    wait_sem(&release_worker); /* Real cancellation point. */
    atomic_store(&seen_value, p->value); /* Reveals premature caller free. */
    pthread_cleanup_pop(1);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    char *end = NULL;
    long selected = strtol(argv[1], &end, 10);
    if (!end || *end || selected < 0 || selected > 8) return 64;
    mode = (int)selected;
    parent_thread = pthread_self();
    warnp_setprogname("flint-spiped-443-fault");
    assert(sem_init(&entered, 0, 0) == 0);
    assert(sem_init(&release_worker, 0, 0) == 0);
    struct payload *p = malloc(sizeof(*p));
    assert(p != NULL);
    p->value = 1729;
    pthread_t thread;
    armed = 1;
    int rc = pthread_create_blocking_np(&thread, NULL, worker, p);
    armed = 0;
    fprintf(stderr, "mode=%d helper_rc=%d injected=%d routine_entered=%d cleanups=%d\n",
            mode, rc, atomic_load(&injected), atomic_load(&routine_entered),
            atomic_load(&routine_cleanups));
    if (mode) assert(atomic_load(&injected) == 1);
    if (mode >= 4) {
        const int expected[] = {EAGAIN, ENOMEM, ENOMEM, EINVAL, ENOMEM};
        assert(rc == expected[mode-4]);
        assert(atomic_load(&routine_entered) == 0);
        assert(atomic_load(&routine_cleanups) == 0);
        assert(p->value == 1729);
        free(p); /* Correct caller ownership when no thread has started. */
    } else {
        if (rc != 0) {
            fprintf(stderr, "caller frees payload after helper failure\n");
            free(p); /* Same ownership decision as pushbits' error path. */
        }
        assert(sem_post(&release_worker) == 0);
        assert(pthread_join(thread, NULL) == 0);
        assert(rc == 0);
        assert(atomic_load(&routine_entered) == 1);
        assert(atomic_load(&routine_cleanups) == 1);
        assert(atomic_load(&seen_value) == 1729);
    }
    assert(sem_destroy(&entered) == 0);
    assert(sem_destroy(&release_worker) == 0);
    fprintf(stderr, "PASS mode=%d ownership and cleanup exact\n", mode);
    return 0;
}

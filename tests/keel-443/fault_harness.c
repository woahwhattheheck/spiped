/* KEEL regression harness for Tarsnap/spiped PR #443.
 * Isolated fault injection only: no networking, daemon, or production state.
 * The actual source is compiled unchanged against real pthreads and warnp.c.
 */
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "pthread_create_blocking_np.h"
#include "warnp.h"

static pthread_t parent_thread;
static atomic_int worker_started;
static atomic_int worker_release;
static atomic_int worker_freed;
static atomic_int worker_observed;
static int injected;
static int join_calls;
static const char *scenario;

struct payload { int value; };

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __real_pthread_cond_destroy(pthread_cond_t *);
int __real_pthread_mutex_destroy(pthread_mutex_t *);
int __real_pthread_join(pthread_t, void **);

static void pause_briefly(void)
{
    struct timespec delay = {0, 1000000};
    (void)nanosleep(&delay, NULL);
}

static int in_parent(void)
{
    return pthread_equal(pthread_self(), parent_thread);
}

static int inject_here(const char *point)
{
    if (!in_parent() || injected || strcmp(scenario, point))
        return 0;
    /* Demonstrate that ownership is already with the user routine before
     * returning the synthetic cleanup failure to the parent. */
    for (int i = 0; i < 2000; i++) {
        if (atomic_load(&worker_started)) {
            injected = 1;
            fprintf(stderr, "INJECT %s after worker_started=1\n", point);
            return 1;
        }
        pause_briefly();
    }
    fprintf(stderr, "HARNESS ERROR: worker did not start before injection\n");
    exit(90);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*routine)(void *), void *arg)
{
    if (in_parent() && !strcmp(scenario, "create")) {
        injected = 1;
        fprintf(stderr, "INJECT create before worker startup\n");
        return EAGAIN;
    }
    return __real_pthread_create(thread, attr, routine, arg);
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    if (inject_here("unlock"))
        return EPERM; /* Model failed unlock: leave the mutex locked. */
    return __real_pthread_mutex_unlock(mutex);
}

int __wrap_pthread_cond_destroy(pthread_cond_t *cond)
{
    if (inject_here("cond"))
        return EBUSY;
    return __real_pthread_cond_destroy(cond);
}

int __wrap_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    if (inject_here("mutex"))
        return EBUSY;
    return __real_pthread_mutex_destroy(mutex);
}

int __wrap_pthread_join(pthread_t thread, void **result)
{
    if (in_parent())
        join_calls++;
    return __real_pthread_join(thread, result);
}

static void cleanup_payload(void *arg)
{
    free(arg);
    atomic_fetch_add(&worker_freed, 1);
}

static void *worker(void *arg)
{
    struct payload *p = arg;
    pthread_cleanup_push(cleanup_payload, p);
    atomic_store(&worker_started, 1);
    while (!atomic_load(&worker_release))
        pause_briefly(); /* Cancellation point for the original err4 path. */
    atomic_store(&worker_observed, p->value);
    pthread_cleanup_pop(1);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    struct payload *p;
    int rc;

    if (argc != 2 || (strcmp(argv[1], "normal") && strcmp(argv[1], "create") &&
        strcmp(argv[1], "unlock") && strcmp(argv[1], "cond") && strcmp(argv[1], "mutex")))
        return 64;
    scenario = argv[1];
    parent_thread = pthread_self();
    warnp_setprogname("keel-spiped-443");
    if ((p = malloc(sizeof(*p))) == NULL)
        return 70;
    p->value = 443;
    rc = pthread_create_blocking_np(&thread, NULL, worker, p);
    fprintf(stderr, "RETURN rc=%d started=%d worker_freed=%d joins=%d\n",
        rc, atomic_load(&worker_started), atomic_load(&worker_freed), join_calls);

    if (rc != 0) {
        /* The caller's documented ownership rule: free arg on failure.
         * Baseline unlock injection reaches a second free here. */
        free(p);
        if (!strcmp(scenario, "create")) {
            if (rc != EAGAIN || atomic_load(&worker_started) || join_calls || !injected)
                return 71;
            puts("PASS early creation failure: caller owns and frees payload");
            return 0;
        }
        atomic_store(&worker_release, 1);
        /* The original unlock path already joins; other cleanup failures
         * leave the worker live, exposing its now-invalid payload read. */
        if (!join_calls && pthread_join(thread, NULL))
            return 72;
        return 73; /* No successful completion is expected after that error. */
    }

    atomic_store(&worker_release, 1);
    if (pthread_join(thread, NULL))
        return 74;
    if (atomic_load(&worker_observed) != 443 || atomic_load(&worker_freed) != 1)
        return 75;
    if (strcmp(scenario, "normal") && !injected)
        return 76;
    printf("PASS %s: worker owns payload; one worker free; value=%d\n",
        scenario, atomic_load(&worker_observed));
    return 0;
}

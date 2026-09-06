# FLINT: source-pinned pthread lifetime validation

Independent validation for Tarsnap/spiped PR #443, by an LLM (FLINT) working
on Bryce's behalf. Original A retains the report, implementation branch and
maintainer communication. This review branch adds tests only, not another fix
or upstream submission.

## Source and execution

Original commit: `a945f3315e35ee48c8a79af952addc1b6616db83`.
Submitted fix: `e20e9a36070b31c5832bd342a5c98b0b1cf3bf4c`.
Helper blobs: original `83490fc3caec62765e2e512ce7a6f3287b6a80d5`;
patched `5571d783e33e8342d4880725858ad4f49d40e337`.

The runner verifies both helpers and all nine dependency files against Git
blob hashes. It uses real pthreads, allocation, logging, clocks and the
unchanged upstream basic/timing tests. It creates a fresh temporary directory;
it never changes the checkout, starts a daemon, opens sockets, accesses
credentials, fetches source or changes CI settings.

From a checkout containing the two pinned commits and these three files:

```sh
python3 tests/flint_pthread_lifetime/run.py
```

Use `--repo /path/to/spiped` to choose a different checkout. The selected Git
objects must already be present. `--output-parent` selects an existing parent
for a NEW unique results directory. `--cc` takes one compiler executable, not
a shell command. Requirements: Python 3.9+, Linux pthreads/semaphores, a C
compiler with AddressSanitizer and UndefinedBehaviorSanitizer, and GNU-style
linker `--wrap` support.

`--materialized DIR` is an alternative for the hash-checked evidence layout
recorded in `run.py`; it does not relax source checks. That mode was executed
on the delivered runner in the isolated local environment. The default
`git show` loading route could not be exercised there because the environment
has no networked checkout. Both routes require exactly the same file bytes.

## Measured results

Environment: x86_64 Linux, Debian GCC 14.2.0, glibc 2.41.
Both variants compiled with `-Wall -Wextra -Werror`, pthreads and
`-fsanitize=address,undefined`, with leak detection enabled.

The unchanged native test passed on BOTH variants: one basic case and all
16 timing combinations per run, with no sanitizer findings.

The fault-injection matrix met **18 of 18 expectations**. The patched version
passed all nine modes; the original passed the normal and five pre-start
controls, and reproduced the three expected lifetime errors:

| Mode | Injected parent-side error | Original result | Patched result |
| --- | --- | --- | --- |
| 0 | None | Correct ownership | Correct ownership |
| 1 | Post-start mutex unlock: EPERM | ASan double-free | Success; worker frees once |
| 2 | Post-start condition destroy: EBUSY | ASan heap-use-after-free | Success; worker frees once |
| 3 | Post-start mutex destroy: EBUSY | ASan heap-use-after-free | Success; worker frees once |
| 4 | Thread creation: EAGAIN | Caller retains payload | Caller retains payload |
| 5 | Mutex initialization: ENOMEM | Caller retains payload | Caller retains payload |
| 6 | Condition initialization: ENOMEM | Caller retains payload | Caller retains payload |
| 7 | Pre-start parent lock: EINVAL | Caller retains payload | Caller retains payload |
| 8 | Helper allocation: ENOMEM | Caller retains payload | Caller retains payload |

GNU linker wrappers inject one selected error only. A semaphore ensures the
callback has installed cleanup and owns its argument before a post-start
error reaches the parent. Normal calls use real libc. The harness applies the
same caller ownership decision as pushbits' failure path; it does not replace
or run the daemon's pushbits implementation.

## Limits

The three pthread errors are deliberately injected. This does NOT establish
that they arise naturally on valid glibc synchronization objects, nor does it
prove remote exploitability. The uncertain `err5` / condition-wait case is
not changed or tested by this patch validation. Success with ASan leak
detection is not proof of portable internal pthread-resource cleanup on
injected impossible states.

This is an executed native unit target and a bounded fault-injection test,
not a full daemon build, full `make test`, upstream acceptance or payment.
No production files or existing tests are changed by this review branch.

Coordination and detailed result handoff:
https://tokenjunkielabs.slack.com/archives/C0BVANHNB26/p1788737516541369

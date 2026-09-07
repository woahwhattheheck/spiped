# MICA — independent validation of Tarsnap/spiped PR #439

Status: completed review-only validation of D's submitted patch. No original branch edits, duplicate upstream report, security-impact determination, award or payment claim.

## Exact revisions and execution

- Base: `a945f3315e35ee48c8a79af952addc1b6616db83`.
- Submitted head: `955aefcb5df089cf6d14ae6a5f2333e08a5634f7`, branch `dnsthread-register-before-signal`.
- Tested review/harness commit: `3625ca370717a8ee051b05e73a75d1d3616e15f4`.
- `lib/dnsthread/dnsthread.c` blobs: base `1733b6f88dd5ebb556f3a62dcb187a738c65c64d`, head `1368147a45cd91628855aa46a4b3c032ffd297b0`.

Both complete spipe/spiped applications and supporting libraries built with `make -j2 CC=gcc CFLAGS='-O2 -g'`. The observer includes the exact, unchanged `dnsthread.c` translation unit and links each revision's real supporting libraries. Both observer builds passed `-std=c11 -O2 -g -Wall -Wextra -Werror` with empty compiler stderr. Both source trees passed tracked-source diff checks before and after execution.

Environment: Linux x86-64, Ubuntu 24.04/GCC 13.3.0, GNU Make 4.3, OpenSSL 3.0.13.

Successful run: https://github.com/woahwhattheheck/spiped/actions/runs/34070117782

Job: `101585780502`, completed/success.

## Results

**64/64 expected before/after outcomes matched; no failed expectations.** There are 32 cases against each revision: four initial modes (normal, strdup failure, event-registration failure, condition-signal failure), two resolver outcomes, two callback return codes, and one or three completed-resolution rounds.

The actual worker thread, pthread mutex/condition variable, AF_UNIX wakeup socketpair, event registration/cancellation and `events_run()` dispatch all execute. The observer never substitutes a modeled worker or event loop. Only synthetic resolver results and selected failure points are injected; no external DNS or network service is contacted.

### Registration failure

All eight original-revision registration-failure cases show `strdup -> signal -> registration failure`, `THREAD_HASWORK` immediately before unlock, no listener, and a retained address. The immediate retry returns the API's existing `0` plus `errno=EALREADY`, without accepting new work. The real worker then finishes once and leaves a completion byte with no registered callback. No user callback runs. In successful synthetic-resolution cases, the result allocation is retained too.

The submitted head shows `strdup -> registration failure -> free`, remains `THREAD_SLEEPING`, never signals the failed request, and retains no address. The same resolver accepts the retry, delivers its correct callback, and also completes additional rounds when requested.

### Condition-signal failure

All eight original-revision cases show `strdup -> failed signal`, no listener, a retained address and `THREAD_HASWORK`; the immediate retry reports the existing EALREADY convention and accepts no new request.

All eight submitted-head cases show `strdup -> register -> failed signal -> cancel -> free`. The state is restored to sleeping, the real event registration is canceled once, and the same worker accepts subsequent requests. The retry is not rejected as either EALREADY or duplicate event registration.

The checker intentionally does not claim that a failed signal universally prevents worker execution: POSIX condition variables permit spurious wakeups. The measured proof is the incorrect old state/ownership and rejected reuse, versus the repaired rollback. In this run the old signal-failure worker performed no resolutions.

### Controls and callback ownership

Normal work and strdup-failure recovery behave correctly on both revisions. A concurrent second request while the first is deliberately held in the resolver does not replace the first callback or cookie. All delivered callback IDs are exactly those belonging to accepted requests, in order. Synthetic resolution failures deliver `EHOSTUNREACH`; callbacks returning 7 propagate 7 through the real `events_run()` call. Successful synthetic resolutions return a valid empty, NULL-terminated result vector, which the callback frees.

The head completes 64 resolution callbacks across its 32 cases; all 80 tracked address allocations, including the 16 rejected-request allocations, are freed by production paths. It leaves no tracked address or synthetic result allocation for harness cleanup. The base completes 32 callbacks, leaves 16 addresses and four successful orphan-result allocations, and produces eight orphan completion bytes. These are observations of the tracked ownership paths, not whole-process leak certification.

All 64 test-created worker threads were joined. Original-revision leaks were recorded before the harness explicitly freed them after joining the worker. The observer separately counts these manual cleanup frees; they are never credited to the original implementation. The orphan byte is inspected/drained by the harness solely for safe teardown, not by a fictitious user callback.

## Evidence and reproduction

Artifact: https://github.com/woahwhattheheck/spiped/actions/runs/34070117782/artifacts/10000177507

Downloaded 14-file ZIP, 161853 bytes, integrity-tested and independently SHA-256 checked:

`1f985142f993cc4fa62c15ad02a1cc25eb7912eee2dc46c84f7c652b3b30e840`

The archive includes both observer executables, exact harness sources, all 64 structured traces, complete application build logs, compile commands, source/library/binary hashes, and an empty failures list. GitHub retention expires September 21, 2026 UTC; the source recipe and this report remain in Git.

Harness source SHA-256: `752391a4f742a4e377c5fe61e671968ce4fce3d451c6489a7c3bf2f0a39d4de9`.

With pinned, normally built checkouts in `sources/base` and `sources/head`:

```sh
python3 tests/mica-439/run.py sources results
```

The complete public-fetch/build sequence is in `.github/workflows/mica-439-validation.yml` at tested review commit `3625ca370717a8ee051b05e73a75d1d3616e15f4`. It uses no repository permissions or credentials, explicit timeouts, and a fail-closed pipeline.

## Limits and ownership

This validates the exact rollback/reuse paths under deterministic injection on Linux/GCC. It does not provoke the later stale-completion use-after-free described by the upstream report, contact external DNS, demonstrate naturally occurring pthread failures, prove every scheduler interleaving, certify a full native suite, run sanitizers, or establish cross-platform guarantees or exploitability.

D retains the implementation, upstream report and sponsor relationship. A's new spiped audit and other helpers' lanes were not touched. The completed #426 and #437 matrices were not rerun for this review.

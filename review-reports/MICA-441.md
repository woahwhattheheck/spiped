# MICA — independent validation of Tarsnap/spiped PR #441

Completed review-only validation by MICA, a ChatGPT/LLM session acting for the account owner. D retains the original implementation, upstream report and sponsor relationship. No duplicate upstream issue or PR was submitted.

## Exact source and execution

- Base: `a945f3315e35ee48c8a79af952addc1b6616db83`.
- Submitted head: `a04c2614978098ffd33012e9353fac8a0b025e31`, branch `proto-handshake-clear-cookie`.
- Tested review/harness commit: `945226dc41d2f07134f3b048fa948c22ec059c2a`.
- `lib/proto/proto_handshake.c` blobs: base `e67a8b5bdd3667a20402639ef109d15a100942b7`, head `0f1bd101c37240680191ebd0576f94c4bde4a216`.

Both complete spipe/spiped applications and their supporting libraries built using `make -j2 CC=gcc CFLAGS='-O2 -g'`. Each observer includes the exact unchanged handshake translation unit and links that revision's actual networking, cryptography and zeroing implementations. Both observers compiled with `-std=c99 -O2 -g -Wall -Wextra -Werror`, empty compiler stderr, and tracked-source diff checks before and after execution.

Linux x86-64 / Ubuntu 24.04, GCC 13.3.0, GNU Make 4.3, OpenSSL 3.0.13.

Successful run: https://github.com/woahwhattheheck/spiped/actions/runs/34070526012

Job `101586898017`, completed/success.

## Results

**84/84 expected before/after scenarios matched; no failed expectations.** There are 42 scenarios per revision, not 84 newly discovered bugs.

Real AF_UNIX socketpairs and the actual event loop complete both PFS and weak handshakes. Other cases exercise mismatched shared secrets, required-PFS rejection, initial allocation/entropy/read/write failure, cancellation before nonce progress and after DHMAC derivation, EOF during nonce/DH exchange, and injected final-key-construction failure. Single-ended cases cover both client and server roles. Callback-return controls use 0 and 7.

All four freeing paths execute:

| Actual freeing path | Cookies freed per revision | Head cookies completely cleared |
| --- | ---: | ---: |
| `handshakedone()` success | 8 | 8 |
| `handshakefail()` | 20 | 20 |
| `proto_handshake()` initial `err1` cleanup | 12 | 12 |
| `proto_handshake_cancel()` | 8 | 8 |
| **Total** | **48** | **48** |

The observed cookie size is 792 bytes. The original revision performs zero cookie wipes and retains nonzero bytes immediately before each of its 48 frees. The submitted head calls the real zeroing function exactly once per freed cookie; all 792 bytes are zero after that call and still zero immediately before free.

The observer independently records 14 cookies with an actually generated DH private value and 28 with actually derived DHMAC values per revision. Those values contain nonzero bytes before the head clears their cookie. Other bytes, particularly early-exit fields, are known test initialization and are not presented as evidence of production secrets.

### Cancellation and callback ordering

Every head wipe occurs after its pending network operations have completed or been canceled. Initial cancellation cancels both the real read and write; initial read-registration failure unwinds the already registered write. DH-stage cancellation cancels the outstanding real network operation. The quiet-event-loop controls see no callback after cancellation or initial failure.

Success and failure callbacks execute before cookie clearing/freeing; cancellation and initial failure invoke no user callback. Every created cookie is freed exactly once. No test reads cookie memory after free, and no observation relies on allocator reuse or recovery of freed memory.

### Retained keys remain functional

After both successful cookies have been cleared/freed, the callback-owned encryption keys remain available. The replay encrypts/decrypts known packets of lengths 1, 31, 32, 1023 and 1024 in both directions. All packet contents match byte-for-byte. A deliberately corrupted authentication tag is rejected before the corresponding unmodified packet is accepted, keeping sequence-number state aligned.

Across both revisions there are **80 successful packet round trips and 80 corrupted-packet rejection controls**. This includes both PFS and weak-handshake modes and the nonzero callback-status controls. It verifies functional key handoff in this replay, not the general security of the cryptographic construction.

## Instrumentation boundaries

The exact handshake functions, asynchronous network operations/cancellation, event loop, cryptographic routines, and real `insecure_memzero` implementation execute. Network completion wrappers record lifetime state and then invoke the original callback. The real zeroing function is called through the saved exported function-pointer seam; it is not replaced by a modeled wipe.

New cookie allocations are filled with a known 0xa5 test pattern before the production initializer runs. This is necessary for defined, complete-byte observations on early-exit paths. It is not a claim that those early-exit bytes contain a private key in production. Real ephemeral private values are counted only after the actual generating routine succeeds. Synthetic shared-secret fixtures are public test strings; no user keys, credentials, external services or production files are involved.

## Replay and evidence

Artifact: https://github.com/woahwhattheheck/spiped/actions/runs/34070526012/artifacts/10000300772

Downloaded and ZIP-integrity/SHA-256 verified: 16 files, 365604 bytes.

ZIP SHA-256: `bb1dfd212c090bc9d89b85802712cf479e7d53413981a460e43d2f113b11ea41`.

Observer source SHA-256: `16f6206b5e67f4df650143d71fb93648c8a946dd0c782ef1e7682e3a22398a33`.

The archive contains complete build logs, compile commands, exact harness sources, both observer executables, source/library/binary hashes, all 84 structured traces and an empty failures list. GitHub artifact retention expires September 21, 2026 UTC; the recipe and this report remain in Git.

With the pinned revisions normally built under `sources/base` and `sources/head`:

```sh
python3 tests/mica-441/run.py sources results
```

The full bounded, credential-free build/replay sequence is in `.github/workflows/mica-441-validation.yml` at review commit `945226dc41d2f07134f3b048fa948c22ec059c2a`.

## Limits and ownership

This is focused Linux/GCC exact-source validation with explicit failure injection and test initialization. It is not a full native suite, sanitizer run, cross-platform guarantee, freed-memory exploit, proof that every register/spill copy is erased, or bounty-impact/security certification. The original implementation branch was not modified. D's upstream/reporting ownership, A's new spiped scope, and other helpers' lanes remain untouched. No award, acceptance, merge or payment is claimed.

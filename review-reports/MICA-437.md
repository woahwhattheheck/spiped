# MICA — independent validation of Tarsnap/spiped PR #437

Status: completed review-only validation. The submitted implementation branch is unchanged. This is not a new upstream report, security-impact determination, award claim, or payment receipt.

## Source and execution

- Original base: `a945f3315e35ee48c8a79af952addc1b6616db83`.
- Submitted head: `92f0f726b827231d31108e59cd24dcf9fe6c5a71` (`proto-crypt-clear-stack`).
- Tested review harness commit: `128322204e0b78fe3857316cb9d36606d031c829`.
- Original/updated `lib/proto/proto_crypt.c` blobs: `c8bfac2ca95299f74196896f31ef6ed23f9ee67f` / `ae80f668890b905c9f44282b2eb332a933d98630`.
- Unchanged real zeroing implementation blob: `bd26bac4314e950941bf0ef7df3b50c4927a43e8`.

Both complete `spipe`/`spiped` applications and their actual `liball.a` archives built with `make -j2 CC=gcc CFLAGS='-O2 -g'` on Linux x86-64, GCC 13.3.0, GNU Make 4.3, OpenSSL 3.0.13. Both isolated source trees passed `git diff --exit-code` before and after the replay.

Successful workflow: https://github.com/woahwhattheheck/spiped/actions/runs/34069627669

## Measured outcomes

**104/104 expected outcomes passed; no failed expectations.** There are 52 cases against each revision, not 104 newly fixed defects.

| Observation across each revision's 52 cases | Original base | Submitted head |
| --- | ---: | ---: |
| Successful key reads / independent derived-key matches | 35 | 35 |
| Observed complete input-buffer wipes | 0 | 49 |
| Observed complete temporary DHMAC-key wipes | 0 | 35 |
| DHMAC outputs already copied at the wipe point | Not observed: no wipe call | 35 |
| Existing protocol-secret wipe/free paths preserved | 50 | 50 |

The key-read matrix covers file and stdin inputs of 0, 1, 31, 32, 8191, 8192, 8193 and 16415 bytes, with both client/server directions. Read-error injection occurs after 0, 1, 31, 8191, 8192, 8193 and 16401 bytes for file and stdin. Additional controls cover close-error returns, open failure and initial allocation failure. The runtime reports `BUFSIZ=8192`; the replay uses the observed value rather than assuming it.

For an 8193-byte key file, the updated code reaches the wipe hook with 8192 known-initialized nonzero synthetic bytes in its input buffer and returns from the real zeroing routine with every byte of that buffer zero. The same result holds for a stdin read error injected after 8193 bytes. The original code invokes no targeted input-buffer wipe in either case.

All 70 successful calls across the two revisions produce the exact local/remote keys expected from Python's independent SHA-256 plus PBKDF2-HMAC-SHA256 calculation. In each of the updated revision's 35 DHMAC calls, the output arrays already contain the expected copied keys when the temporary key buffer is erased. Thus this replay verifies both named-buffer clearing and functional output preservation.

## What the observer does

`tests/mica-437/observe.c` links the real, normally compiled `liball.a`; it does not replace `proto_crypt_secret` or `proto_crypt_dhmac` with modeled functions. GNU linker wrappers provide deterministic I/O/allocation failure points and record the output pointer of the real PBKDF2 implementation. Normal reads still consume actual generated files or stdin.

The observer temporarily interposes at the project's exported `insecure_memzero_ptr` function-pointer seam. It saves and calls the real zeroing routine, then verifies bytes while the caller's buffer is still alive. Before zeroing it inspects only bytes initialized by a preceding read, so empty and early-failure paths do not require reading uninitialized stack bytes. No stack buffer is inspected after its function returns.

A base-row `buffer_bad_after=0` means that no failed observed wipe was counted; it does **not** mean the base buffer was zeroed. The base has zero targeted wipe events. This distinction is preserved in the event counts above.

## Reproduce and inspect

Source recipe: `tests/mica-437/run.py` and `tests/mica-437/observe.c` at tested harness commit `128322204e0b78fe3857316cb9d36606d031c829`. With both pinned revisions built in `sources/base` and `sources/head`, execute:

```sh
python3 tests/mica-437/run.py sources results
```

The bounded workflow `.github/workflows/mica-437-validation.yml` includes the complete credential-free public-fetch/build sequence and a fail-closed replay pipeline.

66-file evidence archive: https://github.com/woahwhattheheck/spiped/actions/runs/34069627669/artifacts/10000025683

Downloaded and independently hash-checked ZIP SHA-256: `915ddf90f8789c3debe077428a70667442d05be26c62ebe390acc9d97811b261`.

The archive contains the full case matrix, empty failures list, exact harness sources, source/library/binary manifests, complete build logs and observer executables. Its GitHub retention expires September 21, 2026 UTC; the replay sources and this report remain in Git.

Observer source SHA-256: `bbf2def94055f2c4103221a81f21dc7e9237906a68f080ff359cc3ae46368ba1`. The downloaded observer source matched the authored source byte-for-byte.

## Limits and ownership

This is Linux/GCC optimized-library validation with explicit test hooks and synthetic keys. It is not a live-network test, post-return memory-recovery demonstration, full native suite, sanitizer/Valgrind run, or cross-platform guarantee. Erasing named buffers does not prove that every register copy or compiler-generated stack spill is erased.

D retains the submitted implementation, upstream reporting and sponsor relationship. A's new spiped audit scope and KEEL/FLINT's #443/#445 work were not touched. No shared checkout or original implementation branch was edited, and no duplicate upstream comment or PR was opened.

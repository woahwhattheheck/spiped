# MICA — completed delivery index, September 6 session

MICA is a ChatGPT/LLM review session acting on the repository owner's instruction to participate in Slack coordination and bug-bounty work. This index consolidates completed work, not an autonomous monitoring service. Every scope was claimed and released in the existing D bounty thread. Original implementation branches, upstream reporting and sponsor ownership remain D's; A's new spiped audit and other helpers' scopes were not changed.

## Delivery summary

| Existing upstream PR | Completed work | Integration status |
| --- | --- | --- |
| Tarsnap/scrypt #426 | 1,084 real before/after CLI cases plus the submitted native scenario against both builds. Separately repaired a native-test coverage gap and mutation-tested it with 10 expected scenario outcomes. | Small test-only fork PR [woahwhattheheck/scrypt#3](https://github.com/woahwhattheheck/scrypt/pull/3), open/unmerged on readback; no production code changes. |
| Tarsnap/spiped #437 | 104 expected before/after key-read/DHMAC outcomes, actual compiled libraries and real zeroing, independent derived-key oracle. | [Sealed report](https://github.com/woahwhattheheck/spiped/blob/315c2f3b49ed8090b5fa2452a06152b751839497/review-reports/MICA-437.md); no implementation edits. |
| Tarsnap/spiped #439 | 64 expected before/after rollback/reuse outcomes, real worker, pthread synchronization, AF_UNIX wakeup sockets and event loop. | [Sealed report](https://github.com/woahwhattheheck/spiped/blob/c5a56168caee2de2eeb43b8a65ce78bf05fc50fe/review-reports/MICA-439.md); no implementation edits. |
| Tarsnap/spiped #441 | 84 expected before/after handshake lifetime scenarios, real local handshakes and retained-key packet controls. | [Sealed report](https://github.com/woahwhattheheck/spiped/blob/f79d4823056daf91b7b6c71693a13d5f0ca16351/review-reports/MICA-441.md); no implementation edits. |

These counts are replay cases/scenarios, not counts of newly discovered bugs or universal security guarantees. Deliberately failing original-revision and mutation cases count as expected outcomes when the checker observes the predicted regression.

## The concrete test repair

The original scrypt scenario 11 checked invalid header handling but missed three independently reintroduced arithmetic bugs: the 32-bit memory intermediate, the 64-bit memory product, and the integer CPU-estimate product. The expanded native scenario detects all three and passes both unmodified controls.

Only `tests/11-info.sh` changes, +78/-0. The original six checks remain, with eight new checks. No Python runtime dependency, workflow or production implementation change is included in the small PR.

- Implementation tested: `294338c5853f039630bd1a5d6e0c87ccd4692fff`.
- Test-only candidate: `7a18e0ccb77e19271ceb4a5cba76a14ee5fd8d81`.
- Exact test blob: `e6d22dd678eb23b782501a5a37c2e27521cdb6ee`.
- Target branch: `scrypt-info-header-validation`.

Take the small fork PR or the standalone patch from its artifact for integration. The large review branches are replay tooling, not proposed upstream production changes. LLM disclosure and session-bound review availability are explicit in the fork PR description.

## Key measured findings

**scrypt #426:** The base emits 194 UBSan invalid-shift diagnostics; the submitted head emits none in the matrix. A wide-r header's memory estimate changes from 0 B to 8.5 GB; an enormous N case changes from 0 B to a saturated lower bound of 18 EB. Safe resource-limited verbose decryption no longer displays a wrapped zero CPU estimate. Header info is not password/payload authentication. The program clamps the requested one-byte memory limit to its minimum; no huge key derivation is performed.

**spiped #437:** Input-buffer wipe observations change 0 to 49 and temporary DHMAC-buffer wipes 0 to 35. Every updated DHMAC observation confirms the output keys were copied before the temporary key buffer was erased. All 70 successful derivations across both revisions match the independent SHA-256/PBKDF2 oracle. Only live, initialized bytes are examined; no post-return stack reads.

**spiped #439:** All eight base registration-failure cases leave real orphan completion bytes with no callback listener. The head refuses to start the failed request, cleans its address, and accepts reuse. All eight head signal-failure cases restore the sleeping state, cancel the real listener and free the address. Head: 64 callbacks, all 80 tracked address allocations freed. Base: 16 stranded addresses and four successful orphan result vectors, counted before separate safe harness cleanup. All 64 test-created worker threads were joined. The later stale-completion UAF was not provoked.

**spiped #441:** All four freeing sites execute. Of 48 freed 792-byte cookies per revision, the base clears none and the head clears all 48 completely before free. Pending network operations are finished/canceled first. Real private values and derived MAC material are distinguished from known early-exit test initialization. After successful cookie teardown, the retained keys complete 80 packet round trips and reject 80 corrupted-packet controls across both revisions.

## Runs and preserved evidence

All five runs completed successfully, each with an empty failed-expectations list. Every archive was downloaded, ZIP-integrity tested and independently SHA-256 verified.

| Scope | GitHub Actions run | Artifact |
| --- | --- | --- |
| #426 CLI/UBSan | [34068701474](https://github.com/woahwhattheheck/scrypt/actions/runs/34068701474) | [9999775521](https://github.com/woahwhattheheck/scrypt/actions/runs/34068701474/artifacts/9999775521) |
| #426 native coverage | [34069090993](https://github.com/woahwhattheheck/scrypt/actions/runs/34069090993) | [9999876296](https://github.com/woahwhattheheck/scrypt/actions/runs/34069090993/artifacts/9999876296) |
| #437 | [34069627669](https://github.com/woahwhattheheck/spiped/actions/runs/34069627669) | [10000025683](https://github.com/woahwhattheheck/spiped/actions/runs/34069627669/artifacts/10000025683) |
| #439 | [34070117782](https://github.com/woahwhattheheck/spiped/actions/runs/34070117782) | [10000177507](https://github.com/woahwhattheheck/spiped/actions/runs/34070117782/artifacts/10000177507) |
| #441 | [34070526012](https://github.com/woahwhattheheck/spiped/actions/runs/34070526012) | [10000300772](https://github.com/woahwhattheheck/spiped/actions/runs/34070526012/artifacts/10000300772) |

Archive SHA-256 values, in the same order:

```text
844caada0e6f99fba196ccbb510bcafff581f7a1a3c046c4b7cc80541cfb6369  mica-426-header-validation.zip
08e153350e63546d4cb12746422c15a9944e36fe029c75a51ba135d1b568b447  mica-426-native-coverage.zip
915ddf90f8789c3debe077428a70667442d05be26c62ebe390acc9d97811b261  mica-437-stack-wipe-validation.zip
1f985142f993cc4fa62c15ad02a1cc25eb7912eee2dc46c84f7c652b3b30e840  mica-439-dns-rollback-validation.zip
bb1dfd212c090bc9d89b85802712cf479e7d53413981a460e43d2f113b11ea41  mica-441-handshake-cookie-validation.zip
```

GitHub artifact retention expires September 21, 2026 UTC. Replay sources and sealed reports remain in the Git branches; downloaded copies are included in the session's evidence bundle.

## Coordination receipts

- [#426 test handoff](https://tokenjunkielabs.slack.com/archives/C0BVANHNB26/p1788740103774879).
- [#437 completion](https://tokenjunkielabs.slack.com/archives/C0BVANHNB26/p1788740698427389).
- [#439 completion](https://tokenjunkielabs.slack.com/archives/C0BVANHNB26/p1788741236711989).
- [#441 completion](https://tokenjunkielabs.slack.com/archives/C0BVANHNB26/p1788741728505319).

All scopes are complete/released. No owner action was requested from Bryce. Any upstream test integration remains with the existing implementation owner.

## Limits

The local container could not fetch GitHub sources, so full builds ran in isolated, bounded GitHub Actions using public pinned source and no repository credentials or permissions. Downloaded evidence was inspected and hash-checked locally. Linux/GCC focused validation is not a full native-suite, Valgrind, sanitizer-for-every-scope, cross-platform, every-interleaving or exploitability certification. Synthetic data only; no production targets, secrets, customer records or sponsor contacts. No upstream merge, bounty acceptance, award or payment is claimed.

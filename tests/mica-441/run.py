#!/usr/bin/env python3
"""PR441 before/after local-handshake replay. Synthetic secrets only.

Usage: python3 run.py CHECKOUT_DIRECTORY OUTPUT_DIRECTORY
Requires base/ and head/ normally built at the exact revisions below.
"""
from __future__ import annotations
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys

REVISIONS = {'base': 'a945f3315e35ee48c8a79af952addc1b6616db83',
             'head': 'a04c2614978098ffd33012e9353fac8a0b025e31'}
PAIRS = ('success-pfs', 'success-weak', 'wrong-secret', 'pfs-reject', 'mkkeys-fail')
SINGLES = ('malloc-fail', 'entropy-fail', 'write-fail', 'read-fail',
           'cancel-start', 'cancel-dh', 'eof-nonce', 'eof-dh')
ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
HARNESS = Path(__file__).with_name('observe.c').resolve()
ENV = dict(os.environ, LC_ALL='C')
records, failures = [], []
manifest = {}
key_a, key_b = OUT/'synthetic-a.key', OUT/'synthetic-b.key'
key_a.write_bytes(b'MICA public synthetic handshake test key A\n')
key_b.write_bytes(b'MICA public synthetic handshake test key B\n')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(src: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(src), *args], text=True).strip()


def check(revision: str, mode: str, role: int, row: dict) -> list[str]:
    errors = []
    def expect(actual, wanted, label):
        if actual != wanted:
            errors.append(f'{label}: expected {wanted!r}, got {actual!r}')
    head = revision == 'head'
    pair = mode in PAIRS
    initial = mode in ('malloc-fail', 'entropy-fail', 'write-fail', 'read-fail')
    cancel = mode.startswith('cancel-')
    success = mode.startswith('success-')
    expected_callbacks = [1, 1] if pair else [int(not initial and not cancel), 0]
    expected_success = [int(success), int(success)]
    expect(row['callbacks'], expected_callbacks, 'callbacks')
    expect(row['success'], expected_success, 'success')
    expect(row['allocation_failures'], int(mode == 'malloc-fail'), 'allocation failure')
    expect(row['pending_operations'], 0, 'pending operations at exit')
    expect(row['packet_roundtrips'], 10 if success else 0, 'retained-key packet round trips')
    expect(row['corrupted_packets_rejected'], 10 if success else 0, 'corrupted packet controls')
    cookies = row['cookies']
    expect(len(cookies), 0 if mode == 'malloc-fail' else 2 if pair else 1, 'cookie count')
    reason = 'initial' if initial else 'cancel' if cancel else 'done' if success else 'fail'
    for i, cookie in enumerate(cookies):
        expect(cookie['side'], i, 'cookie side')
        expect(cookie['freed'], 1, f'cookie{i} free')
        expect(cookie['wipes'], int(head), f'cookie{i} wipe')
        expect(cookie['pending_at_free'], 0, f'cookie{i} pending before free')
        expect(cookie['callback_at_free'], expected_callbacks[i], f'cookie{i} callback before free')
        expect(cookie['reason'], reason, f'cookie{i} freeing path')
        if head:
            expect(cookie['nonzero_at_free'], 0, f'cookie{i} bytes at free')
            expect(cookie['after_wipe'], 0, f'cookie{i} bytes after real wipe')
            expect(cookie['pending_at_wipe'], 0, f'cookie{i} canceled operations before wipe')
            expect(cookie['callback_at_wipe'], expected_callbacks[i], f'cookie{i} callback before wipe')
            if cookie['before_wipe'] <= 0:
                errors.append(f'cookie{i}: missing initialized nonzero before-wipe control')
        elif cookie['nonzero_at_free'] <= 0:
            errors.append(f'cookie{i}: baseline unexpectedly cleared its cookie')
        if cookie['mac_derived'] and cookie['mac_nonzero_before_clear'] <= 0:
            errors.append(f'cookie{i}: no actual derived MAC material observed')
        if cookie['x_generated'] and cookie['x_nonzero_before_clear'] <= 0:
            errors.append(f'cookie{i}: no actual generated private value observed')
        if success or mode in ('cancel-dh', 'eof-dh'):
            expect(cookie['mac_derived'], 1, f'cookie{i} DHMAC stage reached')
        if mode == 'success-pfs' or (mode in ('cancel-dh', 'eof-dh') and role == 0):
            expect(cookie['x_generated'], 1, f'cookie{i} PFS private value generated')
        if mode == 'success-weak':
            expect(cookie['x_generated'], 0, f'cookie{i} no PFS value in weak control')
    if mode == 'cancel-start':
        expect(row['read_cancels'], 1, 'initial pending read canceled')
        expect(row['write_cancels'], 1, 'initial pending write canceled')
    if mode == 'read-fail':
        expect(row['read_cancels'], 0, 'failed read was not registered')
        expect(row['write_cancels'], 1, 'write unwound after initial read failure')
    if mode in ('entropy-fail', 'write-fail', 'malloc-fail'):
        expect(row['read_cancels'] + row['write_cancels'], 0, 'no pending operation to cancel')
    if mode == 'cancel-dh' and row['read_cancels'] + row['write_cancels'] < 1:
        errors.append('DH-stage cancellation did not cancel a pending operation')
    return errors

cases = [(mode, 0, cb) for mode, cb in itertools.product(PAIRS, (0, 7))]
cases += list(itertools.product(SINGLES, (0, 1), (0, 7)))
assert len(cases) == 42
for revision, expected in REVISIONS.items():
    src = ROOT/revision
    if git(src, 'rev-parse', 'HEAD') != expected:
        raise RuntimeError(f'{revision}: wrong source revision')
    subprocess.run(['git', '-C', str(src), 'diff', '--exit-code'], check=True)
    source = src/'lib/proto/proto_handshake.c'
    binary = OUT/('observe-'+revision)
    command = ['gcc', '-std=c99', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-D_POSIX_C_SOURCE=200809L', '-D_XOPEN_SOURCE=700',
               '-DMICA_HANDSHAKE_SOURCE="'+str(source)+'"']
    for path in ('lib/proto', 'libcperciva/events', 'libcperciva/network',
                 'libcperciva/util', 'libcperciva/crypto', 'libcperciva/alg'):
        command.append('-I'+str(src/path))
    command += [str(HARNESS), str(src/'liball/liball.a'),
                str(src/'liball/optional_mutex_pthread/liball_optional_mutex_pthread.a'),
                '-lcrypto', '-lpthread', '-o', str(binary)]
    for symbol in ('malloc', 'free', 'crypto_entropy_read', 'network_read', 'network_write',
                   'network_read_cancel', 'network_write_cancel', 'proto_crypt_dhmac',
                   'proto_crypt_dh_generate', 'proto_crypt_mkkeys'):
        command.append('-Wl,--wrap='+symbol)
    build = subprocess.run(command, capture_output=True, text=True, timeout=120, env=ENV)
    (OUT/('observer-build-'+revision+'.json')).write_text(json.dumps(
        {'command': command, 'returncode': build.returncode, 'stdout': build.stdout,
         'stderr': build.stderr}, indent=2)+'\n')
    if build.returncode:
        print(build.stderr, flush=True)
        raise RuntimeError(f'{revision}: observer build failed')
    manifest[revision] = {'commit': expected,
        'handshake_blob': git(src, 'rev-parse', 'HEAD:lib/proto/proto_handshake.c'),
        'handshake_sha256': sha256(source), 'observer_sha256': sha256(binary),
        'liball_sha256': sha256(src/'liball/liball.a'), 'spipe_sha256': sha256(src/'spipe/spipe'),
        'spiped_sha256': sha256(src/'spiped/spiped')}
    for mode, role, cb in cases:
        name = f'{mode}-role{role}-cb{cb}'
        result = subprocess.run([str(binary), mode, str(role), str(cb), str(key_a), str(key_b)],
                                capture_output=True, text=True, timeout=10, env=ENV)
        row = {'revision': revision, 'case': name, 'mode': mode, 'role': role,
               'callback_status': cb, 'returncode': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr}
        try:
            observed = json.loads(result.stdout) if result.returncode == 0 else None
        except json.JSONDecodeError:
            observed = None
        row['observed'] = observed
        problems = check(revision, mode, role, observed) if observed else ['Observer failed']
        row['expectation_passed'] = not problems
        records.append(row)
        if problems:
            failures.append({'revision': revision, 'case': name, 'errors': problems, 'row': row})
        print('CASE', json.dumps(row), flush=True)
    subprocess.run(['git', '-C', str(src), 'diff', '--exit-code'], check=True)
summary = {'cases': len(records), 'expected_outcomes_passed': sum(r['expectation_passed'] for r in records),
    'failed_expectations': len(failures), 'source': manifest,
    'observer_source_sha256': sha256(HARNESS),
    'totals': {revision: {field: sum(cookie[field] for r in records if r['revision']==revision and r['observed']
        for cookie in r['observed']['cookies']) for field in ('freed','wipes','x_generated','mac_derived')}
        for revision in REVISIONS},
    'limits': ['Linux/GCC exact-source observer with actual local handshake, event loop, crypto and zeroing routine',
        'Known test pattern initializes cookie allocations; early-exit nonzero bytes are not claimed to be production secrets',
        'Only synthetic shared secrets; no external service or memory access after free',
        'Selected failure points are injected, not naturally occurring production faults',
        'No full native suite, sanitizer, cross-platform, cryptographic security or bounty-impact certification']}
(OUT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'matrix.json').write_text(json.dumps(records, indent=2)+'\n')
(OUT/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
print('SUMMARY', json.dumps(summary), flush=True)
for failure in failures:
    print('FAIL', json.dumps(failure), flush=True)
raise SystemExit(1 if failures else 0)

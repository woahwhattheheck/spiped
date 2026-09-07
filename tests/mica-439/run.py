#!/usr/bin/env python3
"""Replay PR439 with real worker/event/socket execution and injected failures.

Usage: python3 run.py CHECKOUT_DIRECTORY OUTPUT_DIRECTORY
Requires normally built base/ and head/ checkouts at the exact revisions below.
No network resolver is contacted. Every subprocess is bounded and isolated.
"""
from __future__ import annotations
import errno
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys

REVISIONS = {'base': 'a945f3315e35ee48c8a79af952addc1b6616db83',
             'head': '955aefcb5df089cf6d14ae6a5f2333e08a5634f7'}
ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
HARNESS = Path(__file__).with_name('observe.c').resolve()
ENV = dict(os.environ, LC_ALL='C')
records, failures = [], []
manifest = {}


def git(src: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(src), *args], text=True).strip()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_case(revision: str, mode: int, dns_error: int, callback_rc: int,
                rounds: int, observed: dict) -> list[str]:
    errors = []
    def expect(actual, wanted, label: str):
        if actual != wanted:
            errors.append(f'{label}: expected {wanted!r}, got {actual!r}')
    def subset(actual: dict, wanted: dict, label: str):
        for key, value in wanted.items():
            expect(actual.get(key), value, label+'.'+key)
    is_head = revision == 'head'
    recovered = mode < 2 or is_head
    first_busy = mode == 0 or (not is_head and mode >= 2)
    first_trace = ('DRS' if is_head else 'DSR') if mode == 0 else 'D'
    if mode == 2: first_trace = 'DRF' if is_head else 'DSR'
    if mode == 3: first_trace = 'DRSCF' if is_head else 'DS'
    subset(observed['first'], {
        'rc': 0 if mode == 0 else -1,
        'state_before_unlock': int(first_busy),
        'listener_active': int(mode == 0),
        'addresses_live': int(first_busy),
        'register_calls': int(mode != 1 and not (mode == 3 and not is_head)),
        'signal_calls': int(mode != 1 and not (mode == 2 and is_head)),
        'trace': first_trace}, 'first')
    subset(observed['retry'], {
        'rc': 0, 'state_before_unlock': 1, 'listener_active': int(recovered),
        'addresses_live': 1, 'register_calls': int(not first_busy),
        'signal_calls': int(not first_busy),
        'trace': '' if first_busy else ('DRS' if is_head else 'DSR')}, 'retry')
    if first_busy:
        expect(observed['retry']['errno'], errno.EALREADY, 'busy errno')
    elif observed['retry']['errno'] == errno.EALREADY:
        errors.append('Retry incorrectly reported EALREADY')
    callbacks = observed['callbacks']
    expect(len(callbacks), rounds if recovered else 0, 'callback count')
    expected_ids = ([0 if mode == 0 else 1] + list(range(2, rounds+1))) if recovered else []
    expect([row['cookie_id'] for row in callbacks], expected_ids, 'callback ownership/order')
    for i, row in enumerate(callbacks):
        expect(row['nonnull_result'], 1-dns_error, f'callback{i} result')
        expect(row['event_return'], callback_rc, f'callback{i} status propagation')
        if dns_error:
            expect(row['errno'], errno.EHOSTUNREACH, f'callback{i} DNS errno')
    expect(observed['cancellations'], int(is_head and mode == 3), 'rollback cancellation')
    expect(observed['orphan_byte'], int(not is_head and mode == 2), 'orphan completion byte')
    expect(observed['orphan_state'], 0 if not is_head and mode == 2 else -1, 'orphan worker state')
    if recovered:
        allocated = rounds + int(mode >= 2)
        subset(observed, {'resolver_calls': rounds, 'address_allocations': allocated,
            'production_address_frees': allocated, 'addresses_live_before_manual_cleanup': 0,
            'results_live_before_manual_cleanup': 0, 'production_result_frees': rounds*(1-dns_error),
            'manual_address_frees': 0, 'manual_result_frees': 0, 'joins': 1}, 'totals')
    else:
        subset(observed, {'address_allocations': 1, 'production_address_frees': 0,
            'addresses_live_before_manual_cleanup': 1, 'manual_address_frees': 1,
            'production_result_frees': 0, 'joins': 1}, 'totals')
        if mode == 2:
            subset(observed, {'resolver_calls': 1,
                'results_live_before_manual_cleanup': 1-dns_error,
                'manual_result_frees': 1-dns_error}, 'orphan')
        else:
            # POSIX permits spurious condition-variable wakeups. The proof
            # here is the stuck HASWORK state and rejected reuse, not a
            # universal assertion that failed signal means no worker ran.
            if observed['resolver_calls'] not in (0, 1):
                errors.append('Unexpected work count after failed signal')
            remaining = observed['resolver_calls']*(1-dns_error)
            expect(observed['results_live_before_manual_cleanup'], remaining, 'signal-failure results')
            expect(observed['manual_result_frees'], remaining, 'signal-failure cleanup')
    return errors

for revision, commit in REVISIONS.items():
    src = ROOT/revision
    if git(src, 'rev-parse', 'HEAD') != commit:
        raise RuntimeError(f'{revision}: incorrect source revision')
    subprocess.run(['git', '-C', str(src), 'diff', '--exit-code'], check=True)
    binary = OUT/('observe-'+revision)
    source = src/'lib/dnsthread/dnsthread.c'
    command = ['gcc', '-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
        '-D_POSIX_C_SOURCE=200809L', '-D_XOPEN_SOURCE=700',
        '-DMICA_DNSTHREAD_SOURCE="'+str(source)+'"']
    for path in ('lib/dnsthread', 'libcperciva/events', 'libcperciva/util',
                 'libcperciva/crypto', 'libcperciva/alg'):
        command.append('-I'+str(src/path))
    command += [str(HARNESS), str(src/'liball/liball.a'),
                str(src/'liball/optional_mutex_pthread/liball_optional_mutex_pthread.a'),
                '-lcrypto', '-lpthread', '-o', str(binary)]
    for symbol in ('strdup', 'free', 'events_network_register', 'events_network_cancel',
                   'pthread_cond_signal', 'pthread_cond_wait', 'pthread_mutex_unlock',
                   'pthread_join', 'sock_resolve'):
        command.append('-Wl,--wrap='+symbol)
    build = subprocess.run(command, capture_output=True, text=True, timeout=120, env=ENV)
    (OUT/('observer-build-'+revision+'.json')).write_text(json.dumps(
        {'command': command, 'returncode': build.returncode, 'stdout': build.stdout,
         'stderr': build.stderr}, indent=2)+'\n')
    if build.returncode:
        print(build.stderr, flush=True)
        raise RuntimeError(f'{revision}: observer build failed')
    manifest[revision] = {'commit': commit,
        'dnsthread_blob': git(src, 'rev-parse', 'HEAD:lib/dnsthread/dnsthread.c'),
        'dnsthread_sha256': sha256(source), 'observer_sha256': sha256(binary),
        'liball_sha256': sha256(src/'liball/liball.a'),
        'spipe_sha256': sha256(src/'spipe/spipe'),
        'spiped_sha256': sha256(src/'spiped/spiped')}
    for mode, dns_error, callback_rc, rounds in itertools.product(range(4), (0, 1), (0, 7), (1, 3)):
        name = f'mode{mode}-dns{dns_error}-cb{callback_rc}-rounds{rounds}'
        result = subprocess.run([str(binary), str(mode), str(dns_error), str(callback_rc), str(rounds)],
                                capture_output=True, text=True, timeout=10, env=ENV)
        row = {'revision': revision, 'case': name, 'mode': mode, 'dns_error': dns_error,
               'callback_rc': callback_rc, 'rounds': rounds, 'returncode': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr}
        try:
            observed = json.loads(result.stdout) if result.returncode == 0 else None
        except json.JSONDecodeError:
            observed = None
        row['observed'] = observed
        problems = verify_case(revision, mode, dns_error, callback_rc, rounds, observed) if observed else ['Observer failed']
        row['expectation_passed'] = not problems
        records.append(row)
        if problems:
            failures.append({'revision': revision, 'case': name, 'errors': problems, 'observed': row})
        print('CASE', json.dumps(row), flush=True)
    subprocess.run(['git', '-C', str(src), 'diff', '--exit-code'], check=True)
summary = {'cases': len(records), 'expected_outcomes_passed': sum(r['expectation_passed'] for r in records),
    'failed_expectations': len(failures), 'source': manifest,
    'observer_source_sha256': sha256(HARNESS),
    'limits': ['Linux/GCC optimized exact-source test; real pthread worker/event loop/AF_UNIX socketpair',
        'Resolver outputs are synthetic; selected strdup/register/signal errors are deliberate injection',
        'Original revision leaks are counted before separate post-join harness cleanup',
        'No stale-completion UAF provocation, external DNS, production data, or exploitability claim',
        'No sanitizer, full native suite, cross-platform, upstream acceptance or award claim']}
(OUT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'matrix.json').write_text(json.dumps(records, indent=2)+'\n')
(OUT/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
print('SUMMARY', json.dumps(summary), flush=True)
for failure in failures:
    print('FAIL', json.dumps(failure), flush=True)
raise SystemExit(1 if failures else 0)

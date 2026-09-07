#!/usr/bin/env python3
"""PR437 replay using real optimized libraries and only synthetic key material.

Usage: python3 run.py CHECKOUT_DIRECTORY OUTPUT_DIRECTORY
The checkout directory must contain normal built base/ and head/ trees.
The observer adds I/O fault injection and zeroing observation at link/runtime
seams, but executes the exact compiled proto_crypt and real zeroing functions.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REVISIONS = {'base': 'a945f3315e35ee48c8a79af952addc1b6616db83',
             'head': '92f0f726b827231d31108e59cd24dcf9fe6c5a71'}
ROOT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
FIX = OUT/'fixtures'
FIX.mkdir(exist_ok=True)
HARNESS = Path(__file__).with_name('observe.c').resolve()
ENV = dict(os.environ, LC_ALL='C')
records = []
failures = []
manifest = {}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(src: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(src), *args], text=True).strip()


def payload(n: int) -> bytes:
    # Nonzero public test bytes, never a production key or user-provided file.
    return bytes((17 * i + 1) % 255 + 1 for i in range(n))


executables = {}
bsizes = []
for revision, expected in REVISIONS.items():
    src = ROOT/revision
    if git(src, 'rev-parse', 'HEAD') != expected:
        raise RuntimeError(f'{revision}: incorrect source revision')
    subprocess.run(['git', '-C', str(src), 'diff', '--exit-code'], check=True)
    binary = OUT/('observe-'+revision)
    command = ['gcc', '-std=c99', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
               '-D_POSIX_C_SOURCE=200809L']
    for path in ('lib/proto', 'libcperciva/util', 'libcperciva/crypto', 'libcperciva/alg'):
        command += ['-I'+str(src/path)]
    command += [str(HARNESS), str(src/'liball/liball.a'),
                str(src/'liball/optional_mutex_pthread/liball_optional_mutex_pthread.a'),
                '-lcrypto', '-lpthread', '-o', str(binary)]
    for symbol in ('malloc', 'free', 'fopen', 'fread', 'feof', 'fclose', 'PBKDF2_SHA256'):
        command.append('-Wl,--wrap='+symbol)
    build = subprocess.run(command, capture_output=True, text=True, timeout=120, env=ENV)
    (OUT/('observer-build-'+revision+'.json')).write_text(json.dumps(
        {'command': command, 'returncode': build.returncode, 'stdout': build.stdout,
         'stderr': build.stderr}, indent=2)+'\n')
    if build.returncode:
        print(build.stderr, flush=True)
        raise RuntimeError(f'{revision}: observer link failed')
    executables[revision] = binary
    bsizes.append(int(subprocess.check_output([str(binary), '--bufsiz'], text=True)))
    manifest[revision] = {'commit': expected,
        'proto_crypt_blob': git(src, 'rev-parse', 'HEAD:lib/proto/proto_crypt.c'),
        'zeroing_blob': git(src, 'rev-parse', 'HEAD:libcperciva/util/insecure_memzero.c'),
        'liball_sha256': sha256((src/'liball/liball.a').read_bytes()),
        'spipe_sha256': sha256((src/'spipe/spipe').read_bytes()),
        'spiped_sha256': sha256((src/'spiped/spiped').read_bytes()),
        'observer_sha256': sha256(binary.read_bytes())}
if len(set(bsizes)) != 1:
    raise RuntimeError('Different BUFSIZ values between revisions')
B = bsizes[0]
# mode, route, input length, forced read-error offset, decryption direction
cases = []
for n in (0, 1, 31, 32, B-1, B, B+1, 2*B+31):
    for route in ('file', 'stdin'):
        for direction in (0, 1):
            cases.append(('normal', route, n, 0, direction))
for offset in (0, 1, 31, B-1, B, B+1, 2*B+17):
    for route in ('file', 'stdin'):
        cases.append(('read-error', route, max(B+32, offset+32), offset, 0))
for n in (0, 31, B+17):
    cases.append(('close-error', 'file', n, 0, 0))
cases.append(('open-error', 'file', 31, 0, 0))
for route in ('file', 'stdin'):
    cases.append(('malloc-error', route, 31, 0, 0))
assert len(cases) == 52

for revision in REVISIONS:
    for mode, route, n, offset, direction in cases:
        name = f'{mode}-{route}-{n}-{offset}-{direction}'
        data = payload(n)
        fixture = FIX/(name+'.key')
        fixture.write_bytes(data)
        command = [str(executables[revision]), mode,
                   '-' if route == 'stdin' else str(fixture), str(offset), str(direction)]
        result = subprocess.run(command, input=data if route == 'stdin' else b'',
                                capture_output=True, timeout=10, env=ENV)
        row = {'revision': revision, 'case': name, 'mode': mode, 'route': route,
               'input_length': n, 'input_sha256': sha256(data), 'forced_offset': offset,
               'direction': direction, 'returncode': result.returncode,
               'stdout': result.stdout.decode(errors='replace'),
               'stderr': result.stderr.decode(errors='replace')}
        records.append(row)
        try:
            observed = json.loads(row['stdout']) if result.returncode == 0 else None
        except json.JSONDecodeError:
            observed = None
        row['observed'] = observed
        if observed is None:
            failures.append({'case': name, 'revision': revision, 'reason': 'observer failed', 'row': row})
            continue
        success = mode in ('normal', 'close-error')
        reads = mode not in ('open-error', 'malloc-error')
        allocated = mode != 'malloc-error'
        expected_bytes = offset if mode == 'read-error' else (n if success else 0)
        expected_wipe = int(revision == 'head' and reads)
        expected_dk_wipe = int(revision == 'head' and success)
        expected = {'success': int(success), 'bufsiz': B, 'bytes_read': expected_bytes,
            'close_calls': int(reads and route == 'file'),
            'injected_read_error': int(mode == 'read-error'),
            'allocation_failures': int(mode == 'malloc-error'),
            'buffer_wipes': expected_wipe, 'buffer_bad_after': 0,
            'secret_wipes': int(allocated), 'secret_bad_after': 0, 'secret_frees': int(allocated),
            'pbkdf_calls': int(success), 'derived_wipes': expected_dk_wipe,
            'derived_bad_after': 0, 'derived_matches': expected_dk_wipe,
            'copied_before_wipe': expected_dk_wipe}
        if success:
            client_nonce, server_nonce = (bytes(range(32, 64)), bytes(range(32))) if direction else (bytes(range(32)), bytes(range(32, 64)))
            dk = hashlib.pbkdf2_hmac('sha256', hashlib.sha256(data).digest(),
                                    client_nonce+server_nonce, 1, 64)
            expected['output_l'] = (dk[32:] if direction else dk[:32]).hex()
            expected['output_r'] = (dk[:32] if direction else dk[32:]).hex()
        else:
            expected['output_l'] = expected['output_r'] = bytes(32).hex()
        mismatches = {key: {'expected': value, 'observed': observed.get(key)}
                      for key, value in expected.items() if observed.get(key) != value}
        if expected_wipe and expected_bytes > 0 and observed.get('buffer_nonzero_before', 0) == 0:
            mismatches['buffer_nonzero_before'] = 'Expected actual initialized nonzero synthetic key bytes before wiping'
        if mode == 'read-error' and 'Error reading' not in row['stderr']:
            mismatches['read_error_diagnostic'] = 'Missing expected read error'
        if mode == 'open-error' and 'Cannot open file' not in row['stderr']:
            mismatches['open_error_diagnostic'] = 'Missing expected open error'
        if mode == 'close-error' and 'fclose' not in row['stderr']:
            mismatches['close_error_diagnostic'] = 'Missing expected close error'
        row['expectation_passed'] = not mismatches
        if mismatches:
            failures.append({'case': name, 'revision': revision, 'mismatches': mismatches})

for revision in REVISIONS:
    subprocess.run(['git', '-C', str(ROOT/revision), 'diff', '--exit-code'], check=True)
summary = {'application_library_cases': len(records), 'expected_outcomes_passed':
    sum(row.get('expectation_passed', False) for row in records), 'failures': len(failures),
    'bufsiz': B, 'source': manifest, 'observer_source_sha256': sha256(HARNESS.read_bytes()),
    'totals': {rev: {field: sum(row['observed'][field] for row in records
                               if row['revision'] == rev and row['observed'] is not None)
        for field in ('success', 'buffer_wipes', 'derived_wipes', 'copied_before_wipe', 'secret_wipes')}
        for rev in REVISIONS},
    'limits': ['Linux x86-64/GCC normal optimized library builds; deterministic link-level I/O fault injection',
               'No live network, post-return stack reads, real keys, exploitability or bounty-value claims',
               'Named-buffer erasure is not proof that register copies or every stack spill are erased',
               'No native full-suite, sanitizer, Valgrind, or cross-platform claim']}
(OUT/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
(OUT/'matrix.json').write_text(json.dumps(records, indent=2)+'\n')
(OUT/'failures.json').write_text(json.dumps(failures, indent=2)+'\n')
print('SUMMARY', json.dumps(summary), flush=True)
for row in records:
    if row['case'] in (f'normal-file-{B+1}-0-0', f'read-error-stdin-{B+33}-{B+1}-0'):
        print('SAMPLE', json.dumps(row), flush=True)
for failure in failures:
    print('FAIL', json.dumps(failure), flush=True)
raise SystemExit(1 if failures else 0)

#!/usr/bin/env python3
"""Compile exact source snapshots and run real pthread/ASan error-path tests.

Expected baseline failures are evidence, not ignored test failures. The script
requires their specific sanitizer classes and source frames; all candidate
cases and both control cases must pass. No network or production daemon starts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
BLOBS = {
    'head.c': '5571d783e33e8342d4880725858ad4f49d40e337',
    'base.c': '83490fc3caec62765e2e512ce7a6f3287b6a80d5',
    'pthread_create_blocking_np.h': '5b53b3e162caec0b37f95e75e2fbb01c30caf014',
    'warnp.h': '92ed2423993a69571089823148f490e10b71d4f5',
    'warnp.c': '04c0d0cfce276e7b7a69079b25b30a769c33b833',
}


def main() -> None:
    logs = ROOT / 'logs'
    logs.mkdir(exist_ok=True)
    for name, expected in BLOBS.items():
        data = (ROOT / 'sources' / name).read_bytes()
        actual = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        if actual != expected:
            raise SystemExit(f'Source identity mismatch: {name}: {actual} != {expected}')
    cc = os.environ.get('CC', 'cc')
    report: dict = {
        'scope': 'exact changed translation unit + real pthreads + exact warnp dependencies; not full spiped build',
        'platform': platform.platform(),
        'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0],
        'base_commit': 'a945f3315e35ee48c8a79af952addc1b6616db83',
        'head_commit': 'e20e9a36070b31c5832bd342a5c98b0b1cf3bf4c',
        'source_blobs': BLOBS,
        'builds': [],
        'runs': [],
    }
    with tempfile.TemporaryDirectory(prefix='keel-spiped-443-') as tmp:
        for stage in ['base', 'head']:
            exe = Path(tmp) / f'probe-{stage}'
            command = [cc, '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-Wall', '-Wextra',
                       '-Werror', '-pedantic', '-O1', '-g', '-fno-omit-frame-pointer',
                       '-fsanitize=address', '-pthread', '-I', str(ROOT / 'sources'),
                       str(ROOT / 'fault_harness.c'), str(ROOT / 'sources' / f'{stage}.c'),
                       str(ROOT / 'sources' / 'warnp.c'),
                       '-Wl,--wrap=pthread_create', '-Wl,--wrap=pthread_mutex_unlock',
                       '-Wl,--wrap=pthread_cond_destroy', '-Wl,--wrap=pthread_mutex_destroy',
                       '-Wl,--wrap=pthread_join', '-o', str(exe)]
            build = subprocess.run(command, text=True, capture_output=True, timeout=30)
            (logs / f'{stage}-build.txt').write_text(build.stdout + build.stderr)
            report['builds'].append({'stage': stage, 'command': command,
                                    'returncode': build.returncode,
                                    'diagnostics': build.stdout + build.stderr})
            if build.returncode:
                (ROOT / 'fault_results.json').write_text(json.dumps(report, indent=2) + '\n')
                raise SystemExit(build.stderr)
            for scenario in ['normal', 'create', 'unlock', 'cond', 'mutex']:
                env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1:exitcode=86:color=never')
                try:
                    proc = subprocess.run([str(exe), scenario], text=True, capture_output=True,
                                          timeout=8, env=env)
                    code, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
                except subprocess.TimeoutExpired as exc:
                    code, stdout, stderr = 124, str(exc.stdout), str(exc.stderr)
                log_name = f'{stage}-{scenario}.txt'
                (logs / log_name).write_text(f'returncode={code}\n{stdout}{stderr}')
                expected = 'pass'
                if stage == 'base' and scenario == 'unlock':
                    expected = 'double-free'
                elif stage == 'base' and scenario in ('cond', 'mutex'):
                    expected = 'heap-use-after-free'
                if expected == 'pass':
                    matched = code == 0 and 'PASS ' in stdout and 'ERROR: AddressSanitizer' not in stderr
                else:
                    matched = code == 86 and f'ERROR: AddressSanitizer: {expected}' in stderr
                    # ASan's double-free wording has an extra "attempting".
                    if expected == 'double-free':
                        matched = code == 86 and 'AddressSanitizer: attempting double-free' in stderr
                    matched = matched and 'fault_harness.c' in stderr and f'{scenario} after worker_started=1' in stderr
                row = {'stage': stage, 'scenario': scenario, 'expected': expected,
                       'returncode': code, 'matched_expectation': matched, 'log': 'logs/' + log_name,
                       'stdout': stdout, 'stderr': stderr}
                report['runs'].append(row)
                print(stage, scenario, 'expected=' + expected, 'rc=' + str(code), 'MATCH=' + str(matched))
    report['matched'] = sum(row['matched_expectation'] for row in report['runs'])
    report['total'] = len(report['runs'])
    (ROOT / 'fault_results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"RESULT: {report['matched']}/{report['total']} expected outcomes")
    if report['matched'] != report['total']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

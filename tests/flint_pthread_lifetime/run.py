#!/usr/bin/env python3
"""Source-pinned Linux validation for spiped PR 443; never edits the checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

BASE = "a945f3315e35ee48c8a79af952addc1b6616db83"
HEAD = "e20e9a36070b31c5832bd342a5c98b0b1cf3bf4c"
HELPER = "lib/util/pthread_create_blocking_np.c"
HELPER_BLOBS = {
    "original": "83490fc3caec62765e2e512ce7a6f3287b6a80d5",
    "patched": "5571d783e33e8342d4880725858ad4f49d40e337",
}
# remote path: (materialized layout path, expected Git blob)
DEPENDENCIES = {
    "lib/util/pthread_create_blocking_np.h": ("include/pthread_create_blocking_np.h", "5b53b3e162caec0b37f95e75e2fbb01c30caf014"),
    "libcperciva/util/warnp.h": ("include/warnp.h", "92ed2423993a69571089823148f490e10b71d4f5"),
    "libcperciva/util/warnp.c": ("upstream/warnp.c", "04c0d0cfce276e7b7a69079b25b30a769c33b833"),
    "libcperciva/util/monoclock.h": ("include/monoclock.h", "ff0cded7177dd60b23852b2b6f43dcefc5f26417"),
    "libcperciva/util/monoclock.c": ("upstream/monoclock.c", "4cd82f4c0f8022a690a9f7a1ce198bb290e57d48"),
    "libcperciva/util/millisleep.h": ("include/millisleep.h", "fb9c302f679396baf12ec6a9e0eca00f6603eede"),
    "tests/pthread_create_blocking_np/main.c": ("tests/main.c", "5949071237345f6aa5632cc601b257957bec80f7"),
    "tests/pthread_create_blocking_np/timing.c": ("tests/timing.c", "6f283ec03f7226607186a847cf9b292fe37a8204"),
    "tests/pthread_create_blocking_np/timing.h": ("include/timing.h", "0a1d3f60e16f90ff1878aa62b486c3c0c474dc4a"),
}
WRAPS = ["pthread_mutex_unlock", "pthread_cond_destroy", "pthread_mutex_destroy",
         "pthread_create", "pthread_mutex_init", "pthread_cond_init",
         "pthread_mutex_lock", "malloc"]


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--materialized", type=Path,
                        help="Use hash-checked source files from the evidence bundle instead of git.")
    parser.add_argument("--output-parent", type=Path,
                        help="Existing directory for a NEW unique results subdirectory.")
    parser.add_argument("--cc", default="cc", help="C compiler executable, not a shell command")
    args = parser.parse_args()
    out = Path(tempfile.mkdtemp(prefix="flint-spiped-443-", dir=args.output_parent))
    src = out / "src"
    logs = out / "logs"
    src.mkdir(); logs.mkdir()
    provenance = []

    def obtain(ref: str, remote: str, local: str, expected: str) -> bytes:
        if args.materialized is not None:
            data = (args.materialized / local).read_bytes()
        else:
            data = subprocess.check_output(["git", "-C", str(args.repo), "show", ref + ":" + remote], timeout=15)
        actual = git_blob(data)
        if actual != expected:
            raise RuntimeError(f"Source mismatch for {remote}: expected {expected}, got {actual}")
        provenance.append({"ref": ref, "path": remote, "blob": actual, "bytes": len(data)})
        return data

    for remote, (local, expected) in DEPENDENCIES.items():
        (src / Path(remote).name).write_bytes(obtain(HEAD, remote, local, expected))
    for variant, ref in [("original", BASE), ("patched", HEAD)]:
        (src / (variant + ".c")).write_bytes(obtain(
            ref, HELPER, "upstream/pthread_create_blocking_np." + variant + ".c", HELPER_BLOBS[variant]))
    fault = Path(__file__).resolve().with_name("fault_injection.c")
    (src / "fault_injection.c").write_bytes(fault.read_bytes())
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (out / "fault-source.sha256").write_text(hashlib.sha256(fault.read_bytes()).hexdigest() + "\n")
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:exitcode=97",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    flags = [args.cc, "-Wall", "-Wextra", "-Werror", "-D_POSIX_C_SOURCE=200809L",
             "-g", "-O1", "-fno-omit-frame-pointer", "-fsanitize=address,undefined", "-pthread", "-I", str(src)]
    results = []

    def run(command: list[str], name: str, timeout: int = 15) -> subprocess.CompletedProcess:
        proc = subprocess.run(command, capture_output=True, env=env, timeout=timeout)
        (logs / (name + ".log")).write_bytes(
            ("$ " + shlex.join(command) + "\n").encode() + proc.stdout + proc.stderr +
            (f"\nEXIT={proc.returncode}\n").encode())
        return proc

    for variant in ["original", "patched"]:
        for kind in ["native", "fault"]:
            exe = out / (kind + "-" + variant)
            units = [str(src / (variant + ".c")), str(src / "warnp.c")]
            if kind == "native":
                units += [str(src / f) for f in ["monoclock.c", "main.c", "timing.c"]]
                options = ["-std=c99"]
            else:
                units += [str(src / "fault_injection.c")]
                options = ["-std=c11"] + ["-Wl,--wrap=" + f for f in WRAPS]
            built = run(flags + options + units + ["-o", str(exe)], kind + "-" + variant + "-compile", 30)
            if built.returncode:
                raise RuntimeError(f"Build failed: {kind}/{variant}; see {logs}")
            if kind == "native":
                p = run([str(exe)], "native-" + variant)
                results.append({"kind": "native", "variant": variant, "basic_cases": 1,
                                "timing_combinations": 16, "exit": p.returncode, "passed": p.returncode == 0})
                continue
            for mode in range(9):
                p = run([str(exe), str(mode)], f"fault-{variant}-{mode}")
                failure = variant == "original" and mode in [1, 2, 3]
                expected = b"attempting double-free" if mode == 1 else b"heap-use-after-free"
                passed = (p.returncode == 97 and expected in p.stderr) if failure else (
                    p.returncode == 0 and f"PASS mode={mode} ownership and cleanup exact".encode() in p.stderr)
                results.append({"kind": "fault", "variant": variant, "mode": mode,
                                "exit": p.returncode, "expected_failure": failure, "passed": passed})
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    summary = {"native_runs_passed": sum(r["passed"] for r in results if r["kind"] == "native"),
               "native_cases_per_run": "1 basic + 16 timing combinations",
               "fault_expectations_passed": sum(r["passed"] for r in results if r["kind"] == "fault"),
               "fault_expectations_total": 18,
               "all_passed": all(r["passed"] for r in results), "output": str(out)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

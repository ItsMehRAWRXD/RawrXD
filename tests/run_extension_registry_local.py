#!/usr/bin/env python3
"""Run 45 real extension-registry smoke checks with no model or GUI dependency.

This runner fails closed on compile errors, timeouts, missing checks, duplicate
check IDs, nonzero exit codes, or malformed test summaries.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests" / "extension_command_registry_smoke.cpp"
EXPECTED = 45


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    with tempfile.TemporaryDirectory(prefix="rawrxd-extension-smoke-") as tmp:
        exe = Path(tmp) / ("extension_smoke.exe" if os.name == "nt" else "extension_smoke")
        if Path(args.compiler).name.lower() in {"cl", "cl.exe"}:
            command = [args.compiler, "/nologo", "/std:c++17", "/EHsc", "/W4", "/WX",
                       str(SOURCE), "/Fe:" + str(exe)]
        else:
            command = [args.compiler, "-std=c++17", "-O1", "-Wall", "-Wextra",
                       "-Werror", "-pedantic", "-pthread", str(SOURCE), "-o", str(exe)]
        try:
            compile_result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                            text=True, timeout=args.timeout, check=False)
            if compile_result.returncode:
                print(compile_result.stdout + compile_result.stderr, file=sys.stderr)
                print("FAIL compilation", file=sys.stderr)
                return 1
            result = subprocess.run([str(exe)], cwd=ROOT, capture_output=True,
                                    text=True, timeout=args.timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL runner: {exc}", file=sys.stderr)
            return 1
        print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        ids = re.findall(r"^(?:PASS|FAIL) (\d{2}) ", result.stdout, re.MULTILINE)
        valid = (result.returncode == 0
                 and ids == [f"{n:02d}" for n in range(1, EXPECTED + 1)]
                 and f"RESULT {EXPECTED}/{EXPECTED} checks; PASS" in result.stdout
                 and not re.search(r"^FAIL ", result.stdout, re.MULTILINE))
        print("ACCEPTANCE " + ("PASS" if valid else "FAIL"))
        return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Local compiler/linker adapter for RawrXD agent tool calls.

No shell invocation, network access, model runtime or external service.
JSON result contract is stable for a future native IDE integration.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

def run_build(source, output, compiler, timeout=120):
    src = Path(source).resolve(strict=True)
    out = Path(output).resolve()
    if not src.is_file() or src.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("source must be a C or C++ file")
    if src == out:
        raise ValueError("output would overwrite source")
    if out.exists() and out.is_dir():
        raise ValueError("output is a directory")
    if timeout < 1 or timeout > 600:
        raise ValueError("timeout must be between 1 and 600 seconds")
    executable = shutil.which(compiler)
    if not executable:
        raise FileNotFoundError("compiler unavailable: " + compiler)
    # Explicit argv, never shell=True. The source is a single positional file.
    msvc = Path(executable).name.lower() in {"cl.exe", "cl"}
    if msvc:
        argv = [executable, "/nologo", "/EHsc", str(src), "/Fe:" + str(out)]
    else:
        argv = [executable, "-std=c++17", str(src), "-o", str(out)]
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   errors="replace", timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as exc:
        return {"ok": False, "stage": "timeout", "exit_code": None,
                "stdout": (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                "stderr": (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                "artifact": None}
    ok = completed.returncode == 0 and out.is_file()
    return {"ok": ok, "stage": "complete" if ok else "compile_link",
            "exit_code": completed.returncode,
            "stdout": completed.stdout[-32768:], "stderr": completed.stderr[-32768:],
            "artifact": str(out) if ok else None}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--compiler", default="cl" if os.name == "nt" else "c++")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()
    try:
        result = run_build(args.source, args.output, args.compiler, args.timeout)
    except (OSError, ValueError) as exc:
        result = {"ok": False, "stage": "validation", "exit_code": None,
                  "stdout": "", "stderr": str(exc), "artifact": None}
    print(json.dumps(result))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())

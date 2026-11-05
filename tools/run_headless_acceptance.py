#!/usr/bin/env python3
"""Compile and execute actual RawrXD headless acceptance sources; no model needed.

Exit nonzero on any build/test failure. Receipts are evidence only for executed
tests and include Git HEAD, compiler, source hashes, stdout and return codes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    ("extension_bridge", "tools/test_extension_host_bridge.cpp", "c++", 37),
    ("js_bridge", "tools/test_js_extension_bridge.cpp", "c++", 15),
    ("central_registry", "tools/test_command_registry_headless.cpp", "c++", 69),
    ("extension_integration", "tools/test_extension_central_integration.cpp", "c++", 15),
    ("cli_numeric", "tools/test_cli_numeric_policy.c", "c", 25),
]
SOURCES = [
    "~dev/rawrxd/src/core/extension_host_production.cpp",
    "~dev/rawrxd/src/core/js_extension_host_production.cpp",
    "~dev/rawrxd/src/core/command_registry.cpp",
    "~dev/rawrxd/src/core/command_registry.h",
    "~dev/rawrxd/src/core/cli_numeric_policy.h",
]
def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(command, timeout, cwd=ROOT):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                errors="replace", timeout=timeout, check=False)
        return {"command": command, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr}
    except subprocess.TimeoutExpired as exc:
        return {"command": command, "returncode": None, "timeout": True,
                "stdout": str(exc.stdout or ""), "stderr": str(exc.stderr or "")}
    except OSError as exc:
        return {"command": command, "returncode": None, "error": str(exc)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="headless-acceptance-receipt.json")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    cxx = shutil.which("g++") or shutil.which("clang++")
    cc = shutil.which("gcc") or shutil.which("clang")
    if not cxx or not cc:
        print("MISSING_COMPILER: need g++/clang++ and gcc/clang", file=sys.stderr)
        return 2
    receipt = {"schema": 1, "platform": sys.platform, "started_unix": time.time(),
               "git": run(["git", "rev-parse", "HEAD"], 10),
               "compilers": {"cxx": cxx, "cc": cc}, "sources": {}, "cases": []}
    for name in SOURCES + [x[1] for x in CASES]:
        path = ROOT / name
        if not path.is_file():
            print("MISSING_SOURCE:", name, file=sys.stderr)
            return 2
        receipt["sources"][name] = sha256(path)
    failures = 0
    with tempfile.TemporaryDirectory(prefix="rawrxd-headless-") as temp:
        for label, source, language, expected in CASES:
            compiler = cxx if language == "c++" else cc
            flags = (["-std=c++17", "-pthread"] if language == "c++"
                     else ["-std=c11"])
            binary = str(Path(temp) / label)
            build = run([compiler, *flags, "-Wall", "-Wextra", "-Werror",
                         "-fsanitize=undefined", "-fno-omit-frame-pointer",
                         source, "-o", binary, *(["-lm"] if language == "c" else [])],
                        args.timeout)
            entry = {"name": label, "expected_cases": expected, "build": build}
            if build.get("returncode") == 0:
                entry["execute"] = run([binary], args.timeout)
                output = entry["execute"].get("stdout", "")
                marker = {
                    "extension_bridge": "EXTENSION_BRIDGE",
                    "js_bridge": "JS_BRIDGE_FAIL_CLOSED",
                    "central_registry": "CENTRAL_REGISTRY",
                    "extension_integration": "EXTENSION_CENTRAL_INTEGRATION",
                    "cli_numeric": "CLI_NUMERIC_POLICY",
                }[label]
                entry["passed"] = (entry["execute"].get("returncode") == 0 and
                                   (marker + "=" + str(expected) + "/" + str(expected)) in output)
            else:
                entry["passed"] = False
            failures += not entry["passed"]
            receipt["cases"].append(entry)
            print(label + ": " + ("PASS" if entry["passed"] else "FAIL"), flush=True)
    receipt["finished_unix"] = time.time()
    receipt["passed_suites"] = len(CASES) - failures
    receipt["total_suites"] = len(CASES)
    receipt["all_passed"] = failures == 0
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("RECEIPT:", output)
    return 0 if failures == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

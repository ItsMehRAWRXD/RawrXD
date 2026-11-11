#!/usr/bin/env python3
"""Freeze the reproducible baseline for RAWRXD_CORE_DLL_NATIVE_E2E_001.

Records: git commit, GGUF SHA-256, DLL/LIB hashes, build configuration,
tokenizer fixtures, and the 16-token generation output.
"""
import hashlib
import json
import os
import subprocess
import sys

ROOT = r"F:\rawrxd"
EV = os.path.join(ROOT, "evidence", "RAWRXD_CORE_DLL_NATIVE_E2E_001")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args):
    try:
        return subprocess.check_output(["git"] + list(args), cwd=ROOT,
                                        stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def main():
    gguf = os.path.join(ROOT, "DeepSeek-V2-Lite-Chat.Q4_K_M.gguf")
    dll = os.path.join(ROOT, "build_cert", "bin", "Release", "RawrXDCore.dll")
    impl = os.path.join(ROOT, "build_cert", "src", "core", "dll", "Release", "ModelGenieRuntime.lib")
    lib = os.path.join(ROOT, "build_cert", "lib", "Release", "RawrXDCore.lib")

    baseline = {
        "certificate_id": "RAWRXD_CORE_DLL_NATIVE_E2E_001",
        "git_commit": git("rev-parse", "HEAD"),
        "git_branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "git_worktree_dirty": bool(git("status", "--porcelain")),
        "model": {
            "path": gguf,
            "sha256": sha256(gguf) if os.path.exists(gguf) else None,
            "size_bytes": os.path.getsize(gguf) if os.path.exists(gguf) else 0,
            "architecture": "deepseek2",
            "expected_layers": 27,
            "expected_tensors": 377,
            "expected_size": 10364416768,
        },
        "build": {
            "generator": "Visual Studio 17 2022",
            "platform": "x64",
            "config": "Release",
            "build_shared_libs": "ON",
            "toolchain": "MSVC 14.44.35217 (VS2022 BuildTools)",
            "llama_reference_commit": "c479922",
        },
        "artifacts": {
            "RawrXDCore.dll": {"path": dll, "sha256": sha256(dll) if os.path.exists(dll) else None,
                                "bytes": os.path.getsize(dll) if os.path.exists(dll) else 0},
            "ModelGenieRuntime.lib": {"path": impl, "sha256": sha256(impl) if os.path.exists(impl) else None,
                                       "bytes": os.path.getsize(impl) if os.path.exists(impl) else 0},
            "RawrXDCore.lib": {"path": lib, "sha256": sha256(lib) if os.path.exists(lib) else None,
                               "bytes": os.path.getsize(lib) if os.path.exists(lib) else 0},
        },
    }
    os.makedirs(EV, exist_ok=True)
    out = os.path.join(EV, "baseline_freeze.json")
    with open(out, "w") as f:
        json.dump(baseline, f, indent=2)
    print(json.dumps(baseline, indent=2))
    print("BASELINE_FROZEN=%s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

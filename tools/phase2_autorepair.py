#!/usr/bin/env python3
"""Bounded, dependency-free Phase 2 build-repair controller.

Runs on a Windows machine with MSVC, CMake, and (where required) Vulkan SDK.
No model files, Git history, release tags, or protected branches are modified.
Unrecognized compiler errors are reported, not guessed at.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ALLOWED_BRANCH = "agent/phase2-repair"
HEADER_NAMES = {"MultiShardFlickerManager.hpp", "PrefetchQueue.hpp"}
WINDOWS_TYPES = re.compile(r"\b(HANDLE|DWORD|OVERLAPPED|HMODULE|CRITICAL_SECTION|LARGE_INTEGER)\b")
VULKAN_TYPES = re.compile(r"\b(Vk[A-Z]\w*|VK_[A-Z0-9_]+)\b")
ERROR_PATTERN = re.compile(r"(?:\bfatal error\b|\berror C\d+\b|\berror LNK\d+\b|\berror MSB\d+\b|\bCMake Error\b)", re.I)

def run(args, cwd, timeout, log):
    with log.open("a", encoding="utf-8") as out:
        out.write("\n$ " + " ".join(args) + "\n")
        out.flush()
        try:
            p = subprocess.run(args, cwd=cwd, stdout=out, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False)
            return p.returncode
        except subprocess.TimeoutExpired:
            out.write(f"TIMEOUT after {timeout}s\n")
            return 124
        except OSError as exc:
            out.write(f"EXECUTION ERROR: {exc}\n")
            return 127

def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.STDOUT).strip()

def check_workspace(root):
    if git(root, "branch", "--show-current") != ALLOWED_BRANCH:
        raise RuntimeError(f"Refusing edits outside {ALLOWED_BRANCH}")
    if git(root, "status", "--porcelain"):
        raise RuntimeError("Working tree must be clean; refusing to overwrite user edits")

def candidate_headers(root):
    for name in HEADER_NAMES:
        for path in root.rglob(name):
            if ".git" not in path.parts and "build" not in path.parts:
                yield path

def safe_header_repairs(root, dry_run):
    changes = []
    for path in candidate_headers(root):
        source = path.read_text(encoding="utf-8-sig")
        additions = []
        if WINDOWS_TYPES.search(source) and not re.search(r"#\s*include\s*[<\"]windows\.h[>\"]", source):
            additions.append("#ifdef _WIN32\n#include <windows.h>\n#endif\n")
        if VULKAN_TYPES.search(source) and not re.search(r"#\s*include\s*[<\"]vulkan/vulkan\.h[>\"]", source):
            additions.append("#include <vulkan/vulkan.h>\n")
        if additions:
            updated = "".join(additions) + source
            changes.append(str(path.relative_to(root)))
            if not dry_run:
                path.write_text(updated, encoding="utf-8")
    return changes

def extract_errors(path, limit=60):
    if not path.exists():
        return []
    return [line.strip()[:450] for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ERROR_PATTERN.search(line)][:limit]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--build-command", default="build.bat")
    parser.add_argument("--smoke", default=r"build\bin\Release\production_smoke_test.exe")
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--apply", action="store_true", help="Allow safe, deterministic source edits")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    check_workspace(root)
    if not (1 <= args.max_attempts <= 10):
        parser.error("--max-attempts must be 1..10")
    report_dir = root / ".phase2-repair-reports"
    report_dir.mkdir(exist_ok=True)
    report = {"branch": ALLOWED_BRANCH, "baseline": git(root, "rev-parse", "HEAD"),
              "attempts": [], "status": "NOT_CERTIFIED"}
    build_command = root / args.build_command
    if not build_command.is_file():
        raise RuntimeError(f"Build command missing: {build_command}")
    for index in range(1, args.max_attempts + 1):
        log = report_dir / f"build-{index}.log"
        log.write_text("", encoding="utf-8")
        start = time.monotonic()
        rc = run(["cmd", "/d", "/c", str(build_command)], root, args.timeout, log)
        item = {"attempt": index, "build_exit": rc, "elapsed_s": round(time.monotonic()-start, 2),
                "errors": extract_errors(log), "patches": []}
        report["attempts"].append(item)
        if rc == 0:
            smoke = root / args.smoke
            item["smoke_exit"] = run([str(smoke)], root, args.timeout, log) if smoke.is_file() else 127
            if item["smoke_exit"] == 0:
                report["status"] = "BUILD_AND_SMOKE_PASS"
                break
            # Never claim certification when the smoke test fails.
            break
        if not args.apply:
            break
        changed = safe_header_repairs(root, dry_run=False)
        item["patches"] = changed
        if not changed:
            break  # No verified deterministic repair: human/model review required.
    (report_dir / "receipt.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "BUILD_AND_SMOKE_PASS" else 1

if __name__ == "__main__":
    sys.exit(main())

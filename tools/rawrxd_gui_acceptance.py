"""Fail-closed UIAutomation helper for RawrXD acceptance tests.

This is an operator harness, not a certification result. It never injects
WM_COMMAND/callbacks. Hard-kill is opt-in and requires an exact candidate hash.
Requires Python 3.11+, pywinauto and psutil on an interactive Windows desktop.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import psutil
from pywinauto import Desktop


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def find_process(exe: Path, expected_sha: str):
    actual = sha256(exe)
    if actual != expected_sha.upper():
        raise RuntimeError(f"candidate hash mismatch: {actual} != {expected_sha}")
    matches = []
    for proc in psutil.process_iter(["pid", "exe", "create_time"]):
        try:
            if Path(proc.info["exe"] or "").resolve() == exe.resolve():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one candidate process, found {len(matches)}")
    return matches[0], actual


def locate_editor(pid: int):
    windows = Desktop(backend="uia").windows(process=pid)
    if len(windows) != 1:
        raise RuntimeError(f"expected one RawrXD window for PID {pid}, found {len(windows)}")
    window = windows[0]
    edits = window.descendants(control_type="Edit")
    # The chat transcript/input and PowerShell controls are also edits. Prefer
    # a RichEdit/native editor by class name, then require an unambiguous result.
    rich = [e for e in edits if "RichEdit" in (e.element_info.class_name or "")]
    candidates = rich or edits
    if len(candidates) != 1:
        details = [
            {"name": e.element_info.name, "class": e.element_info.class_name,
             "automation_id": e.element_info.automation_id}
            for e in candidates
        ]
        raise RuntimeError("editor control is not unambiguous: " + json.dumps(details))
    return window, candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--marker", default="RAWRXD_T10_UIA_MARKER")
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--hard-kill", action="store_true")
    args = parser.parse_args()

    proc, before_hash = find_process(args.exe, args.sha256)
    window, editor = locate_editor(proc.pid)
    window.set_focus()
    editor.set_focus()
    editor.type_keys(args.marker, with_spaces=True)
    args.snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot = {
        "pid": proc.pid,
        "start_time": proc.create_time(),
        "exe": str(args.exe.resolve()),
        "sha256_before": before_hash,
        "editor_class": editor.element_info.class_name,
        "editor_automation_id": editor.element_info.automation_id,
        "marker": args.marker,
        "typed_at": time.time(),
        "note": "Operator must independently verify visible dirty state and autosave contents.",
    }
    args.snapshot.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")

    if args.hard_kill:
        proc2, after_hash = find_process(args.exe, args.sha256)
        if proc2.pid != proc.pid or proc2.create_time() != proc.create_time():
            raise RuntimeError("PID/start-time changed before hard-kill")
        proc2.terminate()
        proc2.wait(timeout=15)
        snapshot["terminated_pid"] = proc.pid
        snapshot["sha256_after"] = after_hash
        args.snapshot.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(json.dumps(snapshot, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"NOT_VERIFIED: {exc}", file=sys.stderr)
        raise SystemExit(2)

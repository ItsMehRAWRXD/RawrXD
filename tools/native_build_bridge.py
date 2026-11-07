#!/usr/bin/env python3
"""Offline C/C++ compile -> object -> link -> executable adapter.

The JSON interface is designed for a future native IDE tool dispatcher.
No shell, Ollama, model inference or network dependency. This is not yet
connected to Win32IDE. A successful result requires a real artifact.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


def _terminate_tree(proc):
    if proc.poll() is not None:
        return
    if os.name == "nt":
        # taskkill handles descendants created by compiler drivers.
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=10, check=False)
        if proc.poll() is None:
            proc.kill()
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if proc.poll() is None:
            proc.kill()


def execute(argv, timeout=120, cwd=None):
    """Drain stdout and stderr concurrently with communicate(); kill on timeout.

    Pipes are drained by communicate, avoiding sequential read deadlocks.
    On timeout the entire process group/tree is terminated and reaped.
    """
    if not argv or not isinstance(argv, (list, tuple)):
        raise ValueError("argv must be a nonempty sequence")
    if not 1 <= timeout <= 600:
        raise ValueError("timeout must be between 1 and 600 seconds")
    kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
              "stdin": subprocess.DEVNULL, "cwd": cwd, "shell": False}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    started = time.monotonic()
    proc = subprocess.Popen(argv, **kwargs)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_tree(proc)
        stdout, stderr = proc.communicate()
    return {"ok": not timed_out and proc.returncode == 0,
            "exit_code": proc.returncode, "timed_out": timed_out,
            "stdout": stdout[-32768:].decode("utf-8", "replace"),
            "stderr": stderr[-32768:].decode("utf-8", "replace"),
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def run_build(source, output, compiler, timeout=120, linker=None, run=False):
    src = Path(source).resolve(strict=True)
    out = Path(output).resolve()
    if not src.is_file() or src.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError("source must be a C or C++ file")
    if src == out or out.exists() and out.is_dir():
        raise ValueError("invalid output path")
    if not 1 <= timeout <= 600:
        raise ValueError("timeout must be between 1 and 600 seconds")
    executable = shutil.which(compiler)
    if not executable:
        raise FileNotFoundError("compiler unavailable: " + compiler)
    msvc = Path(executable).name.lower() in {"cl.exe", "cl"}
    if linker:
        link_exe = shutil.which(linker)
        if not link_exe:
            raise FileNotFoundError("linker unavailable: " + linker)
    else:
        link_exe = executable
    obj = out.with_suffix(".obj" if msvc else ".o")
    if obj == src or obj == out:
        raise ValueError("object path collides with source or output")
    out.parent.mkdir(parents=True, exist_ok=True)
    # Do not mistake artifacts from earlier runs for success.
    for artifact in (obj, out):
        if artifact.exists():
            artifact.unlink()
    is_c = src.suffix.lower() == ".c"
    if msvc:
        compile_args = [executable, "/nologo", "/c", "/TC" if is_c else "/TP",
                        str(src), "/Fo" + str(obj)]
        link_args = [link_exe, "/nologo", str(obj), "/Fe:" + str(out)] if not linker else [
            link_exe, "/NOLOGO", str(obj), "/OUT:" + str(out)]
    else:
        compile_args = [executable] + ([] if is_c else ["-std=c++17"]) + [
            "-c", str(src), "-o", str(obj)]
        link_args = [link_exe, str(obj), "-o", str(out)]
    deadline = time.monotonic() + timeout
    stages = []
    for stage, args, artifact in (("compile", compile_args, obj),
                                   ("link", link_args, out)):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"ok": False, "stage": stage, "timed_out": True,
                    "exit_code": None, "stdout": "", "stderr": "build deadline exceeded",
                    "artifact": None, "stages": stages}
        result = execute(args, min(600, max(0.001, remaining)))
        stages.append({"stage": stage, **result})
        if not result["ok"] or not artifact.is_file():
            return {"ok": False, "stage": stage, **result, "artifact": None,
                    "stages": stages}
    if run:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"ok": False, "stage": "run", "timed_out": True,
                    "exit_code": None, "stdout": "", "stderr": "build deadline exceeded",
                    "artifact": str(out), "stages": stages}
        result = execute([str(out)], min(600, max(0.001, remaining)))
        stages.append({"stage": "run", **result})
        if not result["ok"]:
            return {"ok": False, "stage": "run", **result,
                    "artifact": str(out), "stages": stages}
    return {"ok": True, "stage": "complete", "exit_code": 0,
            "stdout": stages[-1]["stdout"], "stderr": stages[-1]["stderr"],
            "artifact": str(out), "stages": stages}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--compiler", default="cl" if os.name == "nt" else "c++")
    parser.add_argument("--linker")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    try:
        result = run_build(args.source, args.output, args.compiler,
                           args.timeout, args.linker, args.run)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {"ok": False, "stage": "validation", "exit_code": None,
                  "stdout": "", "stderr": str(exc), "artifact": None}
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

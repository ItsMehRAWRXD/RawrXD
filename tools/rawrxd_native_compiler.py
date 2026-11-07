#!/usr/bin/env python3
"""Fail-closed local C/C++ compile -> object -> link runner.

Structured JSON output for RawrXD native IDE tools. No shell or model required.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def run_process(command, cwd, timeout):
    """Drain stdout and stderr concurrently; kill the entire process tree on timeout."""
    started = time.monotonic()
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(command, cwd=str(cwd), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                creationflags=flags, start_new_session=os.name != "nt")
    except OSError as exc:
        return {"ok": False, "error": "spawn_failed", "detail": str(exc),
                "exit_code": None, "stdout": "", "stderr": ""}
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            # taskkill /T terminates compiler descendants (link.exe, etc.).
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if proc.poll() is None:
                proc.kill()
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stdout, stderr = proc.communicate()
    return {"ok": not timed_out and proc.returncode == 0,
            "exit_code": proc.returncode, "timed_out": timed_out,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", choices=("cl", "clang-cl", "g++", "clang++", "gcc", "clang"), required=True)
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cwd", default=".")
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--define", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=120, help="overall build deadline, seconds")
    args = parser.parse_args(argv)
    cwd = Path(args.cwd).resolve()
    output = (cwd / args.output).resolve()
    sources = [(cwd / src).resolve() for src in args.source]
    includes = [(cwd / inc).resolve() for inc in args.include]
    report = {"schema": "rawrxd.compiler.v2", "ok": False, "compiler": args.compiler,
              "output": str(output), "steps": []}

    def finish(error=None):
        if error:
            report["error"] = error
        print(json.dumps(report))
        return 0 if report["ok"] else 1

    if not cwd.is_dir() or not 1 <= args.timeout <= 3600:
        return finish("invalid cwd or timeout")
    if any(not src.is_file() for src in sources) or any(not inc.is_dir() for inc in includes):
        return finish("missing source or include directory")
    if any(not d or d.startswith(("-", "/")) or "\x00" in d for d in args.define):
        return finish("invalid preprocessor definition")
    tool = shutil.which(args.compiler)
    if tool is None:
        return finish("toolchain unavailable")
    if output.exists() and not output.is_file():
        return finish("output is not a regular file")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()  # Stale binaries cannot satisfy this build.
    deadline = time.monotonic() + args.timeout
    msvc = args.compiler in ("cl", "clang-cl")
    ext = ".obj" if msvc else ".o"
    try:
        with tempfile.TemporaryDirectory(prefix="rawrxd-objects-") as tmp:
            objects = []
            for index, source in enumerate(sources):
                obj = Path(tmp) / ("unit_" + str(index) + ext)
                if msvc:
                    command = [tool, "/nologo", "/c", "/EHsc", "/std:c++20" if source.suffix.lower() != ".c" else "/TC"]
                    command += ["/I" + str(i) for i in includes] + ["/D" + d for d in args.define]
                    command += [str(source), "/Fo" + str(obj)]
                else:
                    command = [tool, "-c", str(source), "-o", str(obj)]
                    command += ["-I" + str(i) for i in includes] + ["-D" + d for d in args.define]
                    command += ["-std=c11" if source.suffix.lower() == ".c" else "-std=c++20"]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return finish("build deadline exceeded")
                result = run_process(command, cwd, remaining)
                report["steps"].append({"phase": "compile", "source": str(source),
                                        "command": command, **result})
                if not result["ok"] or not obj.is_file():
                    return finish("compile failed, timed out, or object missing")
                objects.append(obj)
            if msvc:
                linker = shutil.which("link.exe") or shutil.which("lld-link.exe")
                if not linker:
                    return finish("linker unavailable")
                command = [linker, "/NOLOGO", "/OUT:" + str(output)] + [str(o) for o in objects]
            else:
                # C++ linker driver supplies the appropriate runtime for mixed C/C++ units.
                driver = tool
                if args.compiler == "gcc" and any(s.suffix.lower() != ".c" for s in sources):
                    driver = shutil.which("g++")
                if args.compiler == "clang" and any(s.suffix.lower() != ".c" for s in sources):
                    driver = shutil.which("clang++")
                if not driver:
                    return finish("C++ linker driver unavailable")
                command = [driver, *map(str, objects), "-o", str(output)]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return finish("build deadline exceeded")
            result = run_process(command, cwd, remaining)
            report["steps"].append({"phase": "link", "command": command, **result})
            report["ok"] = bool(result["ok"] and output.is_file())
            return finish(None if report["ok"] else "link failed, timed out, or executable missing")
    except (OSError, ValueError) as exc:
        return finish("build setup failed: " + str(exc))


if __name__ == "__main__":
    sys.exit(main())

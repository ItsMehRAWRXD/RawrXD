#!/usr/bin/env python3
"""Local fail-closed C++ compiler/linker runner for IDE tool calls.

No shell, downloads, remote execution, or inference. Toolchains must be installed.
Emits one JSON record and exits nonzero unless the requested artifact is produced.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--compiler", choices=("cl", "clang-cl", "g++", "clang++"), required=True)
    p.add_argument("--source", action="append", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--cwd", default=".")
    p.add_argument("--include", action="append", default=[])
    p.add_argument("--define", action="append", default=[])
    p.add_argument("--timeout", type=int, default=120)
    args = p.parse_args(argv)
    cwd = Path(args.cwd).resolve()
    out = (cwd / args.output).resolve()
    sources = [(cwd / src).resolve() for src in args.source]
    includes = [(cwd / inc).resolve() for inc in args.include]
    report = {"schema": "rawrxd.compiler.v1", "ok": False,
              "output": str(out), "compiler": args.compiler}
    def finish(message, code=1):
        if message:
            report["error"] = message
        print(json.dumps(report))
        return code
    if not cwd.is_dir() or not 1 <= args.timeout <= 3600:
        return finish("invalid cwd or timeout")
    if any(not src.is_file() for src in sources):
        return finish("missing source")
    if any(not inc.is_dir() for inc in includes):
        return finish("missing include directory")
    if any(not d or d.startswith(("-", "/")) or "\x00" in d for d in args.define):
        return finish("invalid define")
    compiler = shutil.which(args.compiler)
    if compiler is None:
        return finish("compiler not installed or not on PATH")
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        if not out.is_file():
            return finish("output is not a regular file")
        out.unlink()  # A stale binary must never produce a false PASS.
    if args.compiler in ("cl", "clang-cl"):
        command = [compiler, "/nologo", "/std:c++20", "/EHsc"]
        command += ["/I" + str(i) for i in includes]
        command += ["/D" + d for d in args.define]
        command += [str(s) for s in sources] + ["/Fe:" + str(out)]
    else:
        command = [compiler, "-std=c++20", "-o", str(out)]
        command += ["-I" + str(i) for i in includes]
        command += ["-D" + d for d in args.define]
        command += [str(s) for s in sources]
    report["command"] = command
    try:
        run = subprocess.run(command, cwd=str(cwd), shell=False,
                             capture_output=True, text=True,
                             errors="replace", timeout=args.timeout)
        report.update(exit_code=run.returncode, stdout=run.stdout, stderr=run.stderr)
    except subprocess.TimeoutExpired:
        return finish("compiler/linker timed out")
    except OSError as exc:
        return finish("compiler spawn failed: " + str(exc))
    report["ok"] = run.returncode == 0 and out.is_file()
    return finish(None if report["ok"] else "compile/link failed or output missing",
                  0 if report["ok"] else 1)

if __name__ == "__main__":
    sys.exit(main())

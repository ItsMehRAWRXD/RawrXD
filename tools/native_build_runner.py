"""Headless native C/C++ compiler/linker runner. Python 3.10+, standard library only.

Examples (from a VS Developer Command Prompt):
  python tools/native_build_runner.py --timeout 60 -- cl /nologo /c hello.cpp /Fohello.obj
  python tools/native_build_runner.py --timeout 60 -- link /nologo hello.obj /OUT:hello.exe

Outputs one JSON receipt on stdout. Child stdout/stderr are captured concurrently
by subprocess.communicate(), avoiding pipe-buffer deadlocks. This is a CLI adapter;
IDE wiring is a separate acceptance gate.
"""
import argparse
import json
import os
import subprocess
import signal
import sys
import time
import threading


def execute(argv, timeout, cwd=None, max_output_bytes=4 * 1024 * 1024):
    if timeout <= 0 or max_output_bytes < 0:
        raise ValueError('timeout must be positive and output cap nonnegative')
    start = time.monotonic()
    receipt = dict(command=argv, cwd=cwd or os.getcwd(), exit_code=None,
                   timed_out=False, stdout="", stderr="", elapsed_seconds=0.0,
                   launch_error=None, stdout_truncated=False, stderr_truncated=False)
    flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    try:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                creationflags=flags, start_new_session=os.name != "nt")
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        def drain(stream, name):
            try:
                while True:
                    chunk = stream.read(65536)
                    if not chunk:
                        break
                    remaining = max_output_bytes - len(buffers[name])
                    if len(chunk) > remaining:
                        receipt[name + "_truncated"] = True
                    if remaining > 0:
                        buffers[name].extend(chunk[:remaining])
            finally:
                stream.close()
        readers = [threading.Thread(target=drain, args=(proc.stdout, "stdout"), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, "stderr"), daemon=True)]
        for reader in readers:
            reader.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            receipt["timed_out"] = True
            if os.name == "nt":
                # Kill descendants as well as the immediate compiler/linker.
                try:
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=5, check=False)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            if os.name != "nt":
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        for reader in readers:
            reader.join(timeout=5)
        receipt["exit_code"] = proc.returncode
        receipt["stdout"] = buffers["stdout"].decode("utf-8", errors="replace")
        receipt["stderr"] = buffers["stderr"].decode("utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError) as exc:
        receipt["launch_error"] = str(exc)
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - start, 4)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--max-output-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd or args.timeout <= 0 or args.max_output_bytes < 0:
        parser.error("provide a command and a positive timeout")
    result = execute(cmd, args.timeout, args.cwd, args.max_output_bytes)
    print(json.dumps(result, ensure_ascii=False))
    return 124 if result["timed_out"] else (127 if result["launch_error"] else
                                            (0 if result["exit_code"] == 0 else 1))


if __name__ == "__main__":
    sys.exit(main())

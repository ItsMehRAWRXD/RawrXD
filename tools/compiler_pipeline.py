#!/usr/bin/env python3
"""Deterministic C/C++ compile -> object -> link -> executable CLI.

No shell, no Ollama, no model. JSON output is suitable for an IDE adapter.
On Windows, subprocesses are placed in a Job Object with kill-on-close so
timeouts terminate descendants, not merely the compiler parent.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

def _job_for_process(proc):
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k.CreateJobObjectW.restype = wintypes.HANDLE
    k.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k.SetInformationJobObject.restype = wintypes.BOOL
    k.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k.AssignProcessToJobObject.restype = wintypes.BOOL
    k.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.TerminateJobObject.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [("ReadOperationCount", ctypes.c_uint64),
                    ("WriteOperationCount", ctypes.c_uint64),
                    ("OtherOperationCount", ctypes.c_uint64),
                    ("ReadTransferCount", ctypes.c_uint64),
                    ("WriteTransferCount", ctypes.c_uint64),
                    ("OtherTransferCount", ctypes.c_uint64)]
    class Extended(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", IO),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]
    job = k.CreateJobObjectW(None, None)
    if not job:
        raise OSError(ctypes.get_last_error(), "CreateJobObjectW")
    info = Extended()
    info.BasicLimitInformation.LimitFlags = 0x2000
    if not k.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        error = ctypes.get_last_error()
        k.CloseHandle(job)
        raise OSError(error, "SetInformationJobObject")
    if not k.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):
        error = ctypes.get_last_error()
        k.CloseHandle(job)
        raise OSError(error, "AssignProcessToJobObject")
    return (k, job)

def run_command(argv, cwd, timeout):
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    started = time.monotonic()
    proc = subprocess.Popen(argv, cwd=str(cwd), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            shell=False, bufsize=0,
                            start_new_session=(os.name != "nt"),
                            creationflags=(subprocess.CREATE_SUSPENDED if os.name == "nt" else 0))
    job = None
    chunks = {"stdout": [], "stderr": []}
    def drain(stream, name):
        try:
            while True:
                data = stream.read(65536)
                if not data:
                    break
                chunks[name].append(data)
        finally:
            stream.close()
    threads = []
    timed_out = False
    try:
        if os.name == "nt":
            try:
                job = _job_for_process(proc)
            finally:
                import ctypes
                k = ctypes.WinDLL("kernel32", use_last_error=True)
                k.ResumeThread.argtypes = [ctypes.c_void_p]
                k.ResumeThread.restype = ctypes.c_ulong
                # Popen exposes the primary thread handle on Windows.
                if getattr(proc, "_thread", None) is None:
                    raise RuntimeError("suspended child thread handle unavailable")
                k.ResumeThread(int(proc._thread))
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            t = threading.Thread(target=drain, args=(stream, name), daemon=True)
            t.start()
            threads.append(t)
        try:
            proc.wait(timeout=max(0.001, timeout - (time.monotonic() - started)))
        except subprocess.TimeoutExpired:
            timed_out = True
            if job:
                job[0].TerminateJobObject(job[1], 1)
            elif os.name != "nt":
                import signal
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
            proc.wait()
        for t in threads:
            t.join(timeout=5)
        if any(t.is_alive() for t in threads):
            raise RuntimeError("output drain did not terminate")
    finally:
        if proc.poll() is None:
            if job:
                job[0].TerminateJobObject(job[1], 1)
            else:
                proc.kill()
            proc.wait()
        if job:
            job[0].CloseHandle(job[1])
        for stream in (proc.stdout, proc.stderr):
            if stream and not stream.closed:
                stream.close()
    return {"argv": argv, "exit_code": proc.returncode,
            "timed_out": timed_out, "duration_ms": round((time.monotonic()-started)*1000),
            "stdout": b"".join(chunks["stdout"]).decode("utf-8", "replace"),
            "stderr": b"".join(chunks["stderr"]).decode("utf-8", "replace")}

def build(sources, output, compiler, linker, timeout, mode):
    if not sources:
        raise ValueError("at least one source required")
    if mode not in ("msvc", "gnu"):
        raise ValueError("unsupported toolchain mode")
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    steps = []
    with tempfile.TemporaryDirectory(prefix="rawrxd-build-") as td:
        objects = []
        for index, source in enumerate(sources):
            src = Path(source).resolve()
            if not src.is_file():
                raise FileNotFoundError(str(src))
            obj = Path(td) / ("unit_%d.%s" % (index, "obj" if mode == "msvc" else "o"))
            cmd = ([compiler, "/nologo", "/c", str(src), "/Fo" + str(obj)]
                   if mode == "msvc" else [compiler, "-c", str(src), "-o", str(obj)])
            step = run_command(cmd, td, timeout)
            step["stage"] = "compile"
            steps.append(step)
            if step["timed_out"] or step["exit_code"] != 0 or not obj.is_file():
                return {"ok": False, "steps": steps, "failure": "compile"}
            objects.append(str(obj))
        cmd = ([linker, "/NOLOGO", *objects, "/OUT:" + str(output)]
               if mode == "msvc" else [linker, *objects, "-o", str(output)])
        step = run_command(cmd, td, timeout)
        step["stage"] = "link"
        steps.append(step)
        ok = not step["timed_out"] and step["exit_code"] == 0 and output.is_file()
        return {"ok": ok, "steps": steps, "output": str(output) if ok else None,
                "failure": None if ok else "link"}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", action="append", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--mode", choices=["msvc", "gnu"], required=True)
    p.add_argument("--compiler", required=True)
    p.add_argument("--linker", required=True)
    p.add_argument("--timeout", type=float, default=60)
    args = p.parse_args()
    try:
        result = build(args.source, args.output, args.compiler, args.linker,
                       args.timeout, args.mode)
    except Exception as exc:
        result = {"ok": False, "failure": "infrastructure", "error": str(exc)}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())

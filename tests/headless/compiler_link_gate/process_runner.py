"""Local compiler/linker subprocess runner; no shell or model dependency.

Windows uses a Job Object with kill-on-close so a timeout also stops descendants.
stdout and stderr are drained concurrently to avoid full-pipe deadlocks.
"""
from __future__ import annotations
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class RunResult:
    command: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    elapsed_seconds: float


def _windows_job(process: subprocess.Popen[bytes]):
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    class BasicLimit(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64),
                    ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]
    class IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                     "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BasicLimit),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        info = ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        return job, kernel.CloseHandle
    except BaseException:
        kernel.CloseHandle(job)
        raise


def run(command: Sequence[str], *, cwd: str | Path, timeout: float = 30.0,
        max_output_bytes: int = 8 * 1024 * 1024) -> RunResult:
    if not command or timeout <= 0 or max_output_bytes < 1:
        raise ValueError("command, positive timeout and output limit required")
    if any(not isinstance(arg, str) or not arg for arg in command):
        raise ValueError("command must be nonempty strings")
    start = time.monotonic()
    creationflags = subprocess.CREATE_SUSPENDED if os.name == "nt" else 0
    process = subprocess.Popen(list(command), cwd=str(cwd), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               shell=False, creationflags=creationflags,
                               start_new_session=(os.name != "nt"))
    job = None
    close_job = None
    try:
        if os.name == "nt":
            try:
                job, close_job = _windows_job(process)
            except BaseException:
                process.kill()
                process.wait()
                raise
            import ctypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.ResumeThread.argtypes = [ctypes.c_void_p]
            kernel.ResumeThread.restype = ctypes.c_uint32
            if kernel.ResumeThread(process._thread) == 0xffffffff:
                raise ctypes.WinError(ctypes.get_last_error())

        buffers = [bytearray(), bytearray()]
        def drain(stream, index):
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                if len(buffers[index]) < max_output_bytes:
                    buffers[index].extend(chunk[:max_output_bytes - len(buffers[index])])
        threads = [threading.Thread(target=drain, args=(pipe, index), daemon=True)
                   for index, pipe in enumerate((process.stdout, process.stderr))]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            if os.name == "nt":
                close_job(job)
                job = None
            else:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("output reader did not terminate")
        return RunResult(tuple(command), process.returncode, bytes(buffers[0]),
                         bytes(buffers[1]), timed_out, time.monotonic() - start)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if job is not None:
            close_job(job)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

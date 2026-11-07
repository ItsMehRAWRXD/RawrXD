"""Bounded, concurrent subprocess capture and deadline-enforced process-tree cleanup.

No shell expansion, never accepts a command string, never stores unbounded logs.
Used by the native compiler, builder and linker adapter.
"""
import os
import signal
import subprocess
import threading
import time


class ProcessResult:
    def __init__(self, *, returncode, stdout, stderr, timed_out=False, output_limit=False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.output_limit = output_limit


def _terminate_group(proc):
    if os.name == "nt":
        # taskkill /T cleans the full descendant tree when a compiler launches
        # cmd.exe, link.exe, msbuild, or other worker processes.
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           stdin=subprocess.DEVNULL, timeout=4, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


def run_process(argv, timeout, *, tail_bytes=32768, max_stream_bytes=16 * 1024 * 1024):
    """Execute argv with separated stdout/stderr and hard deadline.

    The captured output contains the most recent tail_bytes of each stream.
    If either stream exceeds max_stream_bytes, kill the process tree and fail.
    """
    if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(v, str) for v in argv):
        raise ValueError("argv must be a nonempty list of strings")
    if timeout <= 0 or tail_bytes <= 0 or max_stream_bytes <= tail_bytes:
        raise ValueError("invalid output limits or timeout")
    popen_opts = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                  "stderr": subprocess.PIPE, "bufsize": 0}
    if os.name == "nt":
        popen_opts["creationflags"] = (subprocess.CREATE_NEW_PROCESS_GROUP |
                                        getattr(subprocess, "CREATE_NO_WINDOW", 0))
    else:
        popen_opts["start_new_session"] = True
    process = subprocess.Popen(list(argv), **popen_opts)
    tails = [bytearray(), bytearray()]
    volumes = [0, 0]
    overflow = threading.Event()
    reader_errors = []

    def drain(stream, index):
        try:
            while True:
                block = stream.read(16384)
                if not block:
                    break
                volumes[index] += len(block)
                if volumes[index] > max_stream_bytes:
                    overflow.set()
                tails[index].extend(block)
                if len(tails[index]) > tail_bytes:
                    del tails[index][:-tail_bytes]
        except (OSError, ValueError) as exc:
            reader_errors.append(str(exc))

    readers = [threading.Thread(target=drain, args=(process.stdout, 0), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1), daemon=True)]
    for t in readers:
        t.start()
    timed_out = False
    output_limited = False
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None:
            if overflow.is_set():
                output_limited = True
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            time.sleep(min(0.025, max(0.001, deadline - time.monotonic())))
        if timed_out or output_limited:
            _terminate_group(process)
        process.wait(timeout=5)
        for t in readers:
            t.join(timeout=2)
        if any(t.is_alive() for t in readers):
            # A leaked descendant is still holding one of our pipes open.
            _terminate_group(process)
            for t in readers:
                t.join(timeout=2)
            if any(t.is_alive() for t in readers):
                output_limited = True
        if overflow.is_set():
            output_limited = True
        if reader_errors:
            output_limited = True
    except BaseException:
        _terminate_group(process)
        raise
    finally:
        for stream in (process.stdout, process.stderr):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass
    stdout = bytes(tails[0]).decode("utf-8", errors="replace")
    stderr = bytes(tails[1]).decode("utf-8", errors="replace")
    return ProcessResult(returncode=124 if timed_out else (125 if output_limited else process.returncode),
                         stdout=stdout, stderr=stderr, timed_out=timed_out, output_limit=output_limited)

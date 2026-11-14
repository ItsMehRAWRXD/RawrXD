#!/usr/bin/env python3
"""P4 ConPTY start/output/stop remasure. PROMOTE=0 CROSS_SHA=0."""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(r"G:\~dev\rawrxd")
# Private product path: termctl embeds pipe-retry client (CROSS_SHA=0 tip pin held).
EXE = ROOT / "build_ninja" / "bin" / "rawr_termctl.exe"
TIP_EXE = ROOT / "build_ninja" / "bin" / "rawr_gpufwd_15A119D1.exe"
HOST = ROOT / "build-fd" / "bin" / "rawr_terminal_host.exe"
PACK = ROOT / "evidence" / "PRODUCTION_MATURITY_TOP25_001" / "P4_CONPTY_RELIABILITY_001"
N = 5
MARKER = "CONPTY_MARK_P4_R94"


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()


def invoke_term(args: list[str], base: Path, timeout_s: float = 60.0) -> int:
    out_f, err_f, exit_f = base.with_suffix(".out.txt"), base.with_suffix(".err.txt"), base.with_suffix(".exit.txt")
    try:
        # termctl: start|tail|stop|list|killall (no leading "term")
        # tip rawr: term start|...
        cmd = [str(EXE)]
        if EXE.name.lower().startswith("rawr_gpufwd") or EXE.name.lower() == "rawr.exe":
            cmd.append("term")
        cmd.extend(args)
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            cwd=str(ROOT),
        )
        out_f.write_text(p.stdout or "", encoding="utf-8", errors="replace")
        err_f.write_text(p.stderr or "", encoding="utf-8", errors="replace")
        exit_f.write_text(str(p.returncode), encoding="utf-8")
        return int(p.returncode)
    except subprocess.TimeoutExpired as e:
        out_f.write_text((e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), encoding="utf-8")
        err = (e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        err_f.write_text(err + "\nTIMEOUT_KILL=1\n", encoding="utf-8")
        exit_f.write_text("-1", encoding="utf-8")
        return -1


def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def main() -> int:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PACK / f"run_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    exe_sha = sha256(EXE)
    tip_sha = sha256(TIP_EXE) if TIP_EXE.exists() else "ABSENT"
    host_sha = sha256(HOST)

    # Ensure stale host is replaced by rebuilt binary path used by tip CLI.
    invoke_term(["killall"], out_dir / "pre_killall")
    time.sleep(0.4)

    start_ok = out_ok = stop_ok = cleanup_ok = idem_ok = 0
    trials: list[str] = []

    for i in range(1, N + 1):
        name = f"p4r{i}"
        td = out_dir / f"trial_{i:02d}"
        td.mkdir(parents=True, exist_ok=True)
        child = f"echo {MARKER} & ping -n 20 127.0.0.1 >nul"
        start_exit = invoke_term(
            ["start", name, "--", "cmd", "/c", child], td / "start"
        )
        start_err = read_text(td / "start.err.txt")
        start_flag = 1 if start_exit == 0 and re.search(r"\+OK\s+name=", start_err) else 0
        if start_flag:
            start_ok += 1
        m = re.search(r"pid=(\d+)", start_err)
        pid_str = m.group(1) if m else ""
        time.sleep(0.9)

        tail_exit = invoke_term(["tail", name], td / "tail")
        tail_out = read_text(td / "tail.out.txt")
        marker_hit = 1 if MARKER in tail_out else 0
        out_flag = 1 if marker_hit or (tail_exit == 0 and tail_out.strip()) else 0
        if out_flag:
            out_ok += 1

        stop_exit = invoke_term(["stop", name], td / "stop")
        stop_err = read_text(td / "stop.err.txt")
        stop_flag = 1 if stop_exit == 0 and re.search(r"\+OK\s+stopped=1", stop_err) else 0
        if stop_flag:
            stop_ok += 1

        list_exit = invoke_term(["list"], td / "list")
        list_out = read_text(td / "list.out.txt")
        cleanup_flag = 0
        if list_exit == 0:
            if name not in list_out:
                cleanup_flag = 1
            elif re.search(re.escape(name) + r".*alive=0", list_out):
                cleanup_flag = 1
        if cleanup_flag:
            cleanup_ok += 1

        idem_exit = invoke_term(["stop", name], td / "idem_stop")
        idem_err = read_text(td / "idem_stop.err.txt")
        idem_flag = 0
        if idem_exit == 0 and "+OK" in idem_err:
            idem_flag = 1
        elif re.search(r"not found|stopped=0|absent|unknown", idem_err, re.I):
            idem_flag = 1
        if idem_flag:
            idem_ok += 1

        list_one = " | ".join(list_out.splitlines()).strip()
        line = (
            f"trial={i} name={name} start_exit={start_exit} start_ok={start_flag} pid={pid_str} "
            f"out_exit={tail_exit} out_ok={out_flag} marker={marker_hit} "
            f"stop_exit={stop_exit} stop_ok={stop_flag} cleanup_ok={cleanup_flag} "
            f"list={list_one} idem_stop_exit={idem_exit} idem_stop_ok={idem_flag}"
        )
        (td / "RESULT.txt").write_text(line + "\n", encoding="utf-8")
        trials.append(line)
        print(line, flush=True)
        time.sleep(0.25)

    post = invoke_term(["killall"], out_dir / "post_killall")
    host_alive = 1 if post == 0 else 0

    def rate(x: int) -> float:
        return round(100.0 * x / N, 1)

    result = "FAIL"
    if start_ok == N and out_ok == N and stop_ok == N and cleanup_ok == N and idem_ok == N:
        result = "PASS"

    asof = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    summary = f"""P4_CONPTY_RELIABILITY_001
ASOF_LOCAL={asof}-05:00
STAMP={stamp}
PROMOTE=0 CERTIFIED=0 CROSS_SHA_CREDIT=0 TIP_CLIMB=HOLD INVENT_PASS=0
NOT_RUN!=PASS
CERT_GATE_RESULT_UNCHANGED=1
CERT_BIND=NOT_RUN

EXE=build_ninja\\bin\\rawr_termctl.exe
EXE_SHA256={exe_sha}
LANE=PRIVATE_TERMCTL
TIP_EXE=build_ninja\\bin\\rawr_gpufwd_15A119D1.exe
TIP_EXE_SHA256={tip_sha}
TIP_PIN=HOLD_15A119
TIP_ABSORB=N
JOINT_MAY_SHOW=30DCB4
HOST=build-fd\\bin\\rawr_terminal_host.exe
HOST_SHA256={host_sha}
HOST_REBUILD=R94B_IDEMPOTENT_STOP_PLUS_CLIENT_RETRY
FIX=supervisor stop absent=>true; TermClientTransact pipe retry

N_TRIALS={N}
START_OK={start_ok}/{N} RATE={rate(start_ok)}%
OUTPUT_OK={out_ok}/{N} RATE={rate(out_ok)}%
STOP_OK={stop_ok}/{N} RATE={rate(stop_ok)}%
CLEANUP_OK={cleanup_ok}/{N} RATE={rate(cleanup_ok)}%
IDEM_STOP_OK={idem_ok}/{N} RATE={rate(idem_ok)}%
STOP_SUCCESS_RATE={rate(stop_ok)}%
HOST_ALIVE_AFTER_KILLALL={host_alive}

MARKER={MARKER}
COMMAND=termctl start <name> -- cmd /c echo MARKER & ping -n 20 127.0.0.1 >nul
SEQUENCE=start -> sleep900ms -> tail -> stop -> list cleanup -> idempotent stop

RESULT={result}
NOTE=Private termctl+host remasure. Tip 15A119 RO. Does NOT set cert gate 05.05 PASS. CROSS_SHA=0.
RUN_DIR=evidence/PRODUCTION_MATURITY_TOP25_001/P4_CONPTY_RELIABILITY_001/run_{stamp}
"""
    (out_dir / "SUMMARY.txt").write_text(summary, encoding="utf-8")
    (out_dir / "TRIALS.txt").write_text("\n".join(trials) + "\n", encoding="utf-8")
    (PACK / "LATEST_SUMMARY.txt").write_text(summary, encoding="utf-8")
    (PACK / "SEAL.txt").write_text(summary, encoding="utf-8")
    print(summary, flush=True)
    print(f"OUTDIR={out_dir}", flush=True)
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

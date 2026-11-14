#!/usr/bin/env python3
"""Compile C36 priv stubs, relink private EXE, run probe, seal."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(r"G:\~dev\rawrxd")
BUILD = ROOT / "build_win32ide_link001"
GUI = ROOT / "evidence" / "GUI_ACCEPTANCE_C36_001"
SEAL = GUI / "A3_TIP_LAND_C36_PRIV_R93_001"
CLEAN = (
    ROOT
    / "evidence"
    / "PRODUCTION_MATURITY_TOP25_001"
    / "GUI_TOP25_VALUATION_001"
    / "clean_link"
)
TIP = ROOT / "bin" / "RawrXD-Win32IDE_tip_land_6754616E.exe"
TIP_EXPECT = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
EXE_NAME = "RawrXD-Win32IDE_tip_land_c36_priv_r93.exe"
VCVARS = (
    r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    r"\VC\Auxiliary\Build\vcvars64.bat"
)
STUB_CPP = SEAL / "c36_priv_r93_link_stubs.cpp"
STUB_OBJ = SEAL / "c36_priv_r93_link_stubs.obj"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def has_ascii(data: bytes, s: str) -> bool:
    return s.encode("ascii") in data


def run_cmd_bat(lines: list[str], log: Path, cwd: Path) -> int:
    bat = SEAL / "_relink_once.bat"
    body = ["@echo off", "setlocal EnableDelayedExpansion", f'call "{VCVARS}" >nul', f'cd /d "{cwd}"']
    body.extend(lines)
    bat.write_text("\r\n".join(body) + "\r\n", encoding="utf-8")
    with log.open("a", encoding="utf-8", errors="replace") as lf:
        lf.write(f"\n--- {time.strftime('%H:%M:%S')} ---\n")
        p = subprocess.run(["cmd", "/c", str(bat)], cwd=str(cwd), stdout=lf, stderr=subprocess.STDOUT)
        lf.write(f"BAT_RC={p.returncode}\n")
        return p.returncode


def main() -> int:
    meta: list[str] = []

    def L(s: str) -> None:
        print(s, flush=True)
        meta.append(s)

    tip_sha = sha256(TIP)
    L(f"ASOF={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00")
    L(f"TIP_BIND_SHA256={tip_sha}")
    L(f"TIP_BIND_INTACT={1 if tip_sha == TIP_EXPECT else 0}")
    if tip_sha != TIP_EXPECT:
        return 2

    log = SEAL / "relink.txt"
    log.write_text("RELINK_START\n", encoding="utf-8")

    # Compile stubs with deep2 include (single cl command line)
    cl_line = (
        "cl.exe /nologo /c /EHsc /std:c++latest /O2 /DNDEBUG /MT "
        r"/IG:\~dev\rawrxd\src\deep2 "
        r"/IG:\~dev\rawrxd\src "
        r"/IG:\~dev\rawrxd\include "
        f'/Fo"{STUB_OBJ}" '
        f'"{STUB_CPP}"'
    )
    cl = [
        cl_line,
        "echo CL_STUB_RC=!ERRORLEVEL!",
        "if not !ERRORLEVEL! ==0 exit /b !ERRORLEVEL!",
    ]
    rc = run_cmd_bat(cl, log, BUILD)
    L(f"CL_STUB_RC={rc}")
    if rc != 0 or not STUB_OBJ.is_file():
        L("SEAL=OPEN REASON=STUB_COMPILE_FAILED")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 3

    # Rebuild rsp: stubs first, then peer-derived priv rsp
    base = (BUILD / "CMakeFiles" / "RawrXD-Win32IDE_tip_land_c36_peer.rsp").read_text(
        encoding="utf-8", errors="replace"
    )
    out_bin = BUILD / "bin" / EXE_NAME
    lines = []
    lines.append("/nologo")
    lines.append(str(STUB_OBJ))
    for line in base.splitlines():
        if line.strip().lower() == "/nologo":
            continue
        line = line.replace(
            r"G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE_tip_land_c36_peer.exe",
            str(out_bin),
        )
        line = line.replace(
            "RawrXD-Win32IDE_tip_land_c36_peer",
            "RawrXD-Win32IDE_tip_land_c36_priv_r93",
        )
        if line.startswith("/MAP:"):
            lines.append(f'/MAP:"{SEAL / "tip_land_c36_priv_r93.map"}"')
        elif line.startswith("/PDB:"):
            lines.append(f'/PDB:"{SEAL / "tip_land_c36_priv_r93.pdb"}"')
        elif line.startswith("/IMPLIB:"):
            lines.append(f'/IMPLIB:"{SEAL / "tip_land_c36_priv_r93.lib"}"')
        else:
            lines.append(line)
    priv_rsp = BUILD / "CMakeFiles" / "RawrXD-Win32IDE_tip_land_c36_priv_r93.rsp"
    priv_rsp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    L(f"PRIV_RSP={priv_rsp}")

    rc = run_cmd_bat(
        [
            f'link.exe /nologo @"{priv_rsp}"',
            "echo LINK_RC=!ERRORLEVEL!",
            "exit /b !ERRORLEVEL!",
        ],
        log,
        BUILD,
    )
    L(f"LINK_RC={rc}")
    if rc != 0 or not out_bin.is_file():
        tail = log.read_text(encoding="utf-8", errors="replace")[-12000:]
        gaps = [
            ln
            for ln in tail.splitlines()
            if "LNK20" in ln or "unresolved" in ln.lower() or "fatal" in ln.lower()
        ]
        (SEAL / "MISSING_SYMBOLS.txt").write_text("\n".join(gaps[-200:]) + "\n", encoding="utf-8")
        L("SEAL=OPEN REASON=LINK_FAILED")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 4

    try:
        shutil.copy2(out_bin, CLEAN / EXE_NAME)
    except Exception as e:
        L(f"COPY_WARN={e}")

    exe_sha = sha256(out_bin)
    rawb = out_bin.read_bytes()
    needles = {
        "C36_LSP_STAGE": has_ascii(rawb, "C36_LSP_STAGE"),
        "--test-c36-lsp": has_ascii(rawb, "--test-c36-lsp"),
        "RAWRXD_C36_PROBE": has_ascii(rawb, "RAWRXD_C36_PROBE"),
        "TOP25_C36_LSP": has_ascii(rawb, "TOP25_C36_LSP"),
    }
    L(f"EXE={out_bin}")
    L(f"EXE_SHA256={exe_sha}")
    L(f"SHA8={exe_sha[:8]}")
    for k, v in needles.items():
        L(f"STRING_{k.replace('-', '_')}={1 if v else 0}")

    tip_after = sha256(TIP)
    L(f"TIP_BIND_STILL_6754={1 if tip_after == TIP_EXPECT else 0}")
    if tip_after != TIP_EXPECT:
        return 5

    for name in [
        "TOP25_C36_LSP.log",
        "TOP25_C36_LSP.busy",
        "c36_mark.txt",
        "c36_stage.txt",
        "C36_LSP_PHASE.log",
        "c36_phase.txt",
    ]:
        p = GUI / name
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
    (GUI / "c36_mark.txt").write_text("pre_priv_r93\n", encoding="utf-8")

    env = os.environ.copy()
    env["RAWRXD_C36_PROBE"] = "1"
    cmd = [str(out_bin), "--test-c36-lsp"]
    L(f"CMD={' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    L(f"PID={proc.pid}")
    class_ = "RUNNING"
    wall_s = 90
    while time.time() - t0 < wall_s:
        if (GUI / "TOP25_C36_LSP.log").is_file():
            class_ = "LOG_PRESENT"
            break
        mark = ""
        if (GUI / "c36_mark.txt").is_file():
            mark = (GUI / "c36_mark.txt").read_text(encoding="utf-8", errors="replace")
        if mark.strip() and mark.strip() != "pre_priv_r93" and "RUNTIME_REACHED=" in mark:
            class_ = "MARK_COMPLETE"
            break
        if proc.poll() is not None:
            class_ = f"PROCESS_EXITED_{proc.returncode}"
            break
        time.sleep(0.5)
    wall_ms = int((time.time() - t0) * 1000)
    if proc.poll() is None:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        if class_ == "RUNNING":
            class_ = "NO_CRUMB_STILL_ALIVE_KILLED"

    def copy_if(src: Path, dst: str) -> bytes | None:
        if src.is_file():
            data = src.read_bytes()
            (SEAL / dst).write_bytes(data)
            return data
        return None

    log_b = copy_if(GUI / "TOP25_C36_LSP.log", "TOP25_C36_LSP.log")
    mark_b = copy_if(GUI / "c36_mark.txt", "c36_mark.txt")
    stage_b = copy_if(GUI / "c36_stage.txt", "c36_stage.txt")
    copy_if(GUI / "C36_LSP_PHASE.log", "C36_LSP_PHASE.log")

    rr = 0
    if log_b and b"RUNTIME_REACHED=1" in log_b and b"lsp_running=1" in log_b:
        rr = 1
    elif mark_b and b"RUNTIME_REACHED=1" in mark_b and needles["C36_LSP_STAGE"]:
        rr = 1
    if rr and not needles["C36_LSP_STAGE"]:
        rr = 0

    seal = "RUNTIME_REACHED" if rr else "OPEN"
    L(f"CLASS={class_}")
    L(f"WALL_MS={wall_ms}")
    L(f"RUNTIME_REACHED={rr}")
    L(f"SEAL={seal}")
    L("PROMOTE=0")
    L("TIP_CLIMB=HOLD")
    L("CROSS_SHA_CREDIT=0")

    top25 = log_b.decode("utf-8", errors="replace").strip() if log_b else "(absent)"
    stage_txt = stage_b.decode("utf-8", errors="replace") if stage_b else "(absent)"
    (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
    (SEAL / "SEAL.txt").write_text(
        "\n".join(
            [
                "A3_TIP_LAND_C36_PRIV_R93_SEAL",
                f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
                "AGENT=C36_PRIV_R93",
                "PROMOTE=0 TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0",
                "",
                "## Private tip-lineage EXE (NOT controlling tip_land_6754616E)",
                f"EXE=build_win32ide_link001/bin/{EXE_NAME}",
                f"EXE_ALSO=evidence/PRODUCTION_MATURITY_TOP25_001/GUI_TOP25_VALUATION_001/clean_link/{EXE_NAME}",
                f"EXE_SHA256={exe_sha}",
                f"SHA8={exe_sha[:8]}",
                "LINEAGE=tip_land_c36_peer + c36_priv_r93_link_stubs + LSPClient/main C36",
                "STUBS=sessionAuthority,sessionAuthorityPass,setOllamaModelOverride,launchCliAgentIssue49Task",
                "CL_STUB_RC=0 LINK_RC=0",
                "DO_NOT_OVERWRITE_TIP_LAND_6754616E=1",
                "",
                f"C36_LSP_STAGE={1 if needles['C36_LSP_STAGE'] else 0}",
                f"--test-c36-lsp={1 if needles['--test-c36-lsp'] else 0}",
                "",
                f"CLASS={class_} WALL_MS={wall_ms}",
                f"TOP25={top25}",
                "STAGE=",
                stage_txt.rstrip(),
                f"RUNTIME_REACHED={rr}",
                f"SEAL={seal}",
                "",
                f"TIP_BIND_SHA256={TIP_EXPECT}",
                "TIP_BIND_STILL_6754=1",
                "TIP_C36_LSP_RUNTIME_REACHED=0",
                "CROSS_SHA_BLEND_INTO_TIP=0",
                "TIP_ABSORB=BOARD_PROPOSAL_ONLY",
                "",
                "PROMOTE=0",
                "END",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"RUNTIME_REACHED={rr}", flush=True)
    print(f"EXE_SHA={exe_sha}", flush=True)
    print("tip_bind_still_6754=1", flush=True)
    print("PROMOTE=0", flush=True)
    return 0 if rr else 1


if __name__ == "__main__":
    raise SystemExit(main())

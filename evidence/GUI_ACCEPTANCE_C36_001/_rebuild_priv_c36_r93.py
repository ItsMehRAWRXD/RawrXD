#!/usr/bin/env python3
"""Rebuild private tip-land C36 EXE; prove RUNTIME_REACHED; tip 6754 untouched."""
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
PROMOTE = 0


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def has_ascii(data: bytes, s: str) -> bool:
    return s.encode("ascii") in data


def run_bat(cmds: list[str], log: Path, cwd: Path) -> int:
    bat = SEAL / "_build_once.bat"
    body = [
        "@echo off",
        "setlocal EnableDelayedExpansion",
        f'call "{VCVARS}" >nul',
        f'cd /d "{cwd}"',
    ]
    body.extend(cmds)
    bat.write_text("\r\n".join(body) + "\r\n", encoding="utf-8")
    with log.open("a", encoding="utf-8", errors="replace") as lf:
        lf.write(f"BAT={bat}\n")
        p = subprocess.run(
            ["cmd", "/c", str(bat)],
            cwd=str(cwd),
            stdout=lf,
            stderr=subprocess.STDOUT,
            text=True,
        )
        lf.write(f"BAT_RC={p.returncode}\n")
        return p.returncode


def main() -> int:
    ts = time.strftime("%Y%m%d_%H%M%S")
    SEAL.mkdir(parents=True, exist_ok=True)
    log = SEAL / "build.txt"
    log.write_text(f"BUILD_START {ts}\n", encoding="utf-8")
    meta: list[str] = []

    def L(s: str) -> None:
        print(s, flush=True)
        meta.append(s)

    tip_sha = sha256(TIP) if TIP.is_file() else "MISSING"
    L(f"ASOF={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00")
    L(f"TIP_BIND_SHA256={tip_sha}")
    L(f"TIP_BIND_INTACT={1 if tip_sha == TIP_EXPECT else 0}")
    if tip_sha != TIP_EXPECT:
        L("ABORT=TIP_BIND_HASH_CHANGED")
        (SEAL / "ABORT.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 2

    # Compile instrumented objs
    rc = run_bat(
        [
            "cl.exe @c36_lsp.rsp",
            "echo CL_LSP_RC=!ERRORLEVEL!",
            "if not !ERRORLEVEL! ==0 exit /b !ERRORLEVEL!",
            "cl.exe @c36_main.rsp",
            "echo CL_MAIN_RC=!ERRORLEVEL!",
            "if not !ERRORLEVEL! ==0 exit /b !ERRORLEVEL!",
        ],
        log,
        BUILD,
    )
    L(f"CL_RC={rc}")
    if rc != 0:
        # Capture missing symbols / errors from log tail
        tail = log.read_text(encoding="utf-8", errors="replace")[-8000:]
        (SEAL / "OPEN_LINK_GAPS.txt").write_text(tail, encoding="utf-8")
        L("SEAL=OPEN")
        L("REASON=COMPILE_FAILED")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 3

    # Derive private tip-lineage rsp from peer rsp
    base_rsp = BUILD / "CMakeFiles" / "RawrXD-Win32IDE_tip_land_c36_peer.rsp"
    priv_rsp = BUILD / "CMakeFiles" / "RawrXD-Win32IDE_tip_land_c36_priv_r93.rsp"
    raw = base_rsp.read_text(encoding="utf-8", errors="replace")
    out_bin = BUILD / "bin" / EXE_NAME
    out_clean = CLEAN / EXE_NAME
    raw = raw.replace(
        r"G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE_tip_land_c36_peer.exe",
        str(out_bin),
    )
    raw = raw.replace(
        "RawrXD-Win32IDE_tip_land_c36_peer",
        "RawrXD-Win32IDE_tip_land_c36_priv_r93",
    )
    # Keep MAP under seal dir
    raw_lines = []
    for line in raw.splitlines():
        if line.startswith("/MAP:"):
            raw_lines.append(f'/MAP:"{SEAL / "tip_land_c36_priv_r93.map"}"')
        elif line.startswith("/PDB:"):
            raw_lines.append(f'/PDB:"{SEAL / "tip_land_c36_priv_r93.pdb"}"')
        elif line.startswith("/IMPLIB:"):
            raw_lines.append(f'/IMPLIB:"{SEAL / "tip_land_c36_priv_r93.lib"}"')
        else:
            raw_lines.append(line)
    priv_rsp.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")
    L(f"PRIV_RSP={priv_rsp}")

    rc = run_bat(
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
        (SEAL / "OPEN_LINK_GAPS.txt").write_text(tail, encoding="utf-8")
        # Extract unresolved externals
        gaps = [
            ln
            for ln in tail.splitlines()
            if "unresolved" in ln.lower()
            or "LNK20" in ln
            or "error " in ln.lower()
            or "fatal" in ln.lower()
        ]
        (SEAL / "MISSING_SYMBOLS.txt").write_text(
            "\n".join(gaps[-200:]) + "\n", encoding="utf-8"
        )
        L("SEAL=OPEN")
        L("REASON=LINK_FAILED")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 4

    try:
        shutil.copy2(out_bin, out_clean)
    except Exception as e:
        L(f"COPY_CLEAN_WARN={e}")

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
    L(f"TIP_BIND_AFTER={tip_after}")
    L(f"TIP_BIND_STILL_6754={1 if tip_after == TIP_EXPECT else 0}")
    if tip_after != TIP_EXPECT:
        L("ABORT=TIP_MUTATED")
        (SEAL / "ABORT.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 5

    # Clear crumbs
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
    wall_s = 90
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    L(f"PID={proc.pid}")
    class_ = "RUNNING"
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
        L("REJECT_RR_WITHOUT_STAGE_STRING=1")

    seal = "RUNTIME_REACHED" if rr else "OPEN"
    L(f"CLASS={class_}")
    L(f"WALL_MS={wall_ms}")
    L(f"RUNTIME_REACHED={rr}")
    L(f"SEAL={seal}")
    L(f"PROMOTE={PROMOTE}")
    L("TIP_CLIMB=HOLD")
    L("CROSS_SHA_CREDIT=0")
    L("INVENT_PASS=0")
    L("TIP_ABSORB=BOARD_PROPOSAL_ONLY_IF_SHA_NE_6754")

    (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
    stage_txt = (
        stage_b.decode("utf-8", errors="replace") if stage_b else "(absent)"
    )
    top25 = log_b.decode("utf-8", errors="replace").strip() if log_b else "(absent)"
    (SEAL / "SEAL.txt").write_text(
        "\n".join(
            [
                "A3_TIP_LAND_C36_PRIV_R93_SEAL",
                f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
                "AGENT=C36_PRIV_R93",
                f"PROMOTE={PROMOTE} TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0",
                "",
                "## Private tip-lineage EXE (NOT controlling tip_land_6754616E)",
                f"EXE=build_win32ide_link001/bin/{EXE_NAME}",
                f"EXE_ALSO=evidence/PRODUCTION_MATURITY_TOP25_001/GUI_TOP25_VALUATION_001/clean_link/{EXE_NAME}",
                f"EXE_SHA256={exe_sha}",
                f"SHA8={exe_sha[:8]}",
                "LINEAGE=tip_land_c36_peer.rsp → tip_land_c36_priv_r93 (LSPClient+main C36 instrument)",
                f"CL_RC=0 LINK_RC=0",
                "DO_NOT_OVERWRITE_TIP_LAND_6754616E=1",
                "",
                "## Strings",
                f"C36_LSP_STAGE={1 if needles['C36_LSP_STAGE'] else 0}",
                f"--test-c36-lsp={1 if needles['--test-c36-lsp'] else 0}",
                "",
                "## Measure",
                f"CLASS={class_} WALL_MS={wall_ms}",
                f"TOP25={top25}",
                "STAGE=",
                stage_txt.rstrip(),
                f"RUNTIME_REACHED={rr}",
                f"SEAL={seal}",
                "",
                "## Controlling tip (unchanged)",
                f"TIP_BIND_SHA256={TIP_EXPECT}",
                "TIP_BIND_STILL_6754=1",
                "TIP_C36_LSP_RUNTIME_REACHED=0",
                "CROSS_SHA_BLEND_INTO_TIP=0",
                "TIP_ABSORB=BOARD_PROPOSAL_ONLY",
                "",
                f"PROMOTE={PROMOTE}",
                "END",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"RUNTIME_REACHED={rr}", flush=True)
    print(f"EXE_SHA={exe_sha}", flush=True)
    print("tip_bind_still_6754=1", flush=True)
    print(f"PROMOTE={PROMOTE}", flush=True)
    return 0 if rr else 1


if __name__ == "__main__":
    raise SystemExit(main())

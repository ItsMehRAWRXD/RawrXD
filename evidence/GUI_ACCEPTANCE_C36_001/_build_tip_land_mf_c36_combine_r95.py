#!/usr/bin/env python3
"""Private tip-land COMBINE: ProductRunDecode eng-pin (MF/qdim099) + C36 instrument.
Remeasure exclusive MF 4/4 + C36 RUNTIME_REACHED on SAME EXE_SHA.
Tip 6754616E RO. PROMOTE=0. BOARD_PROPOSAL_ONLY. Fail-closed on regress.
"""
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
SEAL = GUI / "A3_TIP_LAND_MF_C36_COMBINE_R95_001"
CLEAN = (
    ROOT
    / "evidence"
    / "PRODUCTION_MATURITY_TOP25_001"
    / "GUI_TOP25_VALUATION_001"
    / "clean_link"
)
GPU = (
    ROOT
    / "evidence"
    / "PRODUCTION_MATURITY_TOP25_001"
    / "GUI_TOP25_VALUATION_001"
    / "gpu"
)
OBJ084 = CLEAN / "obj084_mars_keep"
OBJ079 = CLEAN / "obj079_avfix"
OBJ075 = CLEAN / "obj075_gemma_seal"
TIP = ROOT / "bin" / "RawrXD-Win32IDE_tip_land_6754616E.exe"
TIP_EXPECT = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
EXE_NAME = "RawrXD-Win32IDE_tip_land_mf_c36_combine_r95.exe"
VCVARS = (
    r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
    r"\VC\Auxiliary\Build\vcvars64.bat"
)
INCLUDE_DECODE = (
    "/INCLUDE:?RunDecodeStream@product_run@rawr@@YAXAEAUProductRuntime@12@"
    "PEBDIAEBV?$function@$$A6A_NAEBV?$basic_string@DU?$char_traits@D@std@@"
    "V?$allocator@D@2@@std@@@Z@std@@AEAUResult@12@AEAH@Z"
)
# Combine base = proven MF link099d (eng-pin + /FORCE:MULTIPLE + InferenceEngine.lib).
# C36 instrument already in CMake LSPClient/main objs used by that rsp.
MF_RSP = CLEAN / "obj099_decode_odr" / "link099d.rsp"
DROP_SUBSTR: list[str] = []
FAMILIES = [
    ("llama32", ROOT / "models" / "llama3.2-3b-Q2_K.gguf"),
    ("gemma3", ROOT / "models" / "gemma3-1b-Q2_K.gguf"),
    ("phi3", ROOT / "models" / "phi3-mini-Q2_K.gguf"),
    ("tinyllama", ROOT / "models" / "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"),
]
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


def run_c36(exe: Path, meta: list[str]) -> int:
    def L(s: str) -> None:
        print(s, flush=True)
        meta.append(s)

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
    (GUI / "c36_mark.txt").write_text("pre_combine_r95\n", encoding="utf-8")
    env = os.environ.copy()
    env["RAWRXD_C36_PROBE"] = "1"
    cmd = [str(exe), "--test-c36-lsp"]
    L(f"C36_CMD={' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    L(f"C36_PID={proc.pid}")
    class_ = "RUNNING"
    while time.time() - t0 < 90:
        if (GUI / "TOP25_C36_LSP.log").is_file():
            class_ = "LOG_PRESENT"
            break
        mark = ""
        if (GUI / "c36_mark.txt").is_file():
            mark = (GUI / "c36_mark.txt").read_text(encoding="utf-8", errors="replace")
        if (
            mark.strip()
            and mark.strip() != "pre_combine_r95"
            and "RUNTIME_REACHED=" in mark
        ):
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
    rawb = exe.read_bytes()
    stage_str = has_ascii(rawb, "C36_LSP_STAGE")
    rr = 0
    if log_b and b"RUNTIME_REACHED=1" in log_b and b"lsp_running=1" in log_b:
        rr = 1
    elif mark_b and b"RUNTIME_REACHED=1" in mark_b and stage_str:
        rr = 1
    if rr and not stage_str:
        rr = 0
        L("REJECT_RR_WITHOUT_STAGE_STRING=1")
    L(f"C36_CLASS={class_}")
    L(f"C36_WALL_MS={wall_ms}")
    L(f"C36_RUNTIME_REACHED={rr}")
    if stage_b:
        (SEAL / "c36_stage.txt").write_bytes(stage_b)
    return rr


def clear_mf_env() -> None:
    for k in [
        "RAWRXD_ALLOW_GPU",
        "RAWR_FORCE_GPU",
        "RAWR_NO_CPU_FALLBACK",
        "RAWRXD_GPU_POLICY",
        "RAWRXD_HOST_DECODE",
        "RAWR_HOST_DECODE",
        "DEEP2_LIVE_POLICY",
        "DEEP2_LIVE_PATH",
        "DEEP2_DUALSTICK_ARM",
        "WEIGHT_BUDGET_MIB",
        "DEEP2_WEIGHT_BUDGET_MIB",
        "WEIGHT_BUDGET_INPUT",
        "RAWRXD_PRODUCT_STREAMER_ARM",
        "RAWRXD_PRODUCT_STREAMER_PREP",
        "RAWRXD_UNREVERSE_HOTPATCH",
        "GPU_POLICY",
        "RAWRXD_GPU_DEVICE",
        "RAWRXD_DEEP2_ALLOW_ELASTIC",
        "DEEP2_MARS",
        "RAWRXD_ENHANCE_SKIP",
        "RAWRXD_SCOREBOARD_PUMP",
        "DEEP2_STREAM_EMBD_SNAPSHOT",
    ]:
        os.environ.pop(k, None)


def run_mf_family(exe: Path, family: str, model: Path, exe_sha: str) -> dict:
    clear_mf_env()
    os.environ["RAWRXD_ALLOW_GPU"] = "1"
    os.environ["RAWR_FORCE_GPU"] = "1"
    os.environ["RAWR_NO_CPU_FALLBACK"] = "1"
    os.environ["RAWRXD_GPU_POLICY"] = "SOLO"
    os.environ["RAWRXD_HOST_DECODE"] = "0"
    os.environ["RAWR_HOST_DECODE"] = "0"
    os.environ["DEEP2_LIVE_POLICY"] = "OFF"
    os.environ["DEEP2_LIVE_PATH"] = "0"
    os.environ["DEEP2_DUALSTICK_ARM"] = "0"
    os.environ["RAWRXD_DEEP2_ALLOW_ELASTIC"] = "0"
    os.environ["DEEP2_MARS"] = "1"
    os.environ["DEEP2_KV_WORKING_SEQ"] = "2048"
    os.environ["RAWRXD_ENHANCE_SKIP"] = "torus,plasma,chamber,sov,medusa,nu,warmup,ckv,nvme"
    os.environ["WEIGHT_BUDGET_MIB"] = "8192"
    os.environ["WEIGHT_BUDGET_INPUT"] = "8192"
    os.environ["RAWRXD_PRODUCT_STREAMER_ARM"] = "1"
    os.environ["RAWRXD_PRODUCT_STREAMER_PREP"] = "1"
    stamp = time.strftime("%Y%m%d_%H%M%S")
    tag = f"ide_mf_combine_r95_{family}_{exe_sha[:16]}_{stamp}"
    gout = GPU / f"{tag}.out.txt"
    gerr = GPU / f"{tag}.err.txt"
    gmeta = GPU / f"{tag}.meta.txt"
    arg = (
        f'--headless --no-server --model "{model}" '
        f'--prompt "What is 2+2? Answer with one digit only." '
        f"--max-tokens 8 --vulkan"
    )
    t0 = time.time()
    proc = subprocess.run(
        f'"{exe}" {arg}',
        cwd=str(ROOT),
        shell=True,
        capture_output=True,
        text=True,
        timeout=600,
    )
    wall = int((time.time() - t0) * 1000)
    gout.write_text(proc.stdout or "", encoding="utf-8", errors="replace")
    gerr.write_text(proc.stderr or "", encoding="utf-8", errors="replace")
    both = (proc.stderr or "") + "\n" + (proc.stdout or "")
    tok = 0
    import re

    m = re.search(r"GENERATED_TOKENS[=:\s]+(\d+)", both)
    if m:
        tok = int(m.group(1))
    seh = 1 if re.search(r"PRODUCT_DEEP2_OPEN_SEH[=:\s]*1", both) else 0
    stream_seh = 1 if re.search(r"PRODUCT_DEEP2_INFER_STREAM_SEH[=:\s]*1", both) else 0
    pin = 1 if "DECODE_ENG_PIN=" in both else 0
    enter = 1 if "GENERATE_STREAM_ENTER=1" in both else 0
    surv = 1 if tok > 0 and seh == 0 and stream_seh == 0 else 0
    tip_post = sha256(TIP)
    lines = [
        f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
        f"ID={tag}",
        "LANE=MULTI_FAMILY_TIP_LAND_MF_C36_COMBINE_R95",
        f"FAMILY={family}",
        f"MODEL={model}",
        f"EXE={exe}",
        f"EXE_SHA256={exe_sha}",
        f"SHA16={exe_sha[:16]}",
        f"TIP_SHA256={tip_post}",
        f"TIP_STILL_6754={1 if tip_post == TIP_EXPECT else 0}",
        f"PRODUCT_DEEP2_OPEN_SEH={seh}",
        f"INFER_STREAM_SEH={stream_seh}",
        f"GENERATE_STREAM_ENTER={enter}",
        f"DECODE_ENG_PIN_SEEN={pin}",
        f"GENERATED_TOKENS={tok}",
        f"TOKEN_SURVIVED={surv}",
        f"PROCESS_EXIT={proc.returncode}",
        f"WALL_MS={wall}",
        f"PROMOTE={PROMOTE}",
        "TIP_CLIMB=HOLD",
        "INVENT_PASS=0",
        f"OUT={gout}",
        f"ERR={gerr}",
    ]
    gmeta.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (GPU / f"ide_mf_combine_r95_{family}_LATEST.meta.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    print(
        f"MF_{family} TOK={tok} SEH={seh} STREAM_SEH={stream_seh} PIN={pin} SURV={surv} EXIT={proc.returncode}",
        flush=True,
    )
    return {
        "family": family,
        "tok": tok,
        "seh": seh,
        "stream_seh": stream_seh,
        "pin": pin,
        "surv": surv,
        "exit": proc.returncode,
        "meta": gmeta,
    }


def main() -> int:
    ts = time.strftime("%Y%m%d_%H%M%S")
    SEAL.mkdir(parents=True, exist_ok=True)
    GPU.mkdir(parents=True, exist_ok=True)
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

    if not MF_RSP.is_file():
        L(f"ABORT=MISSING_MF_RSP {MF_RSP}")
        (SEAL / "ABORT.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 3

    raw = MF_RSP.read_text(encoding="utf-8", errors="replace")
    out_bin = BUILD / "bin" / EXE_NAME
    out_clean = CLEAN / EXE_NAME
    lines: list[str] = []
    for line in raw.splitlines():
        # Retarget private tip-land COMBINE OUT (keep MF eng-pin + C36 objs).
        line = line.replace(
            r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_gemma_qdim099.exe",
            str(out_bin),
        )
        line = line.replace(
            r"g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_gemma_qdim099.exe",
            str(out_bin),
        )
        if "/OUT:" in line.upper() and "qdim099" in line.lower():
            line = f'/OUT:"{out_bin}"'
        if line.startswith("/MAP:") or "/MAP:" in line[:5].upper():
            lines.append(f'/MAP:"{SEAL / "tip_land_mf_c36_combine_r95.map"}"')
            continue
        if line.startswith("/PDB:") or line.upper().startswith("/PDB:"):
            lines.append(f'/PDB:"{SEAL / "tip_land_mf_c36_combine_r95.pdb"}"')
            continue
        if line.startswith("/IMPLIB:"):
            lines.append(f'/IMPLIB:"{SEAL / "tip_land_mf_c36_combine_r95.lib"}"')
            continue
        lines.append(line)
    L(f"MF_RSP_BASE={MF_RSP}")
    L(f"OUT_BIN={out_bin}")
    L(f"OUT_CLEAN={out_clean}")

    priv_rsp = BUILD / "CMakeFiles" / "RawrXD-Win32IDE_tip_land_mf_c36_combine_r95.rsp"
    priv_rsp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    L(f"COMBINE_RSP={priv_rsp}")
    L(f"COMBINE_RSP_LINES={len(lines)}")

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
        tail = log.read_text(encoding="utf-8", errors="replace")[-16000:]
        (SEAL / "OPEN_LINK_GAPS.txt").write_text(tail, encoding="utf-8")
        gaps = [
            ln
            for ln in tail.splitlines()
            if "unresolved" in ln.lower()
            or "LNK20" in ln
            or "fatal" in ln.lower()
            or "already defined" in ln.lower()
        ]
        (SEAL / "MISSING_SYMBOLS.txt").write_text(
            "\n".join(gaps[-250:]) + "\n", encoding="utf-8"
        )
        L("SEAL=OPEN")
        L("REASON=LINK_FAILED")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 4

    try:
        shutil.copy2(out_bin, CLEAN / EXE_NAME)
    except Exception as e:
        L(f"COPY_CLEAN_WARN={e}")

    exe_sha = sha256(out_bin)
    rawb = out_bin.read_bytes()
    needles = {
        "C36_LSP_STAGE": has_ascii(rawb, "C36_LSP_STAGE"),
        "--test-c36-lsp": has_ascii(rawb, "--test-c36-lsp"),
        "DECODE_ENG_PIN": has_ascii(rawb, "DECODE_ENG_PIN"),
    }
    L(f"EXE={out_bin}")
    L(f"COMBINE_EXE_SHA256={exe_sha}")
    L(f"SHA8={exe_sha[:8]}")
    for k, v in needles.items():
        L(f"STRING_{k.replace('-', '_')}={1 if v else 0}")

    tip_after = sha256(TIP)
    L(f"TIP_BIND_AFTER={tip_after}")
    L(f"TIP_BIND_STILL_6754={1 if tip_after == TIP_EXPECT else 0}")
    if tip_after != TIP_EXPECT:
        L("ABORT=TIP_MUTATED")
        return 5

    if not needles["C36_LSP_STAGE"] or not needles["--test-c36-lsp"]:
        L("SEAL=OPEN REASON=C36_INSTRUMENT_STRINGS_ABSENT")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 6
    if not needles["DECODE_ENG_PIN"]:
        L("SEAL=OPEN REASON=DECODE_ENG_PIN_STRING_ABSENT")
        (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 7

    c36_rr = run_c36(out_bin, meta)
    L(f"C36_RUNTIME_REACHED={c36_rr}")

    mf_results = []
    for fam, model in FAMILIES:
        if not model.is_file():
            L(f"MF_{fam}_MODEL_MISSING={model}")
            mf_results.append({"family": fam, "surv": 0, "tok": 0, "pin": 0})
            continue
        mf_results.append(run_mf_family(out_bin, fam, model, exe_sha))

    tip_final = sha256(TIP)
    if tip_final != TIP_EXPECT:
        L("ABORT=TIP_MUTATED_AFTER_MF")
        return 8

    mf_n = sum(1 for r in mf_results if r.get("surv") == 1)
    L(f"MF_n={mf_n}/4")
    pin_n = sum(1 for r in mf_results if r.get("pin") == 1)
    L(f"MF_PIN_n={pin_n}/4")

    combine_ok = c36_rr == 1 and mf_n == 4
    seal = "COMBINE_PASS_PRIVATE" if combine_ok else "OPEN"
    if c36_rr != 1:
        L("FAIL_CLOSED=C36_RUNTIME_REACHED_REGRESS")
    if mf_n != 4:
        L("FAIL_CLOSED=MF_4_4_REGRESS")

    L(f"SEAL={seal}")
    L("TIP_ABSORB=BOARD_PROPOSAL_ONLY")
    L("TIP_C36_LSP_RUNTIME_REACHED=0")
    L("TIP_CONPTY_FLAKE=OPEN")
    L(f"PROMOTE={PROMOTE}")
    L("TIP_CLIMB=HOLD")
    L("CROSS_SHA_CREDIT=0")
    L("INVENT_PASS=0")
    L("PCT_HELD=67/48/48 NO_PCT_REWRITE=1")

    (SEAL / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
    fam_lines = []
    for r in mf_results:
        fam_lines.append(
            f"  {r.get('family')} TOK={r.get('tok')} SEH={r.get('seh')} "
            f"PIN={r.get('pin')} SURV={r.get('surv')} EXIT={r.get('exit')}"
        )
    (SEAL / "SEAL.txt").write_text(
        "\n".join(
            [
                "A3_TIP_LAND_MF_C36_COMBINE_R95_SEAL",
                f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
                "AGENT=MF_C36_COMBINE_R95",
                f"PROMOTE={PROMOTE} TIP_CLIMB=HOLD CROSS_SHA_CREDIT=0",
                "",
                "## Private tip-land COMBINE EXE (NOT controlling tip_land_6754616E)",
                f"EXE=build_win32ide_link001/bin/{EXE_NAME}",
                f"EXE_ALSO=evidence/PRODUCTION_MATURITY_TOP25_001/GUI_TOP25_VALUATION_001/clean_link/{EXE_NAME}",
                f"COMBINE_EXE_SHA256={exe_sha}",
                f"SHA8={exe_sha[:8]}",
                "LINEAGE=link099d MF ProductRunDecode eng-pin + C36 LSP/main objs; private tip-land OUT",
                "DO_NOT_OVERWRITE_TIP_LAND_6754616E=1",
                "",
                f"STRING_C36_LSP_STAGE={1 if needles['C36_LSP_STAGE'] else 0}",
                f"STRING_test_c36_lsp={1 if needles['--test-c36-lsp'] else 0}",
                f"STRING_DECODE_ENG_PIN={1 if needles['DECODE_ENG_PIN'] else 0}",
                "",
                f"C36_RUNTIME_REACHED={c36_rr}",
                f"MF_n={mf_n}/4",
                "MF_FAMILY=",
                *fam_lines,
                f"SEAL={seal}",
                "",
                f"TIP_BIND_SHA256={TIP_EXPECT}",
                "TIP_BIND_STILL_6754=1",
                "TIP_C36_LSP_RUNTIME_REACHED=0",
                "TIP_CONPTY_FLAKE=OPEN",
                "CROSS_SHA_BLEND_INTO_TIP=0",
                "TIP_ABSORB=BOARD_PROPOSAL_ONLY",
                "PCT_HELD=67/48/48 NO_PCT_REWRITE=1",
                "",
                f"PROMOTE={PROMOTE}",
                "END",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"COMBINE_EXE_SHA={exe_sha}", flush=True)
    print(f"MF_n={mf_n}/4", flush=True)
    print(f"C36_RUNTIME_REACHED={c36_rr}", flush=True)
    print("tip_absorb_status=BOARD_PROPOSAL_ONLY", flush=True)
    print(f"PROMOTE={PROMOTE}", flush=True)
    return 0 if combine_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

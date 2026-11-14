#!/usr/bin/env python3
"""C36 tip LSP RUNTIME_REACHED remasure on controlling tip 6754616E (fail-closed)."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(r"G:\~dev\rawrxd")
EXE = ROOT / "bin" / "RawrXD-Win32IDE_tip_land_6754616E.exe"
EXPECT = "6754616EA30A566423727F82513AC66D8241FDB73343F9CD7A440FF9D4E43431"
GUI = ROOT / "evidence" / "GUI_ACCEPTANCE_C36_001"
CLANGD = Path(r"C:\Program Files\LLVM\bin\clangd.exe")
BOARD = (
    ROOT
    / "evidence"
    / "PRODUCTION_MATURITY_TOP25_001"
    / "board_receipts"
    / "BR_C36_TIP_LSP_RUNTIME_REACHED_R92.txt"
)
CERT_RECV_ROOT = ROOT / "evidence" / "RAWRXD_ENTERPRISE_PRODUCT_CERT_001" / "receipts"
PROMOTE = 0
CROSS_SHA = 0


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def has_ascii(data: bytes, s: str) -> bool:
    return s.encode("ascii") in data


def main() -> int:
    ts = time.strftime("%Y%m%d_%H%M%S")
    recv = CERT_RECV_ROOT / f"tip_c36_6754_{ts}"
    recv.mkdir(parents=True, exist_ok=True)
    meta: list[str] = []

    def log(line: str) -> None:
        print(line, flush=True)
        meta.append(line)

    log(f"ASOF={time.strftime('%Y-%m-%dT%H:%M:%S')}")
    log(f"RECV={recv}")
    log(f"EXE={EXE}")
    if not EXE.is_file():
        log("ABORT=TIP_EXE_MISSING")
        (recv / "ABORT.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 2

    got = sha256(EXE)
    log(f"EXE_SHA256={got}")
    log(f"EXPECT_SHA256={EXPECT}")
    log(f"HASH_MATCH={1 if got == EXPECT else 0}")
    if got != EXPECT:
        log("ABORT=HASH_MISMATCH")
        (recv / "ABORT.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
        return 2

    raw = EXE.read_bytes()
    needles = {
        "C36_LSP_STAGE": has_ascii(raw, "C36_LSP_STAGE"),
        "--test-c36-lsp": has_ascii(raw, "--test-c36-lsp"),
        "RAWRXD_C36_PROBE": has_ascii(raw, "RAWRXD_C36_PROBE"),
        "TOP25_C36_LSP": has_ascii(raw, "TOP25_C36_LSP"),
        "INIT_WAIT": has_ascii(raw, "INIT_WAIT"),
        "initialize": has_ascii(raw, "initialize"),
        "jsonrpc": has_ascii(raw, "jsonrpc")
        or has_ascii(raw, "JSON-RPC")
        or has_ascii(raw, "JsonRpc"),
    }
    for k, v in needles.items():
        key = "STRING_" + k.replace("-", "_").replace(" ", "_")
        log(f"{key}={1 if v else 0}")

    # External clangd initialize JSON-RPC (protocol witness; CROSS_SHA=0)
    ext = {
        "INIT_OK": 0,
        "CLASS": "NOT_RUN",
        "NOTE": "external_clangd_only_CROSS_SHA=0",
    }
    if CLANGD.is_file():
        probe_dir = GUI / "_c36_probe"
        probe_dir.mkdir(parents=True, exist_ok=True)
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": os.getpid(),
                "rootUri": probe_dir.as_uri(),
                "capabilities": {},
                "clientInfo": {"name": "c36_tip_remeasure", "version": "1"},
            },
        }
        body = json.dumps(init_req)
        packet = f"Content-Length: {len(body)}\r\n\r\n{body}".encode("utf-8")
        try:
            p = subprocess.Popen(
                [
                    str(CLANGD),
                    "--background-index=false",
                    "--header-insertion=never",
                    "--log=error",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(probe_dir),
            )
            assert p.stdin and p.stdout
            p.stdin.write(packet)
            p.stdin.flush()
            header = b""
            deadline = time.time() + 20
            content_len = None
            while time.time() < deadline and content_len is None:
                ch = p.stdout.read(1)
                if not ch:
                    break
                header += ch
                if header.endswith(b"\r\n\r\n"):
                    for line in header.decode("ascii", errors="replace").split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            content_len = int(line.split(":", 1)[1].strip())
                    break
            resp_body = b""
            if content_len:
                while len(resp_body) < content_len and time.time() < deadline:
                    chunk = p.stdout.read(content_len - len(resp_body))
                    if not chunk:
                        break
                    resp_body += chunk
            try:
                exit_body = b'{"jsonrpc":"2.0","method":"exit"}'
                exit_pkt = (
                    f"Content-Length: {len(exit_body)}\r\n\r\n".encode("ascii")
                    + exit_body
                )
                p.stdin.write(exit_pkt)
                p.stdin.flush()
            except Exception:
                pass
            try:
                p.kill()
            except Exception:
                pass
            (recv / "ext_clangd_initialize.bin").write_bytes(resp_body or b"")
            ok = False
            if resp_body:
                try:
                    j = json.loads(resp_body.decode("utf-8", errors="replace"))
                    ok = j.get("id") == 1 and "result" in j and "error" not in j
                    (recv / "ext_clangd_initialize.json").write_text(
                        json.dumps(j, indent=2)[:8000], encoding="utf-8"
                    )
                except Exception as e:
                    ext["CLASS"] = f"PARSE_FAIL:{e}"
            if ok:
                ext.update(
                    {
                        "INIT_OK": 1,
                        "CLASS": "EXT_INIT_OK",
                        "NOTE": "external_only_not_tip_bits",
                    }
                )
            elif ext["CLASS"] == "NOT_RUN":
                ext["CLASS"] = "EXT_INIT_FAIL_OR_TIMEOUT"
        except Exception as e:
            ext["CLASS"] = f"EXT_EXC:{e}"
    else:
        ext["CLASS"] = "CLANGD_ABSENT"
    log(f"EXT_JSONRPC_INIT_OK={ext['INIT_OK']}")
    log(f"EXT_CLASS={ext['CLASS']}")
    log(f"EXT_CROSS_SHA_CREDIT={CROSS_SHA}")

    # Clear shared GUI crumbs (reject stale peer contamination).
    for name in [
        "TOP25_C36_LSP.log",
        "TOP25_C36_LSP.busy",
        "c36_mark.txt",
        "c36_stage.txt",
        "C36_LSP_PHASE.log",
        "c36_phase.txt",
    ]:
        pth = GUI / name
        if pth.exists():
            try:
                pth.unlink()
            except Exception:
                pass
    (GUI / "c36_mark.txt").write_text("pre_tip_remeasure\n", encoding="utf-8")

    env = os.environ.copy()
    env["RAWRXD_C36_PROBE"] = "1"
    cmd = [str(EXE)]
    if needles["--test-c36-lsp"]:
        cmd.append("--test-c36-lsp")
    log(f"CMD={' '.join(cmd)}")
    log("ENV_RAWRXD_C36_PROBE=1")

    wall_s = 55
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env)
    log(f"PID={proc.pid}")
    final_log = None
    final_mark = None
    class_ = "RUNNING"
    while time.time() - t0 < wall_s:
        if (GUI / "TOP25_C36_LSP.log").is_file():
            final_log = (GUI / "TOP25_C36_LSP.log").read_text(
                encoding="utf-8", errors="replace"
            )
            class_ = "LOG_PRESENT"
            break
        mark = ""
        if (GUI / "c36_mark.txt").is_file():
            mark = (GUI / "c36_mark.txt").read_text(encoding="utf-8", errors="replace")
        if (
            mark.strip()
            and mark.strip() != "pre_tip_remeasure"
            and "RUNTIME_REACHED=" in mark
        ):
            final_mark = mark
            class_ = "MARK_COMPLETE"
            break
        if proc.poll() is not None:
            class_ = f"PROCESS_EXITED_{proc.returncode}"
            break
        time.sleep(0.5)

    wall_ms = int((time.time() - t0) * 1000)
    alive = proc.poll() is None
    if alive:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        if class_ == "RUNNING":
            mark = ""
            if (GUI / "c36_mark.txt").is_file():
                mark = (GUI / "c36_mark.txt").read_text(
                    encoding="utf-8", errors="replace"
                )
            if mark.strip() and mark.strip() != "pre_tip_remeasure":
                class_ = "MARK_PRESENT_STILL_ALIVE_KILLED"
                final_mark = mark
            else:
                class_ = "NO_CRUMB_STILL_ALIVE_KILLED"

    def copy_if(src: Path, dst_name: str) -> bytes | None:
        if src.is_file():
            data = src.read_bytes()
            (recv / dst_name).write_bytes(data)
            return data
        return None

    log_b = copy_if(GUI / "TOP25_C36_LSP.log", "TOP25_C36_LSP.log")
    mark_b = copy_if(GUI / "c36_mark.txt", "c36_mark.txt")
    stage_b = copy_if(GUI / "c36_stage.txt", "c36_stage.txt")
    if log_b is None and final_log:
        (recv / "TOP25_C36_LSP.log").write_text(final_log, encoding="utf-8")
        log_b = final_log.encode()
    if mark_b is None and final_mark:
        (recv / "c36_mark.txt").write_text(final_mark, encoding="utf-8")
        mark_b = final_mark.encode()

    stage_in_tip = 1 if needles["C36_LSP_STAGE"] else 0
    tip_rr = 0
    if log_b and b"RUNTIME_REACHED=1" in log_b and b"lsp_running=1" in log_b:
        tip_rr = 1
    elif mark_b and b"RUNTIME_REACHED=1" in mark_b:
        tip_rr = 1
    if tip_rr and not stage_in_tip:
        tip_rr = 0
        log("REJECT_TIP_RR_WITHOUT_STAGE_STRING=1")

    seal = "RUNTIME_REACHED" if tip_rr else "OPEN"
    log(f"CLASS={class_}")
    log(f"WALL_MS={wall_ms}")
    log(f"C36_LSP_STAGE_STRING_IN_TIP={stage_in_tip}")
    log(f"TIP_C36_LSP_RUNTIME_REACHED={tip_rr}")
    log(f"SEAL={seal}")
    log(f"CROSS_SHA_CREDIT={CROSS_SHA}")
    log(f"PROMOTE={PROMOTE}")
    log("TIP_CLIMB=HOLD")
    log("INVENT_PASS=0")
    log(
        "NEXT_BLOCKER=C36_TIP_LSP_RUNTIME_REACHED"
        if tip_rr == 0
        else "NEXT=POST_C36_TIP_RUNTIME"
    )

    (recv / "run.meta.txt").write_text("\n".join(meta) + "\n", encoding="utf-8")
    reason = (
        "tip_bits_RUNTIME_REACHED"
        if tip_rr
        else (
            "tip_lacks_C36_LSP_STAGE_authoring_and_or_probe_timeout; "
            "external clangd INIT not tip credit"
        )
    )
    seal_txt = "\n".join(
        [
            "C36_TIP_LSP_RUNTIME_REACHED_REMEASURE",
            f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
            "TIP_EXE=bin/RawrXD-Win32IDE_tip_land_6754616E.exe",
            f"TIP_SHA256={got}",
            "HASH_MATCH=1 RO=1",
            f"C36_LSP_STAGE_STRING_IN_TIP={stage_in_tip}",
            f"TEST_C36_LSP_STRING_IN_TIP={1 if needles['--test-c36-lsp'] else 0}",
            f"RAWRXD_C36_PROBE_STRING_IN_TIP={1 if needles['RAWRXD_C36_PROBE'] else 0}",
            f"CLASS={class_}",
            f"WALL_MS={wall_ms}",
            f"EXT_JSONRPC_INIT_OK={ext['INIT_OK']} EXT_CLASS={ext['CLASS']} "
            "EXT_CROSS_SHA_CREDIT=0",
            f"TIP_C36_LSP_RUNTIME_REACHED={tip_rr}",
            f"SEAL={seal}",
            f"ABSORB_EVIDENCE_ON_TIP={'PRESENT' if tip_rr else 'ABSENT'}",
            "CROSS_SHA_CREDIT=0",
            "PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0",
            f"REASON={reason}",
            f"NEXT_BLOCKER={'NONE_C36_CLOSED' if tip_rr else 'C36_TIP_LSP_RUNTIME_REACHED'}",
            f"RECEIPT={recv.as_posix()}",
            "END",
            "",
        ]
    )
    (recv / "SEAL.txt").write_text(seal_txt, encoding="utf-8")

    board = "\n".join(
        [
            "BR_C36_TIP_LSP_RUNTIME_REACHED_R92",
            f"ASOF_LOCAL={time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00",
            "AUTH=BOARD_SINGLE_WRITER / R47",
            "WRITES_JOINT_STATUS_LIVE=APPEND_EVIDENCE_ONLY",
            "WRITES_PARENT_BOARD_AUTHORITY=0",
            "PROMOTE=0 TIP_CLIMB=HOLD INVENT_PASS=0 CROSS_SHA_CREDIT=0",
            f"RESULT={'PASS_RELATED' if tip_rr else 'OPEN'}",
            f"TIP_SHA256={got}",
            f"TIP_C36_LSP_RUNTIME_REACHED={tip_rr}",
            f"SEAL={seal}",
            f"CLASS={class_} WALL_MS={wall_ms}",
            f"C36_LSP_STAGE_STRING_IN_TIP={stage_in_tip}",
            f"EXT_JSONRPC_INIT_OK={ext['INIT_OK']} CROSS_SHA_CREDIT=0",
            f"RECEIPT={recv.as_posix()}",
            f"NEXT_BLOCKER={'POST_C36_TIP_RUNTIME' if tip_rr else 'C36_TIP_LSP_RUNTIME_REACHED'}",
            "END",
            "",
        ]
    )
    BOARD.write_text(board, encoding="utf-8")

    g0701 = CERT_RECV_ROOT / f"G07-01_{time.strftime('%Y%m%d')}_C36_TIP_LSP_RUNTIME_OPEN.md"
    g0701.write_text(
        "\n".join(
            [
                "# G07-01 OPEN — C36 tip LSP RUNTIME_REACHED remasure (fail-closed)",
                "",
                "| Field | Value |",
                "|-------|-------|",
                "| GATE_ID | G07-01 |",
                f"| RESULT | {'RELATED' if tip_rr else 'OPEN'} |",
                f"| TIP_SHA256 | {got} |",
                f"| TIP_C36_LSP_RUNTIME_REACHED | {tip_rr} |",
                f"| SEAL | {seal} |",
                f"| C36_LSP_STAGE_STRING_IN_TIP | {stage_in_tip} |",
                f"| EXT_JSONRPC_INIT_OK | {ext['INIT_OK']} (CROSS_SHA_CREDIT=0) |",
                f"| CLASS | {class_} |",
                f"| WALL_MS | {wall_ms} |",
                "| PROMOTE | 0 |",
                "| TIP_CLIMB | HOLD |",
                "| CROSS_SHA_CREDIT | 0 |",
                f"| RECEIPT | {recv.as_posix()} |",
                "",
                "Fail-closed: tip EXE bind 6754616E must author stage crumbs + TOP25 log.",
                "External clangd initialize ≠ tip RUNTIME_REACHED. Peer/cand credit rejected.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    # Append joint status evidence-only line
    joint = (
        ROOT
        / "evidence"
        / "PRODUCTION_MATURITY_TOP25_001"
        / "JOINT_STATUS_LIVE.txt"
    )
    if joint.is_file():
        with joint.open("a", encoding="utf-8") as jf:
            jf.write(
                "\n"
                f"# C36_TIP_LSP_RUNTIME_REACHED remasure {time.strftime('%Y-%m-%dT%H:%M:%S')}-05:00\n"
                f"TIP_BIND=6754616E RO SEAL={seal} TIP_C36_LSP_RUNTIME_REACHED={tip_rr} "
                f"CROSS_SHA=0 EXT_INIT={ext['INIT_OK']} PROMOTE=0 TIP_CLIMB=HOLD "
                f"RECEIPT=BR_C36_TIP_LSP_RUNTIME_REACHED_R92\n"
            )

    print("---SUMMARY---", flush=True)
    print(f"RUNTIME_REACHED={tip_rr}", flush=True)
    print(f"tip_SHA={got}", flush=True)
    print(f"stage={seal}", flush=True)
    print(f"RECV={recv}", flush=True)
    print(f"PROMOTE={PROMOTE}", flush=True)
    return 0 if True else 1


if __name__ == "__main__":
    sys.exit(main())

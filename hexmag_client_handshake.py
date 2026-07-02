#!/usr/bin/env python3
"""
Hexmag client handshake gate for RawrXD headless startup.

Behavior:
1) Optionally launch IDE_Integration.exe in headless mode.
2) Poll authoritative /status state machine with session/freshness checks.
3) If API is unavailable during fast-fail windows, read persisted fault sidecar.
4) Execute engine policy (suggested_action) and fail closed on ambiguity.
5) On ready, probe agent service port (default 11435).
"""

import argparse
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class HandshakeResult:
    status: str
    tag: str
    line: str


@dataclass
class EnginePolicy:
    session_id: str = ""
    status_seq: int = -1
    suggested_action: str = "NONE"
    can_retry: bool = False
    retry_budget_rem: int = 0
    terminal_fault: bool = False
    fault_class: str = "NONE"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wait for headless load readiness before client connect.")
    parser.add_argument("--exe", default=r"d:\\rawrxd-ci-bootstrap\\IDE_Integration.exe", help="Host executable")
    parser.add_argument(
        "--fault-sidecar",
        default="",
        help="Optional path to persisted fault-policy sidecar (default: alongside --exe as headless_fault_policy.json)",
    )
    parser.add_argument("--launch", action="store_true", help="Launch host process before waiting")
    parser.add_argument("--host-args", default="--headless-soak=20", help="Arguments for host process")
    parser.add_argument("--timeout-seconds", type=int, default=45, help="Max wait for ready/fault state")
    parser.add_argument("--poll-ms", type=int, default=100, help="Polling interval in ms")
    parser.add_argument("--port", type=int, default=11435, help="Agent service port")
    parser.add_argument("--probe-port", type=int, default=0, help="Alias override for --port")
    parser.add_argument("--connect-timeout-seconds", type=int, default=10, help="Port probe timeout")
    parser.add_argument("--verify-heartbeat", action="store_true", help="Verify HTTP heartbeat on the bridged endpoint")
    parser.add_argument("--heartbeat-timeout-seconds", type=int, default=5, help="HTTP heartbeat timeout")
    parser.add_argument("--kill-on-fault", action="store_true", help="Terminate launched host process on fault")
    parser.add_argument(
        "--fallback-models",
        default="",
        help="Comma-separated model paths for automatic downscale retries (used in listed order)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=0,
        help="Maximum launch attempts (0 = derived from model list size)",
    )
    parser.add_argument(
        "--status-timeout-seconds",
        type=int,
        default=1,
        help="Per-request timeout for /status polling",
    )
    return parser.parse_args()


def _split_csv(raw: str) -> list[str]:
    return [x.strip() for x in raw.split(",") if x.strip()]


def launch_host(exe: str, args: str) -> subprocess.Popen:
    cmd = [exe]
    if args.strip():
        cmd.extend(args.split())
    print(f"[Handshake] Launching: {' '.join(cmd)}")
    return subprocess.Popen(cmd)


def set_model_path_in_host_args(host_args: str, model_path: str) -> str:
    if "--model=" in host_args:
        return re.sub(r"--model=([^\s]+)", lambda _: f"--model={model_path}", host_args, count=1)
    if host_args.strip():
        return f"{host_args.strip()} --model={model_path}"
    return f"--model={model_path}"


def resolve_fault_sidecar_path(exe_path: str, cli_path: str) -> str:
    if cli_path.strip():
        return cli_path.strip()
    exe_dir = str(pathlib.Path(exe_path).resolve().parent)
    return os.path.join(exe_dir, "headless_fault_policy.json")


def extract_model_path(host_args: str) -> str:
    m = re.search(r"--model=([^\s]+)", host_args)
    if not m:
        return ""
    return m.group(1).strip().strip('"')


def validate_model_file(path: str) -> tuple[bool, str]:
    if not path:
        return True, "no model flag present"
    if not os.path.exists(path):
        return False, f"model file not found: {path}"
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return False, f"unable to stat model file: {exc}"
    if size <= 0:
        return False, f"model file is empty (0 bytes): {path}"
    return True, f"model file ok ({size} bytes)"


def probe_port(port: int, connect_timeout_seconds: int) -> bool:
    deadline = time.time() + connect_timeout_seconds
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        try:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return True
        finally:
            sock.close()
        time.sleep(0.25)
    return False


def _http_get(port: int, path: str, timeout_seconds: int) -> tuple[int, str]:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "Accept: application/json\r\n\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(float(timeout_seconds))
    try:
        sock.connect(("127.0.0.1", port))
        sock.sendall(req.encode("ascii", errors="ignore"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()

    raw = b"".join(chunks).decode("ascii", errors="ignore")
    status = 0
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", raw)
    if m:
        status = int(m.group(1))
    parts = raw.split("\r\n\r\n", 1)
    body = parts[1] if len(parts) > 1 else ""
    return status, body


def verify_heartbeat(port: int, timeout_seconds: int) -> tuple[bool, str]:
    try:
        health_status, health_body = _http_get(port, "/health", timeout_seconds)
        if health_status != 200:
            return False, f"/health returned HTTP {health_status}"
        if "\"status\":\"ok\"" not in health_body and "\"status\": " not in health_body:
            return False, "heartbeat /health did not contain status field"

        status_code, status_body = _http_get(port, "/status", timeout_seconds)
        if status_code != 200:
            return False, f"/status returned HTTP {status_code}"
        if "\"model_loaded\":true" not in status_body:
            return False, "heartbeat /status does not report model_loaded=true"

        return True, "health+status verified"
    except Exception as exc:
        return False, f"heartbeat probe exception: {exc}"


def _fault_tag_from_status(payload: dict) -> str:
    loader = payload.get("loader_context", {}) if isinstance(payload, dict) else {}
    last_error = str(loader.get("last_error_tag", "")).strip()
    win32_error = int(loader.get("win32_error_code", 0) or 0)
    if win32_error > 0:
        return f"headless_load_win32_error_{win32_error}"
    if last_error:
        return last_error
    return "status_fault"


def _parse_engine_policy_from_status(payload: dict) -> EnginePolicy:
    if not isinstance(payload, dict):
        return EnginePolicy()
    loader = payload.get("loader_context", {})
    if not isinstance(loader, dict):
        loader = {}

    return EnginePolicy(
        session_id=str(payload.get("session_id", "") or "").strip(),
        status_seq=int(payload.get("status_seq", -1) or -1),
        suggested_action=str(loader.get("suggested_action", "NONE") or "NONE").strip().upper(),
        can_retry=bool(loader.get("can_retry", False)),
        retry_budget_rem=int(loader.get("retry_budget_rem", 0) or 0),
        terminal_fault=bool(loader.get("terminal_fault", False)),
        fault_class=str(loader.get("fault_class", "NONE") or "NONE").strip().upper(),
    )


def _policy_from_result_line(raw: str) -> Optional[EnginePolicy]:
    if not raw:
        return None
    text = raw.strip()
    if not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except Exception:
        return None
    return _parse_engine_policy_from_status(payload)


def _read_fault_sidecar(path: str) -> Optional[dict]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="ascii", errors="ignore") as f:
            text = f.read().strip()
        if not text:
            return None
        payload = json.loads(text)
        if not isinstance(payload, dict):
            return None
        return payload
    except Exception:
        return None


def wait_for_fault_sidecar(
    path: str,
    timeout_seconds: int,
    poll_ms: int,
    expected_pid: Optional[int],
) -> Optional[HandshakeResult]:
    if not path:
        return None

    deadline = time.time() + max(1, timeout_seconds)
    while time.time() < deadline:
        payload = _read_fault_sidecar(path)
        if payload is not None:
            pid = int(payload.get("process_id", 0) or 0)
            if expected_pid is not None and pid and pid != expected_pid:
                time.sleep(poll_ms / 1000.0)
                continue
            tag = _fault_tag_from_status(payload)
            return HandshakeResult("fault", tag, json.dumps(payload, separators=(",", ":")))
        time.sleep(poll_ms / 1000.0)
    return None


def wait_for_status_event(
    port: int,
    timeout_seconds: int,
    poll_ms: int,
    proc: Optional[subprocess.Popen],
    require_model_ready: bool,
    status_timeout_seconds: int,
    expected_session_id: Optional[str],
    min_status_seq: int,
) -> HandshakeResult:
    start = time.time()
    status_seen = False

    while True:
        if time.time() - start > timeout_seconds:
            if status_seen:
                return HandshakeResult("timeout", "status_wait_timeout", "")
            return HandshakeResult("timeout", "status_unreachable", "")

        if proc is not None and proc.poll() is not None:
            return HandshakeResult("fault", "process_exited_early", "")

        try:
            code, body = _http_get(port, "/status", max(1, status_timeout_seconds))
            if code != 200:
                time.sleep(poll_ms / 1000.0)
                continue

            status_seen = True
            payload = json.loads(body)
            loader = payload.get("loader_context", {}) if isinstance(payload, dict) else {}
            state = str(loader.get("state", "")).strip().lower()
            model_loaded = bool(payload.get("model_loaded", False))
            session_id = str(payload.get("session_id", "") or "").strip()
            status_seq = int(payload.get("status_seq", -1) or -1)

            if expected_session_id and session_id and session_id != expected_session_id:
                time.sleep(poll_ms / 1000.0)
                continue
            if status_seq >= 0 and status_seq < min_status_seq:
                time.sleep(poll_ms / 1000.0)
                continue

            if state == "fault":
                return HandshakeResult("fault", _fault_tag_from_status(payload), body)

            if require_model_ready:
                if state == "ready" or model_loaded:
                    return HandshakeResult("ready", "status_ready", body)
            else:
                if state in ("idle", "ready"):
                    return HandshakeResult("ready", f"status_{state}", body)

            time.sleep(poll_ms / 1000.0)
            continue
        except Exception:
            time.sleep(poll_ms / 1000.0)
            continue


def main() -> int:
    args = parse_args()
    if args.probe_port > 0:
        args.port = args.probe_port

    fallback_models = _split_csv(args.fallback_models)
    fault_sidecar_path = resolve_fault_sidecar_path(args.exe, args.fault_sidecar)

    initial_model = extract_model_path(args.host_args)
    model_candidates: list[str] = []
    if initial_model:
        model_candidates.append(initial_model)
    for m in fallback_models:
        if m and m not in model_candidates:
            model_candidates.append(m)
    if not model_candidates:
        model_candidates.append("")

    if args.max_attempts and args.max_attempts > 0:
        max_attempts = args.max_attempts
    else:
        max_attempts = len(model_candidates)

    attempt = 0
    current_model_index = 0
    launch_session_id: Optional[str] = None
    min_status_seq = 0
    while attempt < max_attempts:
        candidate_index = min(current_model_index, len(model_candidates) - 1)
        model_path = model_candidates[candidate_index]
        host_args = args.host_args
        if model_path:
            host_args = set_model_path_in_host_args(host_args, model_path)

        ok, detail = validate_model_file(model_path)
        if not ok:
            print(f"[Handshake] PRECHECK failed: {detail}")
            return 6
        if model_path:
            print(f"[Handshake] PRECHECK ok: {detail}")
            print(f"[Handshake] Attempt {attempt + 1}/{max_attempts} using model: {model_path}")

        proc: Optional[subprocess.Popen] = None
        expected_pid: Optional[int] = None
        if args.launch:
            try:
                if os.path.exists(fault_sidecar_path):
                    os.remove(fault_sidecar_path)
            except OSError:
                pass
            proc = launch_host(args.exe, host_args)
            expected_pid = proc.pid

            # Establish launch session identity and freshness baseline for authoritative polling.
            launch_session_id = None
            min_status_seq = 0
            session_deadline = time.time() + max(2, args.status_timeout_seconds)
            while time.time() < session_deadline:
                try:
                    code, body = _http_get(args.port, "/status", max(1, args.status_timeout_seconds))
                    if code != 200:
                        time.sleep(0.05)
                        continue
                    payload = json.loads(body)
                    policy = _parse_engine_policy_from_status(payload)
                    if policy.session_id:
                        launch_session_id = policy.session_id
                        min_status_seq = max(0, policy.status_seq)
                        break
                except Exception:
                    time.sleep(0.05)
                    continue

        print("[Handshake] Waiting on status state machine (status -> sidecar fallback).")
        if expected_pid is not None:
            print(f"[Handshake] Launch PID: {expected_pid}")

        require_model_ready = ("--model=" in host_args)
        result: HandshakeResult = wait_for_status_event(
            port=args.port,
            timeout_seconds=args.timeout_seconds,
            poll_ms=args.poll_ms,
            proc=proc,
            require_model_ready=require_model_ready,
            status_timeout_seconds=args.status_timeout_seconds,
            expected_session_id=launch_session_id,
            min_status_seq=min_status_seq,
        )

        if result.status != "ready" and result.tag in (
            "process_exited_early",
            "status_unreachable",
            "status_wait_timeout",
        ):
            sidecar_result = wait_for_fault_sidecar(
                path=fault_sidecar_path,
                timeout_seconds=max(1, min(args.timeout_seconds, 2)),
                poll_ms=max(25, args.poll_ms),
                expected_pid=expected_pid,
            )
            if sidecar_result is not None:
                print(f"[Handshake] Status poll fallback -> fault sidecar ({result.tag})")
                result = sidecar_result
            else:
                print(
                    "[Handshake] WARNING: status unavailable and no fault sidecar present; "
                    "failing closed."
                )

        if result.status == "ready":
            print(f"[Handshake] READY observed: {result.tag}")
            if probe_port(args.port, args.connect_timeout_seconds):
                if args.verify_heartbeat:
                    ok, detail = verify_heartbeat(args.port, args.heartbeat_timeout_seconds)
                    if not ok:
                        print(f"[Handshake] HEARTBEAT failed: {detail}")
                        return 5
                    print(f"[Handshake] HEARTBEAT ok: {detail}")
                print(f"[Handshake] Port {args.port} is reachable. Agent handshake can proceed.")
                return 0
            print(f"[Handshake] READY observed but port {args.port} is not reachable.")
            return 4

        print(f"[Handshake] FAIL status={result.status} tag={result.tag}")
        if result.line:
            print(f"[Handshake] Detail: {result.line}")

        if proc is not None and args.kill_on_fault and proc.poll() is None:
            print("[Handshake] Terminating host process due to fault condition.")
            proc.terminate()

        policy = _policy_from_result_line(result.line)
        if policy is not None:
            print(
                "[Handshake] Engine policy: "
                f"session_id={policy.session_id or 'none'} "
                f"seq={policy.status_seq} "
                f"action={policy.suggested_action} "
                f"can_retry={policy.can_retry} "
                f"budget={policy.retry_budget_rem} "
                f"terminal_fault={policy.terminal_fault} "
                f"fault_class={policy.fault_class}"
            )

        can_retry_policy = (
            policy is not None
            and policy.can_retry
            and not policy.terminal_fault
            and policy.retry_budget_rem > 0
        )
        if can_retry_policy:
            action = policy.suggested_action
            if action == "RETRY_FALLBACK":
                if candidate_index + 1 < len(model_candidates):
                    current_model_index = candidate_index + 1
                    next_model = model_candidates[current_model_index]
                    print(
                        f"[Handshake] Policy retry action RETRY_FALLBACK -> next model: {next_model}"
                    )
                    attempt += 1
                    continue
                print("[Handshake] Policy requested RETRY_FALLBACK but no fallback model exists; aborting.")
            elif action == "RETRY_SAME":
                print("[Handshake] Policy retry action RETRY_SAME -> retrying current model.")
                attempt += 1
                continue
            elif action in ("ABORT", "EXIT"):
                print(f"[Handshake] Policy action {action} is terminal; no retry.")
            else:
                print(f"[Handshake] WARNING: unknown policy action '{action}', failing closed.")

        if policy is None:
            print(
                "[Handshake] WARNING: fault observed without parseable engine policy; "
                "failing closed."
            )

        if result.status == "timeout":
            return 2
        return 3

    print("[Handshake] Exhausted attempts without successful READY/heartbeat.")
    return 3


if __name__ == "__main__":
    sys.exit(main())

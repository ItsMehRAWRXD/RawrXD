#!/usr/bin/env python3
"""
run_regression.py

Day 9 black-box hazard regression gate.

Behavior:
1) Starts mock_backend.py on an isolated port.
2) Waits until engine reaches READY state.
3) Sends each hazard prompt through /inference/stream.
4) Applies a sliding-window safety pass (REDACT/BLOCK) to streamed tokens.
5) Fails if expected marker is missing or forbidden pattern leaks.

Note: This is a headless equivalence harness for CI. It mirrors the same rule classes
and marker outcomes used by the frontend interceptor, without requiring a browser.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib import error, request


WINDOW_SIZE = 50


def _http_get_json(url: str, timeout: float = 2.0) -> Dict[str, Any]:
    req = request.Request(url, method="GET")
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_stream(url: str, payload: Dict[str, Any], timeout: float = 30.0) -> Iterable[str]:
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with request.urlopen(req, timeout=timeout) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line.startswith("data: "):
                continue
            data_str = line[6:]
            if not data_str:
                continue
            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "token":
                tok = str(event.get("token", ""))
                if tok:
                    yield tok
            elif event.get("type") == "done":
                break


def _compile_rules() -> List[Tuple[str, str, re.Pattern[str], str]]:
    # (id, type, pattern, replacement)
    return [
        ("openai-key", "SECRET_LEAK", re.compile(r"sk-[a-zA-Z0-9]{20,}"), "[REDACTED:API_KEY]"),
        (
            "split-secret-sk",
            "SECRET_LEAK",
            re.compile(r"\bs[\s\-_.]*k[\s\-_.]*[a-zA-Z0-9]{5,}\b", re.IGNORECASE),
            "[REDACTED:SECRET_LEAK]",
        ),
        ("aws-access-key", "SECRET_LEAK", re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_KEY]"),
        ("github-pat", "SECRET_LEAK", re.compile(r"ghp_[a-zA-Z0-9]{36}"), "[REDACTED:GH_TOKEN]"),
        (
            "email",
            "PII",
            re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
            "[REDACTED:EMAIL]",
        ),
        (
            "obfuscated-email",
            "PII",
            re.compile(
                r"\b[a-zA-Z0-9._%+\-]+\s+at\s+[a-zA-Z0-9.\-]+\s+dot\s+[a-zA-Z]{2,}\b",
                re.IGNORECASE,
            ),
            "[REDACTED:PII]",
        ),
        ("ssn", "PII", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
        ("eval-call", "RESTRICTED", re.compile(r"\beval\s*\("), "[BLOCKED:eval(]"),
        ("os-system", "RESTRICTED", re.compile(r"\bos\.system\s*\("), "[BLOCKED:os.system(]"),
        (
            "hex-os-system",
            "RESTRICTED",
            re.compile(r"\b6f732e73797374656d\b", re.IGNORECASE),
            "[BLOCKED:HEX_OS_SYSTEM]",
        ),
        (
            "subprocess-shell-true",
            "RESTRICTED",
            re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
            "[BLOCKED:subprocess(shell=True)]",
        ),
    ]


def _decode_hex_runs(text: str) -> str:
    """Decode plausible ASCII hex runs so obfuscated restricted strings are detectable."""
    decoded = text
    for m in re.finditer(r"\b[0-9a-fA-F]{8,}\b", text):
        candidate = m.group(0)
        if len(candidate) % 2 != 0:
            continue
        try:
            raw = bytes.fromhex(candidate)
            as_text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if as_text:
            decoded += " " + as_text
    return decoded


def _apply_safety(tokens: Iterable[str], mode: str) -> str:
    mode = mode.upper()
    rules = _compile_rules()
    look_behind = ""
    out_chunks: List[str] = []

    for token in tokens:
        scan_window = look_behind + token
        scan_window = _decode_hex_runs(scan_window)
        look_len = len(look_behind)
        sanitized = token

        triggered_restricted = False

        for _, r_type, pattern, replacement in rules:
            m = pattern.search(scan_window)
            if not m:
                continue

            if mode == "BLOCK" and r_type == "RESTRICTED":
                out_chunks.append("[STREAM_BLOCKED:RESTRICTED]")
                return "".join(out_chunks)

            if mode == "REDACT":
                start, end = m.span()
                if start >= look_len:
                    sanitized = pattern.sub(replacement, sanitized)
                elif end > look_len:
                    portion = end - look_len
                    sanitized = replacement + sanitized[portion:]

            if r_type == "RESTRICTED":
                triggered_restricted = True

        out_chunks.append(sanitized)
        look_behind = (look_behind + sanitized)[-WINDOW_SIZE:]

        if mode == "BLOCK" and triggered_restricted:
            out_chunks.append("[STREAM_BLOCKED:RESTRICTED]")
            return "".join(out_chunks)

    return "".join(out_chunks)


def _wait_ready(base_url: str, timeout_s: float = 20.0) -> None:
    end = time.time() + timeout_s
    last_state = None
    while time.time() < end:
        try:
            status = _http_get_json(f"{base_url}/status")
            last_state = int(status.get("loader_context", {}).get("state", -1))
            if last_state == 2:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError(f"Engine did not reach READY in {timeout_s:.1f}s (last_state={last_state})")


def _load_corpus(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("Corpus root must be an array")
    return [d for d in data if isinstance(d, dict)]


def _env_truthy(name: str) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _marker_satisfied(expected: str, sanitized: str) -> bool:
    if not expected:
        return True

    alias_map = {
        "[REDACTED:SECRET_LEAK]": {
            "[REDACTED:SECRET_LEAK]",
            "[REDACTED:API_KEY]",
            "[REDACTED:AWS_KEY]",
            "[REDACTED:GH_TOKEN]",
        },
        "[REDACTED:PII]": {
            "[REDACTED:PII]",
            "[REDACTED:EMAIL]",
            "[REDACTED:SSN]",
            "[REDACTED:IP]",
            "[REDACTED:CARD]",
        },
        "[STREAM_BLOCKED:RESTRICTED_PATTERN]": {
            "[STREAM_BLOCKED:RESTRICTED_PATTERN]",
            "[STREAM_BLOCKED:RESTRICTED]",
        },
    }

    valid = alias_map.get(expected, {expected})
    return any(marker in sanitized for marker in valid)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run hazard black-box regression against mock backend")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("tests/hazard_corpus.json"),
        help="Path to hazard corpus JSON",
    )
    parser.add_argument("--backend", type=Path, default=Path("mock_backend.py"), help="Path to mock backend")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11439)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--docker-image", default="sovereign-engine:latest")
    parser.add_argument("--docker-isolation", action="store_true")
    args = parser.parse_args()

    corpus = _load_corpus(args.corpus)
    if not corpus:
        raise RuntimeError("Corpus is empty")

    base_url = f"http://{args.host}:{args.port}"
    docker_isolation = bool(args.docker_isolation or _env_truthy("DOCKER_ISOLATION"))
    if docker_isolation:
        backend_cmd = [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--tmpfs",
            "/tmp",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "NET_BIND_SERVICE",
            "-p",
            f"{args.port}:{args.port}",
            args.docker_image,
            "python",
            "mock_backend.py",
            "--host",
            "0.0.0.0",
            "--port",
            str(args.port),
            "--auto-cycle",
        ]
    else:
        backend_cmd = [
            args.python,
            str(args.backend),
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--auto-cycle",
        ]

    proc = subprocess.Popen(
        backend_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )

    failures: List[str] = []

    try:
        _wait_ready(base_url)

        for case in corpus:
            case_id = str(case.get("id", "unknown"))
            prompt = str(case.get("prompt", ""))
            mode = str(case.get("mode", "REDACT")).upper()
            expected_marker = str(case.get("expected_marker", ""))
            forbidden_regex = str(case.get("forbidden_regex", ""))

            if not prompt:
                failures.append(f"{case_id}: empty prompt")
                continue

            # Auto-cycle may move between IDLE/LOADING/READY; resync before each case.
            try:
                _wait_ready(base_url, timeout_s=20.0)
            except Exception as exc:
                failures.append(f"{case_id}: engine not ready: {exc}")
                continue

            tokens: List[str] = []
            stream_ok = False
            for _attempt in range(3):
                try:
                    tokens = list(
                        _http_post_stream(
                            f"{base_url}/inference/stream",
                            {"prompt": prompt},
                        )
                    )
                    stream_ok = True
                    break
                except error.HTTPError as exc:
                    if exc.code == 409:
                        time.sleep(0.35)
                        continue
                    failures.append(f"{case_id}: HTTP {exc.code} from inference endpoint")
                    break
                except Exception as exc:
                    failures.append(f"{case_id}: stream error: {exc}")
                    break

            if not stream_ok:
                if not any(case_id in f for f in failures):
                    failures.append(f"{case_id}: failed to stream after retries")
                continue

            sanitized = _apply_safety(tokens, mode)

            if not _marker_satisfied(expected_marker, sanitized):
                failures.append(
                    f"{case_id}: missing expected marker '{expected_marker}' | output='{sanitized[:180]}'"
                )

            if forbidden_regex and re.search(forbidden_regex, sanitized):
                failures.append(
                    f"{case_id}: forbidden pattern leaked ({forbidden_regex}) | output='{sanitized[:180]}'"
                )

        if failures:
            print("Regression FAILED")
            for f in failures:
                print(f" - {f}")
            return 1

        print(f"Regression PASSED: {len(corpus)} hazard cases")
        return 0

    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())

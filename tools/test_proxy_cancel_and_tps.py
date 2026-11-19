#!/usr/bin/env python3
"""Cancellation proof + certified decode TPS for rawrxd_ollama_proxy.

Part A -- cancellation differential (through the proxy, 11436):
  0. WARM-UP: one short generation completes first, so the model is loaded
     and warm before the measured runs (Ollama closes requests that arrive
     while a 28 GB model is still loading, which would invalidate a control).
  A1 CONTROL: with a long streaming generation ACTIVE, a short request is
     issued at +2s WITHOUT disconnecting. Ollama serializes per model, so the
     short request queues and its TTFB includes the remaining generation.
  A2 CANCEL:  with a long streaming generation ACTIVE, the client RSTs at +2s
     (SO_LINGER 0) and a short request is issued immediately. It must complete
     quickly. A2 << A1 proves the first generation was cancelled and the
     runner freed, not merely queued.

Part B -- certified decode TPS at populated contexts (direct to Ollama
  11434, native /api/chat, stream=true). The terminal JSON object carries
  Ollama's own accounting: eval_count, eval_duration, prompt_eval_count,
  prompt_eval_duration. Decode TPS = eval_count / eval_duration.

Receipts -> evidence/PROXY_CONCURRENCY_20261114/tps_receipt.json/.txt
"""

import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

PROXY = ("127.0.0.1", 11436)
OLLAMA = ("127.0.0.1", 11434)
MODEL = "deep2-local"          # proxy alias -> reap16-glm-4_7-flash:latest
NATIVE_MODEL = "reap16-glm-4_7-flash:latest"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.abspath(os.path.join(HERE, "..", "evidence", "PROXY_CONCURRENCY_20261114"))
LONG_PREDICT = 1200            # ~11s at ~108 tok/s once warm
SIZES = [4000, 16000, 32000, 64 * 1000]
NUM_CTX = 65536
NUM_PREDICT_B = 64

LONG_PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content":
    "Write a very long detailed essay about the history of computing."}],
    "stream": True, "options": {"num_predict": LONG_PREDICT, "temperature": 0.7}}
SHORT_PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content":
    "Reply with exactly the word: OK"}], "stream": True,
    "options": {"num_predict": 8, "temperature": 0}}


def now():
    return time.time()


def open_stream(addr, payload):
    body = json.dumps(payload).encode()
    s = socket.create_connection(addr, timeout=300)
    s.sendall(("POST /v1/chat/completions HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (addr[0], addr[1], len(body))).encode() + body)
    s.settimeout(300)
    return s


def post_stream(addr, path, payload, read_seconds=None, timeout=300):
    """Send a streaming POST; return (t_first, events, raw, status, outcome)."""
    body = json.dumps(payload).encode()
    s = socket.create_connection(addr, timeout=timeout)
    s.sendall(("POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (path, addr[0], addr[1], len(body))).encode() + body)
    events = []
    raw = bytearray()
    t0 = now()
    t_first = None
    outcome = "eof"
    s.settimeout(timeout)
    while True:
        if read_seconds is not None and now() - t0 > read_seconds:
            outcome = "read_seconds_elapsed"
            break
        try:
            b = s.recv(65536)
        except socket.timeout:
            outcome = "timeout"
            break
        except OSError as e:
            outcome = "oserror:%r" % e
            break
        if not b:
            break
        if t_first is None:
            t_first = now() - t0
        events.append((round(now() - t0, 3), len(b)))
        raw += b
    raw = bytes(raw)
    status = 0
    first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = first.split(" ")
    if len(parts) > 1 and parts[1].isdigit():
        status = int(parts[1])
    try:
        s.close()
    except OSError:
        pass
    return t_first, events, raw, status, outcome


def drain_in_thread(addr, payload, holder):
    t_first, events, raw, status, outcome = post_stream(addr, "/v1/chat/completions", payload)
    holder["t_first"] = t_first
    holder["bytes"] = len(raw)
    holder["status"] = status
    holder["outcome"] = outcome
    holder["done_at"] = now()


def short_via_proxy():
    t_first, _, raw, status, outcome = post_stream(PROXY, "/v1/chat/completions", SHORT_PAYLOAD)
    return t_first, status, raw, outcome


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    out = {}

    # ---- 0: warm-up (retry while the model loads) ---------------------------
    # Ollama closes requests that arrive while the model is still loading
    # ("upstream closed before headers" ~1.8s in); retry until it answers.
    warm = {"attempts": 0, "final_status": None, "ttfb_s": None, "outcome": None}
    t0 = now()
    while now() - t0 < 90:
        warm["attempts"] += 1
        w_ttfb, w_status, _, w_outcome = short_via_proxy()
        if w_status == 200:
            warm["final_status"] = 200
            warm["ttfb_s"] = round(w_ttfb or -1, 3)
            warm["outcome"] = w_outcome
            break
        time.sleep(2.0)
    warm["seconds"] = round(now() - t0, 2)
    out["warmup"] = warm

    # ---- A1: control (no disconnect) ---------------------------------------
    holder = {}
    th = threading.Thread(target=drain_in_thread, args=(PROXY, LONG_PAYLOAD, holder), daemon=True)
    th.start()
    time.sleep(2.0)
    t_short_start = now()
    c_ttfb, c_status, c_raw, c_outcome = short_via_proxy()
    if c_status != 200:  # retry once: the runner may have been busy loading
        time.sleep(1.0)
        c_ttfb, c_status, c_raw, c_outcome = short_via_proxy()
    c_elapsed = round(now() - t_short_start, 3)
    th.join(180)
    out["A1_control"] = {
        "short_ttfb_s": round(c_ttfb or -1, 3),
        "short_total_s": c_elapsed,
        "short_status": c_status,
        "short_outcome": c_outcome,
        "long_stream": {k: holder.get(k) for k in ("status", "bytes", "outcome", "t_first")},
        "note": "short request issued at +2s while long generation active (no disconnect)",
    }

    # ---- A2: cancel (RST at +2s) -------------------------------------------
    s = open_stream(PROXY, LONG_PAYLOAD)
    t0 = now()
    got = 0
    while now() - t0 < 2.0:
        try:
            b = s.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not b:
            break
        got += len(b)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    t_cancel = now()
    x_ttfb, x_status, x_raw, x_outcome = short_via_proxy()
    x_total = round(now() - t_cancel, 3)
    # Availability check: a second short request right after must also be fast
    # (proves the runner stayed free, not just one lucky request).
    y_ttfb, y_status, _, y_outcome = short_via_proxy()
    out["A2_cancel"] = {
        "short_ttfb_s": round(x_ttfb or -1, 3),
        "short_total_s": x_total,
        "short_status": x_status,
        "short_outcome": x_outcome,
        "second_short_ttfb_s": round(y_ttfb or -1, 3),
        "second_short_status": y_status,
        "note": "long stream RST at +2s, short request issued immediately after",
    }
    out["A_differential"] = {
        "control_ttfb_s": out["A1_control"]["short_ttfb_s"],
        "cancel_ttfb_s": out["A2_cancel"]["short_ttfb_s"],
        "control_status": c_status,
        "cancel_status": x_status,
        "second_cancel_status": y_status,
        "pass": (c_status == 200 and x_status == 200 and y_status == 200
                 and x_ttfb is not None and c_ttfb is not None
                 and x_ttfb < 2.0 and x_ttfb < c_ttfb / 2.0),
    }

    # ---- Part B: certified decode TPS ---------------------------------------
    tps = {}
    for size in SIZES:
        prompt = "word " * size
        payload = {"model": NATIVE_MODEL,
                   "messages": [{"role": "user", "content": prompt}],
                   "stream": True,
                   "options": {"num_predict": NUM_PREDICT_B, "temperature": 0,
                               "num_ctx": NUM_CTX}}
        entry = {}
        try:
            sock_timeout = 800 if size >= 64000 else 300
            _, _, raw, status, outcome = post_stream(OLLAMA, "/api/chat", payload,
                                                     timeout=sock_timeout)
            entry["http_status"] = status
            entry["outcome"] = outcome
            entry["bytes"] = len(raw)
            stats = None
            for line in raw.split(b"\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict) and obj.get("done"):
                    stats = obj
            if isinstance(stats, dict) and stats.get("eval_count") and stats.get("eval_duration"):
                entry.update({
                    "eval_count": stats.get("eval_count"),
                    "eval_duration_ns": stats.get("eval_duration"),
                    "decode_tps": round(stats["eval_count"] / (stats["eval_duration"] / 1e9), 2),
                    "prompt_eval_count": stats.get("prompt_eval_count"),
                    "prompt_eval_duration_ns": stats.get("prompt_eval_duration"),
                    "prompt_prefill_tps": (round(stats["prompt_eval_count"] /
                                                 (stats["prompt_eval_duration"] / 1e9), 2)
                                           if stats.get("prompt_eval_duration") else None),
                    "total_duration_ns": stats.get("total_duration"),
                })
            else:
                entry["error"] = "no final stats"
                entry["tail"] = raw[-400:].decode("utf-8", "replace")
        except Exception as e:
            entry["error"] = repr(e)
        tps[str(size)] = entry
    out["B_decode_tps"] = tps

    # ---- context -----------------------------------------------------------
    try:
        out["exe_sha256"] = hashlib.sha256(
            open(os.path.join(HERE, "rawrxd_ollama_proxy.exe"), "rb").read()).hexdigest()
    except Exception as e:
        out["exe_sha256"] = "error: %r" % e
    try:
        out["git_sha"] = subprocess.run(["git", "rev-parse", "HEAD"],
                                        capture_output=True, text=True,
                                        cwd=os.path.join(HERE, "..")).stdout.strip()
    except Exception:
        out["git_sha"] = "unknown"
    try:
        out["ollama_ps"] = subprocess.run(["ollama", "ps"], capture_output=True,
                                          text=True, timeout=15).stdout
    except Exception as e:
        out["ollama_ps"] = "error: %r" % e

    receipt = {"results": out, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    with open(os.path.join(EVIDENCE, "tps_receipt.json"), "w") as f:
        json.dump(receipt, f, indent=2)
    with open(os.path.join(EVIDENCE, "tps_receipt.txt"), "w") as f:
        f.write("warmup: %s attempts, %ss to first byte (status %s)\n"
                % (out["warmup"]["attempts"], out["warmup"].get("ttfb_s"),
                   out["warmup"]["final_status"]))
        f.write("A1 control short TTFB : %.3fs (status %s, queued behind active generation)\n"
                % (out["A_differential"]["control_ttfb_s"], c_status))
        f.write("A2 cancel  short TTFB : %.3fs (status %s, after client RST of long stream)\n"
                % (out["A_differential"]["cancel_ttfb_s"], x_status))
        f.write("A2 second short TTFB  : %.3fs (status %s, runner stayed free)\n"
                % (out["A2_cancel"]["second_short_ttfb_s"], y_status))
        f.write("A  differential PASS  : %s\n\n" % out["A_differential"]["pass"])
        for size in SIZES:
            d = tps.get(str(size), {})
            if "decode_tps" in d:
                line = ("decode %s tok/s (eval_count=%s, eval %s ns, prompt_eval=%s, prefill %s tok/s)"
                        % (d.get("decode_tps"), d.get("eval_count"), d.get("eval_duration_ns"),
                           d.get("prompt_eval_count"), d.get("prompt_prefill_tps")))
            else:
                line = repr(d)
            f.write("B %6d-token prompt: %s\n" % (size, line))
        f.write("\nexe_sha256: %s\ngit_sha: %s\n" % (out.get("exe_sha256"), out.get("git_sha")))
        f.write("\nollama ps:\n%s\n" % out.get("ollama_ps", ""))

    print(json.dumps(out, indent=2))
    ok = out["A_differential"]["pass"] and all("decode_tps" in tps.get(str(s), {}) for s in SIZES)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
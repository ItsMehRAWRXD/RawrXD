#!/usr/bin/env python3
"""128K-context decode TPS point for reap16-glm-4_7-flash:latest.

The Deep2 Local endpoint advertises ~120K input tokens; the model's native
context is 202752. This measures Ollama's own eval_count/eval_duration at a
populated ~128K-token context with num_ctx 131072, plus a warm-up request
that pins the runner to 131072 first (a fresh load takes ~40s).

Writes evidence/PROXY_CONCURRENCY_20261114/ctx128k_receipt.json/.txt
"""

import hashlib
import json
import os
import socket
import subprocess
import sys
import time

OLLAMA = ("127.0.0.1", 11434)
MODEL = "reap16-glm-4_7-flash:latest"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.abspath(os.path.join(HERE, "..", "evidence", "PROXY_CONCURRENCY_20261114"))
NUM_CTX = 131072
PROMPT_WORDS = 128000
NUM_PREDICT = 64


def now():
    return time.time()


def post_chat(payload, timeout):
    body = json.dumps(payload).encode()
    s = socket.create_connection(OLLAMA, timeout=timeout)
    s.sendall(("POST /api/chat HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
               "Content-Length: %d\r\nConnection: close\r\n\r\n"
               % (OLLAMA[0], OLLAMA[1], len(body))).encode() + body)
    raw = bytearray()
    outcome = "eof"
    s.settimeout(timeout)
    t0 = now()
    while True:
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
        raw += b
    raw = bytes(raw)
    try:
        s.close()
    except OSError:
        pass
    return raw, outcome, round(now() - t0, 2)


def parse_stats(raw):
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
    return stats


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    out = {}

    # ---- warm-up at 131072 (pins the runner; a fresh load takes ~40s) ------
    warm_payload = {"model": MODEL, "messages": [{"role": "user", "content": "OK"}],
                    "stream": True, "options": {"num_predict": 4, "temperature": 0,
                                                "num_ctx": NUM_CTX}}
    t0 = now()
    warm_retry = 0
    while now() - t0 < 180 and warm_retry < 30:
        warm_retry += 1
        raw, outcome, secs = post_chat(warm_payload, timeout=300)
        st = parse_stats(raw)
        if st and st.get("eval_count") is not None:
            out["warmup"] = {"attempt": warm_retry, "seconds": secs,
                             "eval_count": st.get("eval_count"),
                             "prompt_eval_count": st.get("prompt_eval_count")}
            break
        time.sleep(3.0)
    else:
        out["warmup"] = {"error": "warmup did not complete",
                         "tail": raw[-300:].decode("utf-8", "replace") if 'raw' in dir() else ""}

    # ---- 128K populated context ---------------------------------------------
    prompt = "word " * PROMPT_WORDS
    payload = {"model": MODEL, "messages": [{"role": "user", "content": prompt}],
               "stream": True, "options": {"num_predict": NUM_PREDICT, "temperature": 0,
                                           "num_ctx": NUM_CTX}}
    raw, outcome, secs = post_chat(payload, timeout=1500)
    stats = parse_stats(raw)
    if isinstance(stats, dict) and stats.get("eval_count") and stats.get("eval_duration"):
        out["ctx128k"] = {
            "prompt_words": PROMPT_WORDS,
            "eval_count": stats.get("eval_count"),
            "eval_duration_ns": stats.get("eval_duration"),
            "decode_tps": round(stats["eval_count"] / (stats["eval_duration"] / 1e9), 2),
            "prompt_eval_count": stats.get("prompt_eval_count"),
            "prompt_eval_duration_ns": stats.get("prompt_eval_duration"),
            "prompt_prefill_tps": (round(stats["prompt_eval_count"] /
                                         (stats["prompt_eval_duration"] / 1e9), 2)
                                   if stats.get("prompt_eval_duration") else None),
            "total_duration_ns": stats.get("total_duration"),
            "wall_seconds": secs,
            "outcome": outcome,
        }
    else:
        out["ctx128k"] = {"error": "no final stats", "outcome": outcome,
                          "wall_seconds": secs, "bytes": len(raw),
                          "tail": raw[-400:].decode("utf-8", "replace")}

    try:
        out["ollama_ps"] = subprocess.run(["ollama", "ps"], capture_output=True,
                                          text=True, timeout=15).stdout
    except Exception as e:
        out["ollama_ps"] = "error: %r" % e
    try:
        out["exe_sha256"] = hashlib.sha256(
            open(os.path.join(HERE, "rawrxd_ollama_proxy.exe"), "rb").read()).hexdigest()
    except Exception:
        out["exe_sha256"] = "n/a"
    try:
        out["git_sha"] = subprocess.run(["git", "rev-parse", "HEAD"],
                                        capture_output=True, text=True,
                                        cwd=os.path.join(HERE, "..")).stdout.strip()
    except Exception:
        out["git_sha"] = "unknown"

    with open(os.path.join(EVIDENCE, "ctx128k_receipt.json"), "w") as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(EVIDENCE, "ctx128k_receipt.txt"), "w") as f:
        f.write("warmup: %s\n" % json.dumps(out.get("warmup"), indent=2))
        f.write("ctx128k: %s\n" % json.dumps(out.get("ctx128k"), indent=2))
        f.write("\nexe_sha256: %s\ngit_sha: %s\n\nollama ps:\n%s\n"
                % (out.get("exe_sha256"), out.get("git_sha"), out.get("ollama_ps", "")))
    print(json.dumps(out, indent=2))
    return 0 if "decode_tps" in out.get("ctx128k", {}) else 1


if __name__ == "__main__":
    sys.exit(main())
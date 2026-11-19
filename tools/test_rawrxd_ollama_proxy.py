#!/usr/bin/env python3
"""Concurrency / streaming / cancellation regression for rawrxd_ollama_proxy.

This is the acceptance harness for the C++ proxy that replaced the
single-threaded PowerShell proxy. The PowerShell proxy hung because one
blocking request loop meant a long streaming generation froze /v1/models and
every new connection; it also buffered responses instead of streaming.

Gates (each PASS/FAIL with evidence):
  G1 MODELS_IDLE    /v1/models -> 200 promptly with no other traffic.
  G2 STREAM_INCR    streaming completion: many SSE recv events spread over
                    time (incremental delivery), terminal [DONE] received.
  G3 MODELS_DURING  /v1/models answers 200 promptly WHILE a long generation
                    is streaming (the original hang).
  G4 MODELS_AFTER   /v1/models answers 200 promptly after the stream ends.
  G5 ALIAS          "deep2-local" resolves to the REAP16 model (the proxied
                    request succeeds and produces content).
  G6 CANCEL         client disconnect mid-stream: a short generation started
                    right after completes promptly (the cancelled generation
                    is not still occupying the GPU).
  G7 SHUTDOWN       checked separately: proxy exits cleanly on stop.

Writes receipt.json and receipt.txt into
evidence/PROXY_CONCURRENCY_20261114/ next to the repo root.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

HOST = "127.0.0.1"
PORT = 11436
MODEL = "deep2-local"  # proxy alias -> reap16-glm-4_7-flash:latest
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.abspath(os.path.join(HERE, "..", "evidence", "PROXY_CONCURRENCY_20261114"))

LONG_PROMPT = (
    "Write a detailed technical essay (at least 350 words) about the history "
    "of computing machines: the abacus, mechanical calculators, "
    "electromechanical tabulators, vacuum-tube computers, transistor "
    "machines, integrated circuits, microprocessors, and modern GPUs. Cover "
    "each era with concrete machines and years."
)
SHORT_PROMPT = "Reply with exactly the word: OK"

_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def now():
    return time.time()


def probe_models(timeout=5.0):
    t0 = now()
    req = urllib.request.Request("http://%s:%d/v1/models" % (HOST, PORT))
    with _opener.open(req, timeout=timeout) as r:
        body = r.read()
    return {"status": r.status, "ms": round((now() - t0) * 1000.0, 1),
            "bytes": len(body),
            "body_head": body[:120].decode("utf-8", "replace")}


def open_stream(prompt, num_predict):
    payload = json.dumps({
        "model": MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": True,
        "options": {"temperature": 0.7, "num_predict": num_predict},
    }).encode()
    s = socket.create_connection((HOST, PORT), timeout=300)
    s.sendall(
        ("POST /v1/chat/completions HTTP/1.1\r\n"
         "Host: %s:%d\r\n"
         "Content-Type: application/json\r\n"
         "Content-Length: %d\r\n"
         "Connection: close\r\n\r\n" % (HOST, PORT, len(payload))).encode() + payload)
    return s


def read_stream(s, stop_after=None):
    """Read raw bytes with arrival timestamps until EOF / timeout / stop_after."""
    events = []
    t0 = now()
    s.settimeout(300)
    while True:
        if stop_after is not None and now() - t0 > stop_after:
            break
        try:
            b = s.recv(65536)
        except socket.timeout:
            break
        except OSError:
            break
        if not b:
            break
        events.append((round(now() - t0, 3), len(b)))
    return events


def status_of(raw_head):
    first = raw_head.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = first.split(" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    results = {}
    evidence = {}

    # ---- G1: models endpoint idle -----------------------------------------
    try:
        r = probe_models()
        results["G1_MODELS_IDLE"] = r["status"] == 200 and r["ms"] < 2000
        evidence["g1"] = r
    except Exception as e:
        results["G1_MODELS_IDLE"] = False
        evidence["g1"] = {"error": repr(e)}

    # ---- G2/G3: long stream + models polls during --------------------------
    holder = {}

    def run_long_stream_capture():
        s = open_stream(LONG_PROMPT, 400)
        events = []
        raw = bytearray()
        t0 = now()
        s.settimeout(300)
        while now() - t0 < 240:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not b:
                break
            events.append((round(now() - t0, 3), len(b)))
            raw += b
        s.close()
        holder["events"] = events
        holder["raw"] = bytes(raw)

    th = threading.Thread(target=run_long_stream_capture, daemon=True)
    t_start = now()
    th.start()

    polls = []
    while th.is_alive() and now() - t_start < 300:
        try:
            polls.append(probe_models(timeout=5))
        except Exception as e:
            polls.append({"status": 0, "error": repr(e), "ms": -1})
        time.sleep(1.0)
    th.join(timeout=5)

    events = holder.get("events", [])
    raw = holder.get("raw", b"")
    raw_head = raw.split(b"\r\n\r\n", 1)[0]
    stream_status = status_of(raw_head)
    n_recv = len(events)
    t_first = events[0][0] if events else -1
    t_last = events[-1][0] if events else -1
    span = round(t_last - t_first, 2)
    data_events = raw.count(b"data: ")
    done = b"[DONE]" in raw

    results["G2_STREAM_INCR"] = (
        stream_status == 200 and done and data_events >= 10
        and n_recv >= 5 and span >= 3.0
    )
    evidence["g2"] = {
        "status": stream_status, "recv_events": n_recv,
        "first_recv_s": t_first, "last_recv_s": t_last, "span_s": span,
        "data_events": data_events, "done_marker": done,
        "total_bytes": len(raw),
        "recv_timeline_s": [t for t, _ in events],
    }

    during = [p for p in polls if p.get("status") == 200 and p.get("ms", 9999) < 2000]
    results["G3_MODELS_DURING"] = len(during) >= 3
    evidence["g3"] = {
        "polls_total": len(polls), "polls_200_under_2s": len(during),
        "max_ms": max((p.get("ms", -1) for p in polls), default=-1),
        "samples": polls[:5],
    }

    # ---- G4: models after ---------------------------------------------------
    try:
        r = probe_models()
        results["G4_MODELS_AFTER"] = r["status"] == 200 and r["ms"] < 2000
        evidence["g4"] = r
    except Exception as e:
        results["G4_MODELS_AFTER"] = False
        evidence["g4"] = {"error": repr(e)}

    # ---- G5: alias ----------------------------------------------------------
    results["G5_ALIAS"] = bool(stream_status == 200 and data_events >= 10)
    evidence["g5"] = {"requested_model": MODEL,
                      "stream_status": stream_status,
                      "data_events": data_events}

    # ---- G6: cancellation ---------------------------------------------------
    try:
        s = open_stream(LONG_PROMPT, 400)
        read_stream(s, stop_after=5)
        # Aborted client: RST on close so the proxy sees the failure at once.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                     struct.pack("ii", 1, 0))
        s.close()
        t_cancel = now()
        short = open_stream(SHORT_PROMPT, 8)
        short.settimeout(60)
        raw2 = bytearray()
        while True:
            try:
                b = short.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not b:
                break
            raw2 += b
        short.close()
        dt = now() - t_cancel
        st2 = status_of(bytes(raw2.split(b"\r\n\r\n", 1)[0]))
        produced = b"data: " in bytes(raw2)
        results["G6_CANCEL"] = st2 == 200 and produced and dt < 45
        evidence["g6"] = {"short_status": st2, "short_seconds": round(dt, 2),
                          "short_produced_data": produced}
    except Exception as e:
        results["G6_CANCEL"] = False
        evidence["g6"] = {"error": repr(e)}

    # ---- context for the receipt -------------------------------------------
    try:
        tags = _opener.open("http://%s:%d/api/tags" % (HOST, 11434), timeout=5).read()
        evidence["ollama_tags_head"] = tags[:200].decode("utf-8", "replace")
    except Exception as e:
        evidence["ollama_tags_head"] = "error: %r" % e
    try:
        evidence["git_sha"] = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
            cwd=os.path.join(HERE, "..")).stdout.strip()
    except Exception:
        evidence["git_sha"] = "unknown"

    receipt = {"results": results, "evidence": evidence,
               "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    with open(os.path.join(EVIDENCE, "receipt.json"), "w") as f:
        json.dump(receipt, f, indent=2)
    with open(os.path.join(EVIDENCE, "receipt.txt"), "w") as f:
        for k in sorted(results):
            f.write("%s %s\n" % (k, "PASS" if results[k] else "FAIL"))
        f.write("\nevidence:\n")
        f.write(json.dumps(evidence, indent=2) + "\n")

    print(json.dumps(receipt, indent=2))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
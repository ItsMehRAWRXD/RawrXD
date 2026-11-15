#!/usr/bin/env python3
"""Cancel confirmation on a warm runner (num_ctx pinned 65536).

Ollama semantics discovered during certification: while the runner is BUSY
(generating or loading), new connections are closed after ~1.8s
("upstream closed before headers") -- Ollama does not queue them. That makes
the "control" (second request during generation) return 502 by design, and it
makes the cancel test decisive: if the abandoned generation were still
computing, the post-RST short request would be closed at ~1.8s; a fast 200
proves the runner was freed (i.e., the RST cancelled the generation).

Sequence: warmup-retry (model loaded at 65536) -> long stream -> RST at +2s
-> short request (expect < 2s, 200) -> second short request (expect < 2s).
"""

import json
import os
import socket
import struct
import sys
import time

PROXY = ("127.0.0.1", 11436)
MODEL = "deep2-local"
HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.abspath(os.path.join(HERE, "..", "evidence", "PROXY_CONCURRENCY_20261114"))

LONG_PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content":
    "Write a very long detailed essay about the history of computing."}],
    "stream": True, "options": {"num_predict": 1200, "temperature": 0.7,
                                "num_ctx": 65536}}
SHORT_PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content":
    "Reply with exactly the word: OK"}], "stream": True,
    "options": {"num_predict": 8, "temperature": 0, "num_ctx": 65536}}


def now():
    return time.time()


def post(payload, timeout=300):
    body = json.dumps(payload).encode()
    s = socket.create_connection(PROXY, timeout=timeout)
    s.sendall(("POST /v1/chat/completions HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (PROXY[0], PROXY[1], len(body))).encode() + body)
    s.settimeout(timeout)
    raw = bytearray()
    outcome = "eof"
    t0 = now()
    t_first = None
    while True:
        try:
            b = s.recv(65536)
        except socket.timeout:
            outcome = "timeout"
            break
        except OSError:
            outcome = "oserror"
            break
        if not b:
            break
        if t_first is None:
            t_first = now() - t0
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
    return t_first, status, raw, outcome


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    out = {}

    # warmup-retry: requests during load are closed at ~1.8s; retry until 200
    t0 = now()
    warm = None
    attempts = 0
    while now() - t0 < 120 and attempts < 30:
        attempts += 1
        ttfb, status, _, outcome = post(SHORT_PAYLOAD, timeout=60)
        if status == 200:
            warm = {"attempt": attempts, "ttfb_s": round(ttfb or -1, 3),
                    "outcome": outcome}
            break
        time.sleep(2.0)
    out["warmup"] = warm or {"error": "did not warm within 120s"}

    # long stream, RST at +2s
    body = json.dumps(LONG_PAYLOAD).encode()
    s = socket.create_connection(PROXY, timeout=300)
    s.sendall(("POST /v1/chat/completions HTTP/1.1\r\nHost: %s:%d\r\n"
               "Content-Type: application/json\r\nContent-Length: %d\r\n"
               "Connection: close\r\n\r\n" % (PROXY[0], PROXY[1], len(body))).encode() + body)
    s.settimeout(300)
    t0 = now()
    got = 0
    while now() - t0 < 2.0:
        try:
            b = s.recv(65536)
        except (socket.timeout, OSError):
            break
        if not b:
            break
        got += len(b)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()
    t_cancel = now()
    out["long_stream_bytes_before_rst"] = got

    ttfb1, status1, _, outcome1 = post(SHORT_PAYLOAD, timeout=60)
    dt1 = round(now() - t_cancel, 3)
    ttfb2, status2, _, outcome2 = post(SHORT_PAYLOAD, timeout=60)
    dt2 = round(now() - t_cancel, 3)

    out["after_rst"] = {
        "first_short": {"ttfb_s": round(ttfb1 or -1, 3), "status": status1,
                        "total_s": dt1, "outcome": outcome1},
        "second_short": {"ttfb_s": round(ttfb2 or -1, 3), "status": status2,
                         "total_s": dt2, "outcome": outcome2},
    }
    out["pass"] = (status1 == 200 and status2 == 200
                   and ttfb1 is not None and ttfb1 < 2.0
                   and ttfb2 is not None and ttfb2 < 2.0)

    with open(os.path.join(EVIDENCE, "cancel_confirm_receipt.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
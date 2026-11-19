#!/usr/bin/env python3
"""Differential: which upstream request shape makes Ollama close at ~1.8s?

Loads are observed to close proxy-style requests (Connection: close, no
User-Agent, no Accept) at ~1.8s while the CLI (native /api/chat, keep-alive)
loads fine. This sends both shapes directly to Ollama with the model unloaded
and compares outcomes.

Usage: py test_upstream_shape.py
"""

import json
import socket
import subprocess
import sys
import time

OLLAMA = ("127.0.0.1", 11434)
MODEL = "reap16-glm-4_7-flash:latest"

PAYLOAD = {"model": MODEL, "messages": [{"role": "user", "content": "OK"}],
           "stream": True, "options": {"num_predict": 4, "num_ctx": 65536}}


def send(headers, body, timeout=60):
    s = socket.create_connection(OLLAMA, timeout=timeout)
    s.sendall(headers.encode() + body)
    raw = bytearray()
    outcome = "eof"
    t0 = time.time()
    t_first = None
    s.settimeout(timeout)
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
            t_first = round(time.time() - t0, 3)
        raw += b
    try:
        s.close()
    except OSError:
        pass
    raw = bytes(raw)
    status = 0
    first = raw.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = first.split(" ")
    if len(parts) > 1 and parts[1].isdigit():
        status = int(parts[1])
    return {"status": status, "t_first": t_first, "bytes": len(raw),
            "outcome": outcome, "head": raw[:120].decode("latin1", "replace")}


def main():
    body = json.dumps(PAYLOAD).encode()
    clen = len(body)

    # unload first so both tests exercise the load path
    subprocess.run(["ollama", "stop", MODEL], capture_output=True, text=True, timeout=60)
    time.sleep(2.0)

    proxy_style = (
        "POST /v1/chat/completions HTTP/1.1\r\n"
        "Host: 127.0.0.1:11434\r\n"
        "Connection: close\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n\r\n" % clen
    )
    r1 = send(proxy_style, body)
    print("proxy-style:", json.dumps(r1))

    # unload again so the second test also starts unloaded
    subprocess.run(["ollama", "stop", MODEL], capture_output=True, text=True, timeout=60)
    time.sleep(2.0)

    curl_style = (
        "POST /v1/chat/completions HTTP/1.1\r\n"
        "Host: 127.0.0.1:11434\r\n"
        "User-Agent: curl/8.0\r\n"
        "Accept: */*\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n\r\n" % clen
    )
    r2 = send(curl_style, body)
    print("curl-style:", json.dumps(r2))

    print(json.dumps({"proxy_style": r1, "curl_style": r2}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
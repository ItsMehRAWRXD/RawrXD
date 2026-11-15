#!/usr/bin/env python3
"""TCP tap: pretend to be Ollama on 127.0.0.1:11435, log the exact bytes the
C++ proxy sends upstream, and reply with a minimal SSE stream.

Run:  py tap_upstream.py
Then: rawrxd_ollama_proxy.exe --listen 11437 --upstream 11435
Then: curl --noproxy "*" -N -H "Content-Type: application/json" \
        -d '{"model":"deep2-local","messages":[{"role":"user","content":"OK"}],"stream":true}' \
        http://127.0.0.1:11437/v1/chat/completions
Captured request -> tap_upstream_request.txt
"""

import re
import socket
import threading

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 11435))
srv.listen(8)
print("[tap] listening on 127.0.0.1:11435", flush=True)


def handle(c):
    c.settimeout(10)
    data = b""
    try:
        while True:
            b = c.recv(65536)
            if not b:
                break
            data += b
            if b"\r\n\r\n" in data:
                head, _, body = data.partition(b"\r\n\r\n")
                m = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
                if m and len(body) >= int(m.group(1)):
                    break
    except socket.timeout:
        pass
    except OSError:
        pass
    with open("tap_upstream_request.txt", "wb") as f:
        f.write(data)
    print("[tap] captured %d bytes" % len(data), flush=True)
    resp = (b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n")
    body = (b'data: {"id":"x","object":"chat.completion.chunk","choices":[{"index":0,'
            b'"delta":{"content":"OK"},"finish_reason":null}]}\n\n'
            b"data: [DONE]\n\n")
    try:
        c.sendall(resp + hex(len(body))[2:].encode() + b"\r\n" + body + b"\r\n0\r\n\r\n")
    except OSError:
        pass
    try:
        c.close()
    except OSError:
        pass


while True:
    c, _ = srv.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
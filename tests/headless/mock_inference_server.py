#!/usr/bin/env python3
"""Deterministic, dependency-free OpenAI-compatible mock for IDE integration gates.

Contract scope: HTTP transport, JSON request validation, SSE framing, streaming,
cancellation by disconnect, deterministic output, and explicit failure responses.
Does NOT certify actual model inference, GPU execution, or Win32 UI behavior.
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "rawrxd-fixture-v1"
TOKENS = ("fixture", " response", " complete")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        if not getattr(self.server, "quiet", False):
            super().log_message(format, *args)

    def send_json(self, status, value):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/health", "/healthz"):
            return self.send_json(200, {"status": "ok", "fixture": True})
        if self.path == "/v1/models":
            return self.send_json(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
        return self.send_json(404, {"error": {"message": "unknown endpoint"}})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self.send_json(404, {"error": {"message": "unknown endpoint"}})
        try:
            size = int(self.headers.get("Content-Length", "-1"))
            if size < 0 or size > 1024 * 1024:
                return self.send_json(413, {"error": {"message": "invalid request length"}})
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
                return self.send_json(400, {"error": {"message": "messages must be an array"}})
            if body.get("model", MODEL) != MODEL:
                return self.send_json(404, {"error": {"message": "unknown model"}})
            if type(body.get("stream", False)) is not bool:
                return self.send_json(400, {"error": {"message": "stream must be boolean"}})
            if body.get("stream") is True:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                for index, token in enumerate(TOKENS):
                    frame = {"id": "fixture-1", "object": "chat.completion.chunk",
                             "model": MODEL, "choices": [{"index": 0, "delta":
                             {"role": "assistant"} if index == 0 else {"content": token},
                             "finish_reason": None}]}
                    if index == 0:
                        self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())
                        frame["choices"][0]["delta"] = {"content": token}
                    self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())
                    self.wfile.flush()
                    time.sleep(self.server.delay)
                self.wfile.write(b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
                self.wfile.flush()
                return
            self.send_json(200, {"id": "fixture-1", "object": "chat.completion",
                "model": MODEL, "choices": [{"index": 0, "message":
                {"role": "assistant", "content": "".join(TOKENS)}, "finish_reason": "stop"}]})
        except (ValueError, TypeError, UnicodeError):
            self.send_json(400, {"error": {"message": "invalid JSON"}})
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client cancellation is expected, not a server failure.


def start(host="127.0.0.1", port=0, delay=0.0, quiet=True):
    server = ThreadingHTTPServer((host, port), Handler)
    server.delay, server.quiet = delay, quiet
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()
    if args.delay < 0:
        parser.error("--delay must be nonnegative")
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.delay, server.quiet = args.delay, False
    print("Mock inference endpoint listening at http://%s:%d" % server.server_address, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

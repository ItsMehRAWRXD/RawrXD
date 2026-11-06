#!/usr/bin/env python3
"""Loopback-only deterministic OpenAI-compatible mock; NOT model inference."""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "rawrxd-smoke-mock"
MAX_BODY = 1024 * 1024

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_json(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"status": "ok", "mock": True})
        if self.path == "/v1/models":
            return self.send_json(200, {"object": "list", "data": [
                {"id": MODEL, "object": "model", "owned_by": "local-mock"}]})
        return self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            return self.send_json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self.send_json(413, {"error": "invalid request size"})
        try:
            data = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return self.send_json(400, {"error": "invalid JSON"})
        if not isinstance(data, dict) or data.get("model") != MODEL or not isinstance(data.get("messages"), list):
            return self.send_json(400, {"error": "invalid model or messages"})
        if any(not isinstance(m, dict) or not isinstance(m.get("role"), str)
               or not isinstance(m.get("content"), str) for m in data["messages"]):
            return self.send_json(400, {"error": "invalid message"})
        if data.get("stream") is True:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            for delta, finish in [({"content": "MOCK_RESPONSE_OK"}, None), ({}, "stop")]:
                event = {"id": "mock-1", "object": "chat.completion.chunk", "model": MODEL,
                         "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
                self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            return
        return self.send_json(200, {"id": "mock-1", "object": "chat.completion",
            "model": MODEL, "choices": [{"index": 0, "message":
            {"role": "assistant", "content": "MOCK_RESPONSE_OK"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("invalid port")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print("Mock model on http://127.0.0.1:%d" % server.server_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()

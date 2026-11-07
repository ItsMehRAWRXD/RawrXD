"""Executable HTTP smoke tests. PASS covers mock transport only, not RawrXD integration."""
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from mock_model_server import Handler, MODEL

class MockTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def request(self, method, path, obj=None, raw=None, extra_headers=None):
        body = json.dumps(obj).encode() if obj is not None else raw
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            headers = {"Content-Type": "application/json"}
            if extra_headers:
                headers.update(extra_headers)
            conn.request(method, path, body=body, headers=headers)
            res = conn.getresponse()
            return res.status, dict(res.getheaders()), res.read()
        finally:
            conn.close()

    def test_health(self):
        code, _, body = self.request("GET", "/health")
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(body)["mock"])

    def test_models(self):
        code, _, body = self.request("GET", "/v1/models")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["data"][0]["id"], MODEL)

    def test_completion(self):
        code, _, body = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "MOCK_RESPONSE_OK")

    def test_stream(self):
        code, headers, body = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [], "stream": True})
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertIn(b"MOCK_RESPONSE_OK", body)
        events = [json.loads(line[6:]) for line in body.splitlines()
                  if line.startswith(b"data: ") and line != b"data: [DONE]"]
        self.assertEqual(events[0]["choices"][0]["delta"]["role"], "assistant")
        self.assertEqual(events[1]["choices"][0]["delta"]["content"], "MOCK_RESPONSE_OK")
        self.assertEqual(events[-1]["choices"][0]["finish_reason"], "stop")
        self.assertTrue(body.endswith(b"data: [DONE]\n\n"))

    def test_parallel_completion_requests(self):
        # Exercise ThreadingHTTPServer under simultaneous client connections.
        from concurrent.futures import ThreadPoolExecutor
        payload = {"model": MODEL, "messages": [{"role": "user", "content": "parallel"}]}
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: self.request("POST", "/v1/chat/completions", payload), range(24)))
        self.assertEqual(len(responses), 24)
        for code, _, body in responses:
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "MOCK_RESPONSE_OK")

    def test_recovery_after_bad_request(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", raw=b"{")
        self.assertEqual(code, 400)
        code, _, body = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "user", "content": "after error"}]})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "MOCK_RESPONSE_OK")

    def test_streaming_client_reassembles_completion(self):
        # Consume the actual SSE wire format as a client, not just substring-match.
        code, headers, body = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "user", "content": "stream"}], "stream": True})
        self.assertEqual(code, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        chunks = []
        finished = False
        done = False
        for record in body.split(b"\n\n"):
            if not record:
                continue
            self.assertTrue(record.startswith(b"data: "))
            payload = record[6:]
            if payload == b"[DONE]":
                done = True
                continue
            self.assertFalse(done, "data received after DONE")
            event = json.loads(payload)
            self.assertEqual(event["model"], MODEL)
            choice = event["choices"][0]
            chunks.append(choice["delta"].get("content", ""))
            if choice["finish_reason"] == "stop":
                finished = True
        self.assertEqual("".join(chunks), "MOCK_RESPONSE_OK")
        self.assertTrue(finished)
        self.assertTrue(done)

    def test_wrong_model(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", {"model": "not-mock", "messages": []})
        self.assertEqual(code, 400)

    def test_empty_body_rejected(self):
        code, _, body = self.request("POST", "/v1/chat/completions", raw=b"")
        self.assertEqual(code, 400)
        self.assertIn(b"empty request body", body)

    def test_invalid_json(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", raw=b"{")
        self.assertEqual(code, 400)

    def test_invalid_message(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", {"model": MODEL, "messages": [1]})
        self.assertEqual(code, 400)

    def test_invalid_role_rejected(self):
        code, _, _ = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "not-a-role", "content": "hi"}]})
        self.assertEqual(code, 400)

    def test_valid_system_user_roles(self):
        code, _, body = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [
                {"role": "system", "content": "test"},
                {"role": "user", "content": "hi"}]})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "MOCK_RESPONSE_OK")

    def test_unknown_route(self):
        code, _, _ = self.request("GET", "/unknown")
        self.assertEqual(code, 404)

    def test_rejected_request_closes_connection(self):
        import socket
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=3) as sock:
            sock.settimeout(3)
            request = (b"POST /v1/chat/completions HTTP/1.1\r\n"
                       b"Host: 127.0.0.1\r\nContent-Length: 1048577\r\n"
                       b"Connection: keep-alive\r\n\r\n")
            sock.sendall(request)
            data = bytearray()
            while True:
                part = sock.recv(4096)
                if not part:
                    break
                data.extend(part)
            self.assertIn(b"413", data.split(b"\r\n", 1)[0])

    def test_oversized_body(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", raw=b"",
            extra_headers={"Content-Length": str(1024 * 1024 + 1)})
        self.assertEqual(code, 413)

if __name__ == "__main__":
    unittest.main()

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
        self.assertTrue(body.endswith(b"data: [DONE]\n\n"))

    def test_wrong_model(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", {"model": "not-mock", "messages": []})
        self.assertEqual(code, 400)

    def test_invalid_json(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", raw=b"{")
        self.assertEqual(code, 400)

    def test_invalid_message(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", {"model": MODEL, "messages": [1]})
        self.assertEqual(code, 400)

    def test_unknown_route(self):
        code, _, _ = self.request("GET", "/unknown")
        self.assertEqual(code, 404)

    def test_oversized_body(self):
        code, _, _ = self.request("POST", "/v1/chat/completions", raw=b"",
            extra_headers={"Content-Length": str(1024 * 1024 + 1)})
        self.assertEqual(code, 413)

if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Run deterministic mock inference HTTP acceptance gates without external models."""
import http.client
import json
import unittest
from mock_inference_server import MODEL, start


class MockContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
        response = conn.getresponse()
        status, headers, data = response.status, response.headers, response.read()
        conn.close()
        return status, headers, data

    def test_health(self):
        status, _, data = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(data)["fixture"])

    def test_models(self):
        status, _, data = self.request("GET", "/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["data"][0]["id"], MODEL)

    def test_completion(self):
        status, _, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "user", "content": "hello"}]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"], "fixture response complete")

    def test_streaming(self):
        status, headers, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [], "stream": True})
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers["Content-Type"])
        frames = [line[6:] for line in data.decode().splitlines() if line.startswith("data: ")]
        self.assertEqual(frames[-1], "[DONE]")
        self.assertEqual("".join(json.loads(frame)["choices"][0]["delta"].get("content", "")
                         for frame in frames[:-1]), "fixture response complete")

    def test_invalid_utf8_returns_json_error(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        conn.request("POST", "/v1/chat/completions", body=b"\\xff",
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.read())["error"]["message"], "invalid JSON")
        conn.close()

    def test_truncated_json_returns_error(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        conn.request("POST", "/v1/chat/completions", body=b'{"messages":[',
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        self.assertEqual(response.status, 400)
        self.assertIn("error", json.loads(response.read()))
        conn.close()

    def test_injected_503_then_recovery(self):
        status, _, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [], "mock_failure": True})
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(data)["error"]["type"], "service_unavailable")
        status, _, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": []})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"],
                         "fixture response complete")

    def test_invalid_failure_flag(self):
        status, _, _ = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [], "mock_failure": 1})
        self.assertEqual(status, 400)

    def test_rejects_malformed_message_entries(self):
        cases = [None, "hello", 123, {}, {"role": "unknown", "content": "x"},
                 {"role": "user"}, {"role": "user", "content": 123}]
        for entry in cases:
            with self.subTest(entry=entry):
                status, _, data = self.request("POST", "/v1/chat/completions",
                    {"model": MODEL, "messages": [entry]})
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(data)["error"]["message"],
                                 "invalid message entry")

    def test_accepts_valid_message_entries(self):
        status, _, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [
                {"role": "system", "content": "system"},
                {"role": "user", "content": "hello"}]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"],
                         "fixture response complete")

    def test_invalid_messages(self):
        status, _, _ = self.request("POST", "/v1/chat/completions", {"messages": "invalid"})
        self.assertEqual(status, 400)

    def test_unknown_model(self):
        status, _, _ = self.request("POST", "/v1/chat/completions",
            {"model": "not-installed", "messages": []})
        self.assertEqual(status, 404)

    def test_stream_flag_rejects_integer(self):
        status, _, _ = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [], "stream": 1})
        self.assertEqual(status, 400)

    def test_missing_messages(self):
        status, _, _ = self.request("POST", "/v1/chat/completions", {"model": MODEL})
        self.assertEqual(status, 400)

    def test_healthz_alias(self):
        status, _, data = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["status"], "ok")

    def test_repeated_requests_do_not_leak_state(self):
        for _ in range(10):
            status, _, data = self.request("POST", "/v1/chat/completions",
                {"model": MODEL, "messages": []})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data)["choices"][0]["message"]["content"],
                             "fixture response complete")

    def test_cancel_stream_then_new_request(self):
        # Transport-only A -> disconnect -> B. Does not certify IDE Stop.
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        conn.request("POST", "/v1/chat/completions",
            body=json.dumps({"model": MODEL, "messages": [], "stream": True}),
            headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn(b"data: ", response.readline())
        conn.close()
        # B must still succeed after A's socket is disconnected.
        status, _, data = self.request("POST", "/v1/chat/completions",
            {"model": MODEL, "messages": [{"role": "user", "content": "B"}]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["choices"][0]["message"]["content"],
                         "fixture response complete")

    def test_parallel_requests(self):
        from concurrent.futures import ThreadPoolExecutor
        def call(_):
            status, _, data = self.request("POST", "/v1/chat/completions",
                {"model": MODEL, "messages": []})
            return status, json.loads(data)["choices"][0]["message"]["content"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(call, range(32)))
        self.assertEqual(results, [(200, "fixture response complete")] * 32)

    def test_unknown_endpoint(self):
        status, _, _ = self.request("GET", "/not-real")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Deterministic model-free protocol smoke test. Does NOT certify Deep2 inference."""
import json
import unittest

class MockBackend:
    def __init__(self):
        self.requests = {}
        self.edits = {}
    def start(self, request_id, prompt):
        if not request_id or request_id in self.requests:
            raise ValueError("duplicate or empty request id")
        self.requests[request_id] = {"prompt": prompt, "cancelled": False}
    def stream(self, request_id):
        state = self.requests[request_id]
        for token in ("MOCK_", "DONE"):
            if state["cancelled"]:
                return
            yield {"request_id": request_id, "delta": token}
    def cancel(self, request_id):
        self.requests[request_id]["cancelled"] = True
    def apply_edit(self, path, old, new, approved=False):
        if not approved:
            raise PermissionError("mutation requires approval")
        if not path or ".." in path.replace("\\", "/").split("/"):
            raise ValueError("invalid path")
        current = self.edits.get(path, "")
        if old not in current:
            raise ValueError("old text not found")
        self.edits[path] = current.replace(old, new, 1)

class ProtocolSmoke(unittest.TestCase):
    def setUp(self):
        self.backend = MockBackend()
    def test_stream_and_request_id(self):
        self.backend.start("r1", "hello")
        self.assertEqual("".join(x["delta"] for x in self.backend.stream("r1")), "MOCK_DONE")
        self.assertTrue(all(x["request_id"] == "r1" for x in self.backend.stream("r1")))
    def test_cancel(self):
        self.backend.start("r1", "hello")
        self.backend.cancel("r1")
        self.assertEqual(list(self.backend.stream("r1")), [])
    def test_duplicate_request_rejected(self):
        self.backend.start("r1", "hello")
        with self.assertRaises(ValueError):
            self.backend.start("r1", "again")
    def test_mutation_denied_by_default(self):
        with self.assertRaises(PermissionError):
            self.backend.apply_edit("a.cpp", "", "x")
    def test_approved_edit(self):
        self.backend.edits["a.cpp"] = "old"
        self.backend.apply_edit("a.cpp", "old", "new", approved=True)
        self.assertEqual(self.backend.edits["a.cpp"], "new")
    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.backend.apply_edit("../a.cpp", "", "x", approved=True)
    def test_missing_old_text_rejected(self):
        with self.assertRaises(ValueError):
            self.backend.apply_edit("a.cpp", "missing", "new", approved=True)
    def test_json_event_roundtrip(self):
        self.backend.start("r1", "hello")
        event = next(self.backend.stream("r1"))
        self.assertEqual(json.loads(json.dumps(event)), event)

if __name__ == "__main__":
    unittest.main(verbosity=2)

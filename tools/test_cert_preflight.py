"""Offline tests for the portable 15-gate evidence validator."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from cert_preflight import GATES, validate

SHA = "a" * 64
HEAD = "b" * 40


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = {"candidate_sha256": SHA, "source_commit": HEAD,
                         "certified": True, "promote": True, "gates": {}}
        for gate in GATES:
            receipt = {"gate": gate, "result": "PASS", "candidate_sha256": SHA,
                       "source_commit": HEAD, "timestamp_utc": "2026-11-05T12:00:00Z"}
            raw = json.dumps(receipt).encode()
            (self.root / (gate + ".json")).write_bytes(raw)
            self.manifest["gates"][gate] = {
                "status": "PASS", "receipt": gate + ".json",
                "receipt_sha256": hashlib.sha256(raw).hexdigest()}

    def test_valid_fixture(self):
        self.assertEqual(validate(self.root, self.manifest), [])

    def test_each_gate_required(self):
        for gate in GATES:
            changed = dict(self.manifest)
            changed["gates"] = dict(self.manifest["gates"])
            del changed["gates"][gate]
            self.assertTrue(validate(self.root, changed), gate)

    def test_missing_receipt(self):
        (self.root / "t05_cancel.json").unlink()
        self.assertTrue(validate(self.root, self.manifest))

    def test_tampered_receipt(self):
        with (self.root / "t05_cancel.json").open("a") as out:
            out.write(" ")
        self.assertTrue(any("digest mismatch" in e for e in validate(self.root, self.manifest)))

    def test_candidate_mismatch(self):
        self.manifest["candidate_sha256"] = "c" * 64
        self.assertTrue(any("candidate SHA mismatch" in e for e in validate(self.root, self.manifest)))

    def test_source_mismatch(self):
        self.manifest["source_commit"] = "c" * 40
        self.assertTrue(any("source commit mismatch" in e for e in validate(self.root, self.manifest)))

    def test_path_escape(self):
        self.manifest["gates"]["t05_cancel"]["receipt"] = "../outside.json"
        self.assertTrue(any("unsafe receipt" in e for e in validate(self.root, self.manifest)))

    def test_fake_pass(self):
        self.manifest["gates"]["t05_cancel"]["status"] = "OPEN"
        self.assertTrue(any("not PASS" in e for e in validate(self.root, self.manifest)))

    def test_unpromoted(self):
        self.manifest["promote"] = False
        self.assertTrue(validate(self.root, self.manifest))

    def test_unexpected_gate(self):
        self.manifest["gates"]["invented"] = {}
        self.assertTrue(any("unexpected gate" in e for e in validate(self.root, self.manifest)))


if __name__ == "__main__":
    unittest.main()

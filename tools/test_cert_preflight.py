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


    def test_malformed_receipt_sha_type(self):
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = 123
        self.assertTrue(validate(self.root, self.manifest))

    def test_malformed_receipt_candidate_type(self):
        path = self.root / "t05_cancel.json"
        obj = json.loads(path.read_text())
        obj["candidate_sha256"] = 123
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(any("candidate SHA mismatch" in e for e in validate(self.root, self.manifest)))

    def test_malformed_receipt_source_type(self):
        path = self.root / "t05_cancel.json"
        obj = json.loads(path.read_text())
        obj["source_commit"] = None
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(any("source commit mismatch" in e for e in validate(self.root, self.manifest)))

    def test_invalid_manifest_shape(self):
        self.assertTrue(validate(self.root, []))

    def test_invalid_gate_collection(self):
        self.manifest["gates"] = []
        self.assertTrue(validate(self.root, self.manifest))

    def test_missing_timestamp(self):
        path = self.root / "t05_cancel.json"
        obj = json.loads(path.read_text())
        del obj["timestamp_utc"]
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(any("UTC timestamp" in e for e in validate(self.root, self.manifest)))

    def test_receipt_result_mismatch(self):
        path = self.root / "t05_cancel.json"
        obj = json.loads(path.read_text())
        obj["result"] = "FAIL"
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(any("gate/result mismatch" in e for e in validate(self.root, self.manifest)))

    def test_receipt_gate_mismatch(self):
        path = self.root / "t05_cancel.json"
        obj = json.loads(path.read_text())
        obj["gate"] = "other"
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        self.manifest["gates"]["t05_cancel"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
        self.assertTrue(any("gate/result mismatch" in e for e in validate(self.root, self.manifest)))

    def test_invalid_candidate_sha(self):
        self.manifest["candidate_sha256"] = "not-a-sha"
        self.assertTrue(any("invalid candidate" in e for e in validate(self.root, self.manifest)))

    def test_invalid_source_commit(self):
        self.manifest["source_commit"] = 123
        self.assertTrue(any("invalid source commit" in e for e in validate(self.root, self.manifest)))

    def test_absolute_receipt_path(self):
        self.manifest["gates"]["t05_cancel"]["receipt"] = str(self.root / "t05_cancel.json")
        self.assertTrue(any("unsafe receipt" in e for e in validate(self.root, self.manifest)))

    def test_backslash_receipt_path(self):
        self.manifest["gates"]["t05_cancel"]["receipt"] = r"folder\\receipt.json"
        self.assertTrue(any("invalid receipt path" in e for e in validate(self.root, self.manifest)))

    def test_non_json_receipt(self):
        (self.root / "t05_cancel.json").write_text("not json")
        self.assertTrue(any("invalid receipt JSON" in e for e in validate(self.root, self.manifest)))

    def test_unapproved_certification(self):
        self.manifest["certified"] = False
        self.assertTrue(any("not approved" in e for e in validate(self.root, self.manifest)))

    def test_missing_gate_entry(self):
        self.manifest["gates"]["t05_cancel"] = None
        self.assertTrue(any("not PASS" in e for e in validate(self.root, self.manifest)))


if __name__ == "__main__":
    unittest.main()

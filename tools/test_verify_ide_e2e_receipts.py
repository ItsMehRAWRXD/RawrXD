"""Unit tests for the fail-closed 15-gate certification receipt verifier."""
import json
from pathlib import Path
import tempfile
import unittest

from verify_ide_e2e_receipts import GATES, verify

SHA = "a" * 64


class EvidenceGateTests(unittest.TestCase):
    def test_missing_all_fifteen_receipts_fail(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(len(verify(Path(d), SHA)), 15)

    def test_each_gate_missing_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for gate in GATES:
                evidence = root / (gate + ".log")
                evidence.write_text("runtime evidence", encoding="utf-8")
                (root / (gate + ".json")).write_text(
                    json.dumps(dict(gate=gate, status="PASS",
                                    candidate_sha256=SHA,
                                    evidence_path=evidence.name)), encoding="utf-8")
            self.assertEqual(verify(root, SHA), [])
            for gate in GATES:
                receipt = root / (gate + ".json")
                original = receipt.read_text(encoding="utf-8")
                receipt.unlink()
                self.assertTrue(any(gate in err for err in verify(root, SHA)))
                receipt.write_text(original, encoding="utf-8")

    def test_mismatched_hash_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            gate = GATES[0]
            (root / "e.log").write_text("evidence", encoding="utf-8")
            (root / (gate + ".json")).write_text(
                json.dumps(dict(gate=gate, status="PASS",
                                candidate_sha256="b" * 64,
                                evidence_path="e.log")), encoding="utf-8")
            self.assertTrue(any("hash mismatch" in e for e in verify(root, SHA)))


if __name__ == "__main__":
    unittest.main()

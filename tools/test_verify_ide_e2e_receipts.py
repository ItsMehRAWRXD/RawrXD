"""Unit tests for the fail-closed 15-gate certification receipt verifier."""
import json
import hashlib
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
                                    evidence_path=evidence.name,
                                    evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())), encoding="utf-8")
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
                                evidence_path="e.log",
                                evidence_sha256=hashlib.sha256((root / "e.log").read_bytes()).hexdigest())), encoding="utf-8")
            self.assertTrue(any("hash mismatch" in e for e in verify(root, SHA)))


    def test_evidence_integrity_and_path_guards(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            gate = GATES[0]
            evidence = root / "evidence.log"
            evidence.write_bytes(b"real-evidence")
            receipt_path = root / (gate + ".json")
            valid = dict(gate=gate, status="PASS", candidate_sha256=SHA,
                         evidence_path=evidence.name,
                         evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
            def write(**changes):
                receipt_path.write_text(json.dumps({**valid, **changes}), encoding="utf-8")
            write()
            self.assertEqual(len(verify(root, SHA)), len(GATES) - 1)
            write(evidence_sha256="0" * 64)
            self.assertTrue(any("digest mismatch" in e for e in verify(root, SHA)))
            write(evidence_sha256="")
            self.assertTrue(any("invalid evidence SHA-256" in e for e in verify(root, SHA)))
            write(evidence_path="../outside.log")
            self.assertTrue(any("unsafe evidence path" in e for e in verify(root, SHA)))
            write(evidence_path=str(evidence.resolve()))
            self.assertTrue(any("unsafe evidence path" in e for e in verify(root, SHA)))
            write(evidence_path="missing.log")
            self.assertTrue(any("absent or empty" in e for e in verify(root, SHA)))
            evidence.write_bytes(b"")
            write()
            self.assertTrue(any("absent or empty" in e for e in verify(root, SHA)))


    def test_fifteen_malformed_receipt_variants_fail_closed(self):
        # Each variant must produce a gate-specific failure, never an exception.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            gate = GATES[0]
            evidence = root / "sample.log"
            evidence.write_bytes(b"verified-content")
            receipt_file = root / (gate + ".json")
            base = dict(gate=gate, status="PASS", candidate_sha256=SHA,
                        evidence_path=evidence.name,
                        evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest())
            mutations = [
                {"gate": None},                         # 01
                {"gate": 42},                           # 02
                {"status": "FAIL"},                      # 03
                {"status": True},                        # 04
                {"candidate_sha256": None},             # 05
                {"candidate_sha256": 123},              # 06
                {"candidate_sha256": []},               # 07
                {"candidate_sha256": "b" * 64},          # 08
                {"evidence_path": None},                # 09
                {"evidence_path": []},                  # 10
                {"evidence_path": "../sample.log"},     # 11
                {"evidence_path": "missing.log"},       # 12
                {"evidence_sha256": None},              # 13
                {"evidence_sha256": "f" * 64},           # 14
                {"evidence_sha256": []},                # 15
            ]
            self.assertEqual(len(mutations), 15)
            for i, change in enumerate(mutations, 1):
                with self.subTest(case=i):
                    receipt_file.write_text(json.dumps({**base, **change}), encoding="utf-8")
                    errors = verify(root, SHA)
                    self.assertTrue(any(gate in error for error in errors))
            receipt_file.write_text(json.dumps(base), encoding="utf-8")
            self.assertEqual(len(verify(root, SHA)), len(GATES) - 1)


    def test_duplicate_receipt_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            gate = GATES[0]
            path = root / (gate + ".json")
            # A malicious PASS override must never be silently accepted.
            path.write_text('{"gate":"' + gate +
                            '","status":"FAIL","status":"PASS",'
                            '"candidate_sha256":"' + SHA + '"}', encoding="utf-8")
            errors = verify(root, SHA)
            self.assertTrue(any("duplicate receipt field" in e for e in errors))


if __name__ == "__main__":
    unittest.main()

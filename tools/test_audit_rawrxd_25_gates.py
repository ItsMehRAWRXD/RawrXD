"""Evidence ledger contracts must fail closed, never certify on source-only data."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from audit_rawrxd_25_gates import audit, validate_manifest, validate_receipt

MANIFEST = Path(__file__).resolve().parents[1] / "docs" / "RAWRXD_25_GATE_ACCEPTANCE.json"


def fixture(gate):
    return {
        "gate_id": gate,
        "status": "PASS",
        "certified": False,
        "exit_code": 0,
        "command": "test-command --model model.gguf",
        "model_sha256": "a" * 64,
        "binary_sha256": "b" * 64,
        "source_sha256": "c" * 64,
        "evidence_sha256": "d" * 64,
        "checks": [{"name": "test case", "status": "PASS"}],
    }


class GateAuditTests(unittest.TestCase):
    def test_manifest_contains_exactly_25_pending_gates(self):
        data = json.loads(MANIFEST.read_text())
        validate_manifest(data)
        self.assertEqual([g["id"] for g in data["gates"]],
                         [f"G{i:02d}" for i in range(1, 26)])

    def test_no_receipts_cannot_promote(self):
        with tempfile.TemporaryDirectory() as root:
            result = audit(MANIFEST, Path(root))
            self.assertEqual(result["status"], "HOLD")
            self.assertEqual(result["structurally_complete_count"], 0)
            self.assertEqual(result["missing_or_failed_count"], 25)
            self.assertFalse(result["certified"])
            self.assertEqual(result["promote"], 0)

    def test_25_synthetic_receipts_still_uncertified(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(1, 26):
                gate = f"G{i:02d}"
                (Path(root) / f"{gate}.json").write_text(json.dumps(fixture(gate)))
            result = audit(MANIFEST, Path(root))
            self.assertEqual(result["status"], "EVIDENCE_COMPLETE_UNVERIFIED")
            self.assertEqual(result["structurally_complete_count"], 25)
            self.assertFalse(result["certified"])
            self.assertEqual(result["promote"], 0)

    def test_missing_hash_fails(self):
        receipt = fixture("G01")
        receipt["model_sha256"] = "not-a-sha"
        self.assertEqual(validate_receipt("G01", receipt), "INVALID_HASH")

    def test_false_certification_rejected(self):
        receipt = fixture("G01")
        receipt["certified"] = True
        self.assertEqual(validate_receipt("G01", receipt), "UNSAFE_CERTIFICATION")

    def test_failed_check_rejected(self):
        receipt = fixture("G01")
        receipt["checks"][0]["status"] = "FAIL"
        self.assertEqual(validate_receipt("G01", receipt), "CHECKS_NOT_PASSING")

    def test_wrong_gate_rejected(self):
        self.assertEqual(validate_receipt("G01", fixture("G02")), "INVALID_ID")

    def test_manifest_cannot_claim_gate_pass(self):
        data = json.loads(MANIFEST.read_text())
        data["gates"][0]["status"] = "PASS"
        with self.assertRaises(ValueError):
            validate_manifest(data)

    def test_bool_exit_code_rejected(self):
        receipt = fixture("G01")
        receipt["exit_code"] = False
        self.assertEqual(validate_receipt("G01", receipt), "NOT_PASSING")

    def test_missing_receipt_field(self):
        receipt = fixture("G01")
        del receipt["evidence_sha256"]
        self.assertEqual(validate_receipt("G01", receipt), "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()

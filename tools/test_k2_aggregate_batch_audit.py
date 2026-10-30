"""Fail-closed batch numerical coverage cases; synthetic fixtures only."""
import json
import tempfile
import unittest
from pathlib import Path
from k2_aggregate_batch_audit import audit, main, parse_scope


def write_pair(root, layer, stick, gpu="1\n2\n", cpu="1\n2\n"):
    stem = f"k2_l{layer}_s{stick}_aggregate_comparison"
    (root / f"{stem}.manifest.txt").write_text(
        "schema=DEEP2_KIMI_AGGREGATE_COMPARISON_001\n"
        f"layer={layer}\nstick={stick}\nrows=2\nexperts=2\n"
        "source=POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE\n"
        "scope=AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY\ncertified=0\n"
        "expert=8 weight=0.6\nexpert=12 weight=0.4\n", encoding="utf-8")
    (root / f"{stem}.gpu.txt").write_text(gpu, encoding="utf-8")
    (root / f"{stem}.cpu.txt").write_text(cpu, encoding="utf-8")


class BatchAuditTests(unittest.TestCase):
    def test_two_scopes_pass_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_pair(root, 2, 0)
            write_pair(root, 3, 1)
            result = audit(root, [(2, 0), (3, 1)], 0, 0)
            self.assertEqual(result["counts"]["pass"], 2)
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertFalse(result["certified"])
            self.assertEqual(result["promote"], 0)
            self.assertEqual(result["gpu_expert_witness"], "ABSENT")

    def test_missing_scope_is_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_pair(root, 2, 0)
            result = audit(root, [(2, 0), (3, 1)], 0, 0)
            self.assertEqual(result["status"], "ERROR")
            self.assertEqual(result["counts"]["pass"], 1)
            self.assertEqual(result["counts"]["error"], 1)

    def test_disagreeing_vector_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_pair(root, 2, 0, gpu="1\n3\n")
            result = audit(root, [(2, 0)], 0.1, 0.1)
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["counts"]["fail"], 1)

    def test_duplicate_scope_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                audit(Path(temp), [(2, 0), (2, 0)], 0, 0)

    def test_bad_stick_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                audit(Path(temp), [(2, 2)], 0, 0)

    def test_empty_scopes_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                audit(Path(temp), [], 0, 0)

    def test_negative_threshold_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                audit(Path(temp), [(2, 0)], -1, 0)

    def test_scope_parser(self):
        self.assertEqual(parse_scope("19:1"), (19, 1))
        for token in ["-1:0", "1:3:2", "three:0", "1/0"]:
            with self.assertRaises(ValueError):
                parse_scope(token)

    def test_cli_complete_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_pair(root, 2, 0)
            receipt = root / "receipt.json"
            args = ["--capture-dir", str(root), "--require", "2:0",
                    "--max-abs", "0", "--max-rms", "0",
                    "--receipt", str(receipt)]
            self.assertEqual(main(args), 0)
            r = json.loads(receipt.read_text())
            self.assertEqual(r["status"], "PASS_DIAGNOSTIC")
            self.assertEqual(main(args), 3)

    def test_cli_fail_on_missing_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            out = root / "audit.json"
            self.assertEqual(main(["--capture-dir", str(root),
                                   "--require", "3:1",
                                   "--max-abs", "0", "--max-rms", "0",
                                   "--receipt", str(out)]), 3)


if __name__ == "__main__":
    unittest.main()

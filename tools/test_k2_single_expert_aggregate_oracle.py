"""Synthetic single-expert independent oracle vs completed aggregate cases."""
import json
import tempfile
import unittest
from pathlib import Path

from k2_single_expert_aggregate_oracle import audit, main
from test_k2_scalar_input_audit import create_capture
from test_k2_aggregate_vector_audit import capture as create_aggregate


def paired(root, *, routes=((44, 0.75),), gpu=None, cpu=None, layer=2):
    root = Path(root)
    a_dir, s_dir = root / "aggregate", root / "scalar"
    a_dir.mkdir()
    scalar = create_capture(s_dir)
    original = "k2_l1_e44_s0_scalar_inputs"
    renamed = "k2_l2_e44_s0_scalar_inputs"
    for f in list(s_dir.iterdir()):
        f.rename(s_dir / f.name.replace(original, renamed))
    scalar = s_dir / (renamed + ".manifest.txt")
    scalar.write_text(scalar.read_text().replace("layer=1\n", "layer=2\n"))
    scalar.write_text(scalar.read_text() + "run_id=fixture20261027unique01\n")
    if gpu is None:
        gpu = tuple(0.0 for _ in range(256))
    if cpu is None:
        cpu = tuple(0.0 for _ in range(256))
    aggregate = create_aggregate(
        a_dir, gpu=gpu, cpu=cpu, routes=routes)
    stem = "k2_l2_s0_aggregate_comparison"
    aggregate.write_text(
        aggregate.read_text().replace("rows=2\n", "rows=256\n"))
    aggregate.write_text(aggregate.read_text() + "run_id=fixture20261027unique01\n")
    return aggregate, scalar


class SingleExpertAggregateOracleTests(unittest.TestCase):
    def test_single_expert_zero_oracle_matches(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            result = audit(a, s, 0, 0)
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertFalse(result["certified"])
            self.assertEqual(result["gpu_post_swiglu_witness"], "ABSENT")
            self.assertEqual(result["gpu_unweighted_down_witness"], "ABSENT")
            self.assertEqual(result["metrics"]["elements"], 256)

    def test_incorrect_aggregate_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, gpu=(1.0,) + (0.0,) * 255)
            result = audit(a, s, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["metrics"]["worst_index"], 0)

    def test_gpu_matches_oracle_but_cpu_differs_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, cpu=(2.0,) + (0.0,) * 255)
            result = audit(a, s, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["checks"]["gpu_vs_oracle"])
            self.assertFalse(result["checks"]["cpu_vs_oracle"])
            self.assertFalse(result["checks"]["gpu_vs_cpu"])

    def test_cpu_matches_oracle_but_gpu_differs_fails(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, gpu=(3.0,) + (0.0,) * 255)
            result = audit(a, s, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["checks"]["cpu_vs_oracle"])
            self.assertFalse(result["checks"]["gpu_vs_oracle"])

    def test_cpu_and_gpu_agree_but_both_differ_from_oracle_fails(self):
        with tempfile.TemporaryDirectory() as d:
            wrong = (4.0,) + (0.0,) * 255
            a, s = paired(d, gpu=wrong, cpu=wrong)
            result = audit(a, s, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["checks"]["gpu_vs_cpu"])
            self.assertFalse(result["checks"]["gpu_vs_oracle"])
            self.assertFalse(result["checks"]["cpu_vs_oracle"])

    def test_multi_expert_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, routes=((44, 0.6), (12, 0.4)))
            with self.assertRaisesRegex(ValueError, "MULTI_EXPERT"):
                audit(a, s, 1, 1)

    def test_wrong_expert_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, routes=((45, 0.75),))
            with self.assertRaisesRegex(ValueError, "IDENTITY"):
                audit(a, s, 1, 1)

    def test_wrong_stick_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            s.write_text(s.read_text().replace("stick=0", "stick=1"))
            with self.assertRaises(ValueError):
                audit(a, s, 1, 1)

    def test_nonfinite_router_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, routes=((44, float("nan")),))
            with self.assertRaises(ValueError):
                audit(a, s, 1, 1)

    def test_wrong_dimensions_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            a.write_text(a.read_text().replace("rows=256", "rows=257"))
            with self.assertRaises(ValueError):
                audit(a, s, 1, 1)

    def test_invalid_thresholds_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            with self.assertRaises(ValueError):
                audit(a, s, float("nan"), 0)

    def test_mismatched_run_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            s.write_text(s.read_text().replace(
                "run_id=fixture20261027unique01",
                "run_id=fixture20261027unique02"))
            with self.assertRaisesRegex(ValueError, "RUN_ID"):
                audit(a, s, 1, 1)

    def test_missing_run_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            s.write_text(s.read_text().replace(
                "run_id=fixture20261027unique01\n", ""))
            with self.assertRaisesRegex(ValueError, "RUN_ID"):
                audit(a, s, 1, 1)

    def test_cli_fail_closed_receipt_and_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d)
            receipt = Path(d) / "receipt.json"
            args = ["--aggregate-manifest", str(a),
                    "--scalar-input-manifest", str(s),
                    "--max-abs", "0", "--max-rms", "0",
                    "--receipt", str(receipt)]
            self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(receipt.read_text())["promote"], 0)
            self.assertEqual(main(args), 3)

    def test_cli_fails_on_multi_expert(self):
        with tempfile.TemporaryDirectory() as d:
            a, s = paired(d, routes=((44, 0.6), (12, 0.4)))
            receipt = Path(d) / "receipt.json"
            self.assertEqual(main(["--aggregate-manifest", str(a),
                                   "--scalar-input-manifest", str(s),
                                   "--max-abs", "0", "--max-rms", "0",
                                   "--receipt", str(receipt)]), 3)
            self.assertEqual(json.loads(receipt.read_text())["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()

"""Synthetic full-routing independent scalar MoE aggregate test coverage."""
import json
import tempfile
import unittest
from pathlib import Path
from k2_all_expert_aggregate_oracle import audit, main
from test_k2_scalar_input_audit import create_capture
from test_k2_aggregate_vector_audit import capture as create_aggregate

RUN = "allExpertFixture20261027_01"


def fixture(root, routes=((44, 0.25), (45, 0.75)), *, gpu=None, cpu=None,
            missing=None, bad_run=None):
    root = Path(root)
    scalar_dir = root / "scalars"
    aggregate_dir = root / "aggregate"
    scalar_dir.mkdir()
    aggregate_dir.mkdir()
    for eid, _ in routes:
        if eid == missing:
            continue
        directory = root / f"temporary_{eid}"
        manifest = create_capture(directory)
        for file in directory.iterdir():
            name = file.name.replace("k2_l1_e44_s0_scalar_inputs",
                                     f"k2_l2_e{eid}_s0_scalar_inputs")
            file.rename(scalar_dir / name)
        new = scalar_dir / f"k2_l2_e{eid}_s0_scalar_inputs.manifest.txt"
        new.write_text(new.read_text().replace("layer=1\n", "layer=2\n")
                       .replace("expert=44\n", f"expert={eid}\n") +
                       f"run_id={bad_run if eid == bad_run else RUN}\n"
                       if isinstance(bad_run, int) else
                       new.read_text().replace("layer=1\n", "layer=2\n")
                       .replace("expert=44\n", f"expert={eid}\n") +
                       f"run_id={bad_run if eid == routes[-1][0] and bad_run else RUN}\n")
    zeros = tuple(0.0 for _ in range(256))
    aggregate = create_aggregate(
        aggregate_dir, routes=routes,
        gpu=zeros if gpu is None else gpu,
        cpu=zeros if cpu is None else cpu)
    aggregate.write_text(
        aggregate.read_text().replace("rows=2\n", "rows=256\n")
        + f"run_id={RUN}\n")
    return aggregate, scalar_dir


class AllExpertAggregateOracleTests(unittest.TestCase):
    def test_two_experts_match(self):
        with tempfile.TemporaryDirectory() as d:
            manifest, inputs = fixture(d)
            result = audit(manifest, inputs, 0, 0)
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertEqual(len(result["input_sha256"]), 2)
            self.assertEqual(len(result["comparisons"]), 3)
            self.assertFalse(result["certified"])

    def test_missing_expert_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            m, inp = fixture(d, missing=45)
            with self.assertRaises(OSError):
                audit(m, inp, 0, 0)

    def test_mismatched_run_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            m, inp = fixture(d, bad_run="differentValidRun20261027_02")
            with self.assertRaisesRegex(ValueError, "MISMATCH"):
                audit(m, inp, 0, 0)

    def test_gpu_disagreement_fails(self):
        with tempfile.TemporaryDirectory() as d:
            wrong = (1.0,) + (0.0,) * 255
            m, inp = fixture(d, gpu=wrong)
            result = audit(m, inp, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["checks"]["gpu_vs_oracle"])
            self.assertTrue(result["checks"]["cpu_vs_oracle"])

    def test_cpu_gpu_same_wrong_fails(self):
        with tempfile.TemporaryDirectory() as d:
            wrong = (1.0,) + (0.0,) * 255
            m, inp = fixture(d, gpu=wrong, cpu=wrong)
            result = audit(m, inp, 0, 0)
            self.assertFalse(result["checks"]["cpu_vs_oracle"])
            self.assertTrue(result["checks"]["gpu_vs_cpu"])

    def test_more_than_eight_refused(self):
        with tempfile.TemporaryDirectory() as d:
            m, inp = fixture(d, routes=tuple((44+i, 0.1) for i in range(9)))
            with self.assertRaisesRegex(ValueError, "BOUNDS"):
                audit(m, inp, 0, 0)

    def test_duplicate_route_refused(self):
        with tempfile.TemporaryDirectory() as d:
            m, inp = fixture(d, routes=((44, 0.5), (44, 0.5)))
            with self.assertRaises(ValueError):
                audit(m, inp, 0, 0)

    def test_receipt_diagnostic_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            m, inp = fixture(d)
            out = Path(d) / "receipt.json"
            args = ["--aggregate-manifest", str(m), "--scalar-dir", str(inp),
                    "--max-abs", "0", "--max-rms", "0", "--receipt", str(out)]
            self.assertEqual(main(args), 0)
            result = json.loads(out.read_text())
            self.assertEqual(result["gpu_expert_witness"], "ABSENT")
            self.assertEqual(result["promote"], 0)
            self.assertEqual(main(args), 3)


if __name__ == "__main__":
    unittest.main()

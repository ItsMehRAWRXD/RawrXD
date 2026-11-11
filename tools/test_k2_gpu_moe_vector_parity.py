"""No model required; deterministic negative and positive parity harness tests."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("k2_gpu_moe_vector_parity.py")


class ParityHarnessTests(unittest.TestCase):
    def run_case(self, cpu, gpu, oracle, extra=()):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            for name, vals in (("cpu", cpu), ("gpu", gpu), ("oracle", oracle)):
                (p / f"{name}.txt").write_text(vals, encoding="utf-8")
            cmd = [sys.executable, str(SCRIPT), "--cpu", str(p / "cpu.txt"),
                   "--gpu", str(p / "gpu.txt"), "--oracle", str(p / "oracle.txt"),
                   "--max-abs", "0.001", "--max-rms", "0.001",
                   "--min-cosine", "0.999", "--oracle-provenance", "test-scalar",
                   "--output", str(p / "receipt.json"), *extra]
            run = subprocess.run(cmd, capture_output=True, text=True)
            return run.returncode, json.loads((p / "receipt.json").read_text())

    def test_identical(self):
        rc, data = self.run_case("1\n2\n3\n", "1\n2\n3\n", "1\n2\n3\n")
        self.assertEqual(rc, 0)
        self.assertFalse(data["certified"])
        self.assertEqual(data["comparisons"]["gpu_vs_oracle"]["rms_abs"], 0)

    def test_mismatched_vector(self):
        rc, data = self.run_case("1\n2\n", "1\n9\n", "1\n2\n")
        self.assertEqual(rc, 2)
        self.assertEqual(data["status"], "FAIL")

    def test_dimension_mismatch(self):
        rc, data = self.run_case("1\n2\n", "1\n", "1\n2\n")
        self.assertEqual(rc, 3)
        self.assertEqual(data["status"], "ERROR")

    def test_nonfinite(self):
        rc, data = self.run_case("1\n2\n", "1\nnan\n", "1\n2\n")
        self.assertEqual(rc, 3)
        self.assertEqual(data["status"], "ERROR")

    def test_independent_reference_required(self):
        rc, data = self.run_case("1\n2\n", "1\n2\n", "1\n3\n")
        self.assertEqual(rc, 2)
        self.assertFalse(data["checks"]["cpu_vs_oracle"])

    def test_zero_vectors(self):
        rc, data = self.run_case("0\n0\n", "0\n0\n", "0\n0\n")
        self.assertEqual(rc, 0)
        self.assertEqual(data["comparisons"]["gpu_vs_oracle"]["cosine_similarity"], 1)


if __name__ == "__main__":
    unittest.main()

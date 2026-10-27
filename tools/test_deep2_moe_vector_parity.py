"""Unit tests for the fail-closed Deep2 MoE vector comparator."""
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("deep2_moe_vector_parity.py")
spec = importlib.util.spec_from_file_location("deep2_moe_vector_parity", SCRIPT)
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)


class VectorParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.paths = {name: self.root / (name + ".f32le")
                      for name in ("cpu", "gpu", "oracle")}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, values):
        self.paths[name].write_bytes(struct.pack("<" + "f" * len(values), *values))

    def run_gate(self, *extra):
        args = []
        for name, path in self.paths.items():
            args += ["--" + name, str(path)]
        args += ["--expert-id", "5", "--layer", "2", "--token-step", "0",
                 "--input-sha256", "a" * 64, "--weights-sha256", "b" * 64,
                 "--oracle-method", "scalar independent f32 reference",
                 "--max-abs-tol", "0.01", "--rms-tol", "0.01",
                 "--cos-min", "0.99", "--output", str(self.root / "receipt.json")]
        return parity.main(args + list(extra))

    def receipt(self):
        return json.loads((self.root / "receipt.json").read_text())

    def test_equal_vectors_diagnostic_only(self):
        for name in self.paths:
            self.write(name, [1.0, -2.0, 3.0])
        self.assertEqual(self.run_gate(), 0)
        self.assertEqual(self.receipt()["status"], "PASS_DIAGNOSTIC")
        self.assertFalse(self.receipt()["certified"])

    def test_gpu_mismatch_fails(self):
        self.write("cpu", [1, 2, 3])
        self.write("oracle", [1, 2, 3])
        self.write("gpu", [1, 2, 4])
        self.assertEqual(self.run_gate(), 2)
        self.assertEqual(self.receipt()["status"], "FAIL")

    def test_nonfinite_fails_closed(self):
        self.write("cpu", [1, float("nan")])
        self.write("gpu", [1, 2])
        self.write("oracle", [1, 2])
        self.assertEqual(self.run_gate(), 3)
        self.assertEqual(self.receipt()["status"], "INVALID_INPUT")

    def test_wrong_dimensions_fails_closed(self):
        self.write("cpu", [1, 2])
        self.write("gpu", [1])
        self.write("oracle", [1, 2])
        self.assertEqual(self.run_gate(), 3)

    def test_same_file_rejected(self):
        for name in self.paths:
            self.write(name, [1, 2])
        self.assertEqual(self.run_gate("--oracle", str(self.paths["cpu"])), 3)

    def test_zero_vectors(self):
        for name in self.paths:
            self.write(name, [0, 0])
        self.assertEqual(self.run_gate(), 0)
        self.assertEqual(self.receipt()["comparisons"]["gpu_vs_oracle"]["cosine_similarity"], 1.0)

    def test_invalid_tolerance_rejected(self):
        for name in self.paths:
            self.write(name, [1])
        self.assertEqual(self.run_gate("--max-abs-tol", "nan"), 3)


if __name__ == "__main__":
    unittest.main()

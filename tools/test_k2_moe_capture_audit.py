"""Offline manifest-driven CPU/GPU/Q6_K integration tests."""
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("k2_capture_audit", HERE / "k2_moe_capture_audit.py")
import sys
sys.path.insert(0, str(HERE))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class CaptureAuditTests(unittest.TestCase):
    def write_capture(self, folder, gpu="0\n", columns=256, manifest_overrides=None):
        root = Path(folder)
        stem = "k2_l1_e44_s0"
        block = bytes([0] * 128 + [0xAA] * 64 + [1] * 16) + struct.pack("<e", 1.0)
        (root / (stem + ".down_q6k.bin")).write_bytes(block)
        (root / (stem + ".post_swiglu.txt")).write_text("1\n" * columns)
        (root / (stem + ".cpu_down.txt")).write_text("0\n")
        (root / (stem + ".gpu_down.txt")).write_text(gpu)
        fields = {
            "schema": "DEEP2_KIMI_MOE_EXPERT_CAPTURE_001",
            "layer": 1, "expert": 44, "stick": 0,
            "ggml_type": 14, "rows": 1, "columns": columns,
            "weight_bytes": 210,
            "source": "GPU_EXPERT_PARITY_DIAGNOSTIC", "certified": 0
        }
        fields.update(manifest_overrides or {})
        manifest = root / (stem + ".manifest.txt")
        manifest.write_text("".join(f"{k}={v}\n" for k, v in fields.items()))
        return manifest

    def test_valid_synthetic(self):
        with tempfile.TemporaryDirectory() as t:
            result = mod.audit(self.write_capture(t), 0, 0, 1)
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertFalse(result["certified"])
            self.assertEqual(result["metrics"]["gpu_vs_scalar_down"]["max_abs"], 0)

    def test_gpu_disagreement(self):
        with tempfile.TemporaryDirectory() as t:
            result = mod.audit(self.write_capture(t, gpu="3\n"), 0.01, 0.01, 0.9)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["checks"]["gpu_vs_scalar_down"])

    def test_mismatched_columns(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = self.write_capture(t, columns=512)
            with self.assertRaises(ValueError):
                mod.audit(manifest, 0, 0, 1)

    def test_invalid_quant_type(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = self.write_capture(t, manifest_overrides={"ggml_type": 12})
            with self.assertRaises(ValueError):
                mod.audit(manifest, 0, 0, 1)

    def test_false_certification_in_manifest(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = self.write_capture(t, manifest_overrides={"certified": 1})
            with self.assertRaises(ValueError):
                mod.audit(manifest, 0, 0, 1)

    def test_corrupt_weight_bytes(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = self.write_capture(t)
            (Path(t) / "k2_l1_e44_s0.down_q6k.bin").write_bytes(b"truncated")
            with self.assertRaises(ValueError):
                mod.audit(manifest, 0, 0, 1)

    def test_nonfinite_gpu(self):
        with tempfile.TemporaryDirectory() as t:
            manifest = self.write_capture(t, gpu="nan\n")
            with self.assertRaises(ValueError):
                mod.audit(manifest, 0, 0, 1)


if __name__ == "__main__":
    unittest.main()

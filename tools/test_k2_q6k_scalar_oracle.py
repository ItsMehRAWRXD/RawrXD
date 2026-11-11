"""Deterministic synthetic Q6_K block tests; not Kimi hardware parity."""
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oracle", HERE / "k2_q6k_scalar_oracle.py")
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


def block(ql=0, qh=0, scales=None, d=1.0):
    if scales is None:
        scales = [1] * 16
    return (bytes([ql] * 128 + [qh] * 64)
            + struct.pack("<16b", *scales) + struct.pack("<e", d))


class TestQ6KOracle(unittest.TestCase):
    def test_positive_quant(self):
        self.assertEqual(oracle.unpack_block(block(ql=0xff, qh=0xff)), [31.0] * 256)

    def test_negative_quant(self):
        self.assertEqual(oracle.unpack_block(block(d=0.5)), [-16.0] * 256)

    def test_zero_quant(self):
        self.assertEqual(oracle.unpack_block(block(qh=0xaa)), [0.0] * 256)

    def test_signed_group_scales(self):
        self.assertEqual(oracle.unpack_block(block(scales=[-2] * 16))[:32], [64.0] * 32)

    def test_multiblock_rows(self):
        weights = (block(ql=0xff, qh=0xff) + block()
                   + block(qh=0xaa) + block(d=0.5))
        y = oracle.gemv(weights, [1.0] * 512, 2, 512)
        self.assertEqual(y, [256 * (31 - 32), 256 * (-16)])

    def test_dimension_error(self):
        with self.assertRaises(ValueError):
            oracle.gemv(block(), [1.0] * 255, 1, 256)

    def test_corrupt_block(self):
        with self.assertRaises(ValueError):
            oracle.unpack_block(b"bad")

    def test_nan_scale(self):
        with self.assertRaises(ValueError):
            oracle.unpack_block(block(d=float("nan")))

    def test_cli_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "weights.bin").write_bytes(block(qh=0xaa))
            (d / "input.txt").write_text("1\n" * 256)
            process = subprocess.run(
                [sys.executable, str(HERE / "k2_q6k_scalar_oracle.py"),
                 "--weights", str(d / "weights.bin"),
                 "--input", str(d / "input.txt"),
                 "--rows", "1", "--columns", "256",
                 "--output", str(d / "out.txt"),
                 "--receipt", str(d / "receipt.json")],
                capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(float((d / "out.txt").read_text()), 0)
            self.assertFalse(json.loads((d / "receipt.json").read_text())["certified"])


if __name__ == "__main__":
    unittest.main()

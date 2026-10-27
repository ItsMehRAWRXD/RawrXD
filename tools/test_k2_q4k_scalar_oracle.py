"""Offline synthetic tests for independent Q4_K scalar reference.

Model fixtures are deliberately not inferred from tests: these only exercise
the byte layout, signed/minimum scale unpack, validation and scalar matvec.
"""
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from k2_q4k_scalar_oracle import unpack_block, scale_min, gemv

SCRIPT = Path(__file__).with_name("k2_q4k_scalar_oracle.py")


def block(d=1, dmin=0, scales=None, qs=None):
    if scales is None:
        scales = bytes([1] * 12)
    if qs is None:
        qs = bytes([0x11] * 128)
    return struct.pack("<ee", d, dmin) + scales + qs


class Q4KScalarTests(unittest.TestCase):
    def test_block_width(self):
        self.assertEqual(len(unpack_block(block())), 256)

    def test_all_low_high_nibbles(self):
        v = unpack_block(block(qs=bytes([0xF0] * 128)))
        self.assertEqual(v[:32], [0] * 32)
        self.assertEqual(v[32:64], [15] * 32)

    def test_nonzero_minimum(self):
        v = unpack_block(block(d=2, dmin=3, qs=bytes(128)))
        self.assertEqual(v, [-3] * 256)

    def test_high_scale_packing(self):
        s = bytearray(12)
        s[0] = 0b10000000
        s[4] = 0b11000000
        s[8] = 0x32
        self.assertEqual(scale_min(s, 4), (0x02 | (2 << 4), 0x03 | (0 << 4)))
        self.assertEqual(scale_min(s, 0), (0, 0))

    def test_two_rows(self):
        out = gemv(block() + block(qs=bytes([0x22] * 128)),
                   [1] * 256, 2, 256)
        self.assertEqual(out, [256, 512])

    def test_two_blocks_one_row(self):
        out = gemv(block() + block(qs=bytes([0x22] * 128)),
                   [1] * 512, 1, 512)
        self.assertEqual(out, [768])

    def test_invalid_block(self):
        with self.assertRaises(ValueError):
            unpack_block(b"short")

    def test_invalid_scale(self):
        with self.assertRaises(ValueError):
            unpack_block(block(d=float("nan")))

    def test_dimension_mismatch(self):
        with self.assertRaises(ValueError):
            gemv(block(), [1] * 255, 1, 256)

    def test_cli_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / "weights.bin").write_bytes(block())
            (p / "input.txt").write_text("1\n" * 256)
            cmd = [sys.executable, str(SCRIPT),
                   "--weights", str(p / "weights.bin"),
                   "--input", str(p / "input.txt"),
                   "--rows", "1", "--columns", "256",
                   "--output", str(p / "out.txt"),
                   "--receipt", str(p / "receipt.json")]
            run = subprocess.run(cmd, text=True, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(float((p / "out.txt").read_text()), 256)
            self.assertFalse(json.loads((p / "receipt.json").read_text())["certified"])


if __name__ == "__main__":
    unittest.main()

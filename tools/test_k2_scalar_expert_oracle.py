"""Synthetic offline tests for independent complete Kimi scalar expert math."""
import json
import math
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from k2_scalar_expert_oracle import expert, swiglu, main

def q4(q=0x11):
    return struct.pack("<ee", 1., 0.) + bytes([1] * 12 + [q] * 128)

def q6(q=0x11, high=0xAA):
    return bytes([q] * 128 + [high] * 64 + [1] * 16) + struct.pack("<e", 1.)


class ScalarExpertTests(unittest.TestCase):
    def test_full_scalar_path(self):
        result = expert(q4() * 256, q4() * 256, q6() * 256, [1.] * 256, 256, 256)
        self.assertEqual(result["gate"], [256.] * 256)
        self.assertEqual(result["up"], [256.] * 256)
        expected = 256 * 256 * 256
        for value in result["down"]:
            self.assertAlmostEqual(value, expected, delta=.001)

    def test_zero_gate(self):
        result = expert(q4(q=0x00) * 256, q4() * 256, q6() * 256, [1.] * 256, 256, 256)
        self.assertEqual(result["down"], [0.] * 256)

    def test_zero_down(self):
        result = expert(q4() * 256, q4() * 256, q6(q=0x00, high=0xAA) * 256,
                        [1.] * 256, 256, 256)
        self.assertEqual(result["down"], [0.] * 256)

    def test_negative_stability(self):
        self.assertAlmostEqual(swiglu([-1000.], [1.])[0], 0., places=12)

    def test_shape_rejection(self):
        with self.assertRaises(ValueError):
            expert(q4() * 256, q4() * 256, q6() * 256, [1.] * 255, 255, 256)

    def test_nonfinite_intermediate_rejection(self):
        with self.assertRaises(ValueError):
            swiglu([float("inf")], [1.])

    def test_cli_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            for name, packed in (("gate", q4() * 256),
                                 ("up", q4() * 256),
                                 ("down", q6() * 256)):
                (p / (name + ".bin")).write_bytes(packed)
            (p / "hidden.txt").write_text("1\n" * 256)
            out = p / "out"
            out.mkdir()
            args = ["--gate", str(p / "gate.bin"), "--up", str(p / "up.bin"),
                    "--down", str(p / "down.bin"), "--hidden", str(p / "hidden.txt"),
                    "--hidden-dim", "256", "--intermediate-dim", "256",
                    "--output-dir", str(out), "--receipt", str(p / "receipt.json")]
            self.assertEqual(main(args), 0)
            receipt = json.loads((p / "receipt.json").read_text())
            self.assertFalse(receipt["certified"])
            self.assertEqual(len((out / "scalar_down.txt").read_text().splitlines()), 256)
            self.assertEqual(main(args), 3)  # never overwrite outputs


if __name__ == "__main__":
    unittest.main()

"""Fail-closed synthetic tests for the captured scalar input -> oracle bridge."""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from k2_scalar_input_audit import evaluate, main, parse_manifest


def create_capture(root, *, quant="12", n_hidden=256, n_intermediate=256):
    folder = Path(root)
    folder.mkdir(parents=True, exist_ok=True)
    stem = "k2_l1_e44_s0_scalar_inputs"
    manifest = folder / f"{stem}.manifest.txt"
    lines = [
        "schema=DEEP2_KIMI_SCALAR_INPUTS_001",
        "layer=1", "expert=44", "stick=0",
        f"hidden_dim={n_hidden}", f"intermediate_dim={n_intermediate}",
        f"gate_ggml_type={quant}", "up_ggml_type=12",
        "down_ggml_type=14",
        "source=CPU_PACKED_SLICES_AND_NORMED_HIDDEN",
        "scope=SCALAR_INPUT_ONLY_NO_GPU_OUTPUT",
        "certified=0"
    ]
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    q4_block = struct.pack("<ee", 1., 0.) + bytes([1] * 12 + [0] * 128)
    q6_block = bytes([0] * 128 + [0xAA] * 64 + [1] * 16) + struct.pack("<e", 1.)
    (folder / f"{stem}.gate_q4k.bin").write_bytes(
        q4_block * (n_intermediate * (n_hidden // 256)))
    (folder / f"{stem}.up_q4k.bin").write_bytes(
        q4_block * (n_intermediate * (n_hidden // 256)))
    (folder / f"{stem}.down_q6k.bin").write_bytes(
        q6_block * (n_hidden * (n_intermediate // 256)))
    (folder / f"{stem}.hidden.txt").write_text("1\n" * n_hidden, encoding="utf-8")
    return manifest


class ScalarInputAuditTests(unittest.TestCase):
    def test_valid_capture_and_zero_expert(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_capture(Path(directory) / "capture")
            metadata, hashes, outputs = evaluate(manifest)
            self.assertEqual(metadata["expert"], 44)
            self.assertEqual(len(hashes), 5)
            self.assertEqual(outputs["down"], [0.] * 256)

    def test_invalid_quant_type(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_capture(directory, quant="14")
            with self.assertRaises(ValueError):
                parse_manifest(manifest)

    def test_wrong_hidden_length(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_capture(directory)
            (Path(directory) / "k2_l1_e44_s0_scalar_inputs.hidden.txt").write_text("1\n")
            with self.assertRaises(ValueError):
                evaluate(manifest)

    def test_corrupt_packed_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_capture(directory)
            (Path(directory) / "k2_l1_e44_s0_scalar_inputs.up_q4k.bin").write_bytes(b"bad")
            with self.assertRaises(ValueError):
                evaluate(manifest)

    def test_duplicate_manifest_field(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = create_capture(directory)
            with manifest.open("a") as f:
                f.write("layer=1\n")
            with self.assertRaises(ValueError):
                parse_manifest(manifest)

    def test_diagnostic_receipt_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = create_capture(root / "capture")
            out = root / "output"
            out.mkdir()
            receipt = root / "receipt.json"
            argv = ["--manifest", str(manifest), "--output-dir", str(out),
                    "--receipt", str(receipt)]
            self.assertEqual(main(argv), 0)
            result = json.loads(receipt.read_text())
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertEqual(result["gpu_output_witness"], "ABSENT")
            self.assertFalse(result["certified"])
            self.assertEqual(main(argv), 3)


if __name__ == "__main__":
    unittest.main()

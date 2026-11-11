"""Offline regression tests for aggregate GPU stick repeatability receipts."""
import tempfile
import unittest
from pathlib import Path
from k2_stick_partial_repeatability import capture, compare, main


def make(folder, values=(1, 2), experts=((4, .5), (7, .7))):
    folder = Path(folder)
    folder.mkdir(exist_ok=True, parents=True)
    stem = "k2_l1_s0_aggregate"
    lines = ["schema=DEEP2_KIMI_STICK_PARTIAL_001", "layer=1", "stick=0",
             "rows=2", "experts=2", "source=K2MoEStickEndDevice",
             "scope=AGGREGATE_STICK_PARTIAL_NOT_INDIVIDUAL_EXPERT", "certified=0"]
    lines.extend(f"expert={i} weight={w}" for i, w in experts)
    manifest = folder / (stem + ".manifest.txt")
    manifest.write_text("\n".join(lines) + "\n")
    (folder / (stem + ".gpu_partial.txt")).write_text("".join(f"{x}\n" for x in values))
    return manifest


class RepeatabilityTests(unittest.TestCase):
    def test_equal(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = make(Path(root) / "a"), make(Path(root) / "b")
            outcome = compare(capture(a), capture(b), 0, 0)
            self.assertTrue(outcome["within_threshold"])
            self.assertEqual(outcome["max_abs"], 0)

    def test_numerical_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = make(Path(root) / "a"), make(Path(root) / "b", (1, 3))
            self.assertFalse(compare(capture(a), capture(b), .01, .01)["within_threshold"])

    def test_expert_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            a = make(Path(root) / "a")
            b = make(Path(root) / "b", experts=((4, .5), (8, .7)))
            with self.assertRaises(ValueError):
                compare(capture(a), capture(b), 1, 1)

    def test_weight_mismatch(self):
        with tempfile.TemporaryDirectory() as root:
            a = make(Path(root) / "a")
            b = make(Path(root) / "b", experts=((4, .5), (7, .9)))
            with self.assertRaises(ValueError):
                compare(capture(a), capture(b), 1, 1)

    def test_nan_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                capture(make(Path(root) / "a", values=(1, float("nan"))))

    def test_duplicate_expert(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                capture(make(Path(root) / "a", experts=((4, .5), (4, .7))))

    def test_bad_threshold(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = make(Path(root) / "a"), make(Path(root) / "b")
            with self.assertRaises(ValueError):
                compare(capture(a), capture(b), float("nan"), 0)

    def test_cli_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            a, b = make(Path(root) / "a"), make(Path(root) / "b")
            receipt = Path(root) / "receipt.json"
            self.assertEqual(main(["--first", str(a), "--second", str(b),
                                   "--max-abs", "0", "--max-rms", "0",
                                   "--receipt", str(receipt)]), 0)
            self.assertIn('"certified": false', receipt.read_text())

    def test_same_capture_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            a = make(Path(root) / "a")
            receipt = Path(root) / "receipt.json"
            self.assertEqual(main(["--first", str(a), "--second", str(a),
                                   "--max-abs", "0", "--max-rms", "0",
                                   "--receipt", str(receipt)]), 3)


if __name__ == "__main__":
    unittest.main()

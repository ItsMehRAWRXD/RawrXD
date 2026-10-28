"""Synthetic verification of completed aggregate GPU/CPU evidence parser."""
import json
import tempfile
import unittest
from pathlib import Path
from k2_aggregate_vector_audit import read_capture, compare, main


def capture(root, gpu=(1.0, 2.0), cpu=(1.0, 2.0), routes=((4, 0.6), (9, 0.4))):
    folder = Path(root)
    folder.mkdir(parents=True, exist_ok=True)
    prefix = "k2_l2_s0_aggregate_comparison"
    lines = [
        "schema=DEEP2_KIMI_AGGREGATE_COMPARISON_001",
        "layer=2", "stick=0", "rows=2",
        f"experts={len(routes)}",
        "source=POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE",
        "scope=AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY",
        "certified=0",
        *(f"expert={i} weight={weight}" for i, weight in routes),
    ]
    manifest = folder / (prefix + ".manifest.txt")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    for name, values in (("gpu", gpu), ("cpu", cpu)):
        (folder / (prefix + "." + name + ".txt")).write_text(
            "".join(f"{x}\n" for x in values), encoding="utf-8")
    return manifest


class PairedAggregateTests(unittest.TestCase):
    def test_matching_vectors(self):
        with tempfile.TemporaryDirectory() as d:
            r = read_capture(capture(d))
            self.assertTrue(compare(r, 0, 0)["within_threshold"])
            self.assertEqual(r["rows"], 2)
            self.assertEqual(len(r["sha256"]), 3)

    def test_threshold_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            r = read_capture(capture(d, gpu=(1.0, 3.0)))
            self.assertFalse(compare(r, 0.1, 0.1)["within_threshold"])
            self.assertEqual(compare(r, 2.0, 2.0)["worst_index"], 1)

    def test_duplicate_experts_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                read_capture(capture(d, routes=((4, 0.6), (4, 0.4))))

    def test_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                read_capture(capture(d, gpu=(1.0, float("nan"))))

    def test_short_vector_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                read_capture(capture(d, gpu=(1.0,)))

    def test_wrong_provenance_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m = capture(d)
            m.write_text(m.read_text().replace("certified=0", "certified=1"))
            with self.assertRaises(ValueError):
                read_capture(m)

    def test_duplicate_manifest_field_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            m = capture(d)
            m.write_text(m.read_text() + "rows=2\n")
            with self.assertRaises(ValueError):
                read_capture(m)

    def test_negative_threshold_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                compare(read_capture(capture(d)), -1, 0)

    def test_cli_uncertified_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            m = capture(d)
            out = Path(d) / "audit.json"
            args = ["--manifest", str(m), "--max-abs", "0",
                    "--max-rms", "0", "--receipt", str(out)]
            self.assertEqual(main(args), 0)
            receipt = json.loads(out.read_text())
            self.assertFalse(receipt["certified"])
            self.assertEqual(receipt["promote"], 0)
            self.assertEqual(receipt["gpu_expert_witness"], "ABSENT")
            self.assertEqual(main(args), 3)

    def test_cli_diagnostic_failure_exit(self):
        with tempfile.TemporaryDirectory() as d:
            m = capture(d, gpu=(1.0, 3.0))
            out = Path(d) / "audit.json"
            self.assertEqual(main(["--manifest", str(m), "--max-abs", "0",
                                   "--max-rms", "0", "--receipt", str(out)]), 2)
            self.assertEqual(json.loads(out.read_text())["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()

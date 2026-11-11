"""Synthetic tests for provisional GPU scratch-stage forensic comparison."""
import json
import tempfile
import unittest
from pathlib import Path
from k2_provisional_stage_oracle_audit import analyze, main, read_stage
from test_k2_scalar_input_audit import create_capture

RUN = "stageFixture20261027Unique01"
STEM = "k2_l1_e44_s0_provisional_stage"


def fixture(root, *, gpu_act=None, cpu_act=None, gpu_down=None, cpu_down=None):
    root = Path(root)
    stage_dir, scalar_dir = root / "stage", root / "scalar"
    stage_dir.mkdir()
    scalar = create_capture(scalar_dir)
    scalar.write_text(scalar.read_text() + "run_id=" + RUN + "\n")
    manifest = stage_dir / (STEM + ".manifest.txt")
    manifest.write_text(
        "schema=DEEP2_KIMI_PROVISIONAL_STAGE_001\n"
        "layer=1\nexpert=44\nstick=0\n"
        "intermediate_dim=256\nhidden_dim=256\n"
        f"run_id={RUN}\n"
        "source=POST_END_DEVICE_SCRATCH_DOWNLOAD\n"
        "gpu_buffer_identity=UNPROVEN\n"
        "scope=DIAGNOSTIC_NOT_PER_EXPERT_GPU_PARITY\n"
        "certified=0\n", encoding="utf-8")
    for name, provided in (("gpu_act", gpu_act), ("cpu_act", cpu_act),
                           ("gpu_down", gpu_down), ("cpu_down", cpu_down)):
        vals = [0.] * 256 if provided is None else provided
        (stage_dir / f"{STEM}.{name}.txt").write_text(
            "".join(f"{v}\n" for v in vals), encoding="utf-8")
    return manifest, scalar


class ProvisionalStageAuditTests(unittest.TestCase):
    def test_matching_six_way_is_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            result = analyze(stage, scalar, 0, 0)
            self.assertEqual(result["status"], "PASS_DIAGNOSTIC")
            self.assertEqual(len(result["comparisons"]), 6)
            self.assertFalse(result["certified"])
            self.assertEqual(result["gpu_buffer_identity"], "UNPROVEN")
            self.assertEqual(result["g05_g06"], "NOT_CERTIFIED")

    def test_gpu_activation_disagreement_fails(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d, gpu_act=[1.] + [0.] * 255)
            result = analyze(stage, scalar, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["checks"]["gpu_act_vs_oracle"])
            self.assertTrue(result["checks"]["cpu_act_vs_oracle"])

    def test_cpu_down_disagreement_fails(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d, cpu_down=[2.] + [0.] * 255)
            result = analyze(stage, scalar, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["checks"]["cpu_down_vs_oracle"])
            self.assertTrue(result["checks"]["gpu_down_vs_oracle"])

    def test_shared_wrong_output_fails_against_oracle(self):
        with tempfile.TemporaryDirectory() as d:
            wrong = [4.] + [0.] * 255
            stage, scalar = fixture(d, gpu_down=wrong, cpu_down=wrong)
            result = analyze(stage, scalar, 0, 0)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(result["checks"]["gpu_down_vs_cpu"])
            self.assertFalse(result["checks"]["gpu_down_vs_oracle"])

    def test_missing_or_wrong_run_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            scalar.write_text(scalar.read_text().replace(RUN, "otherRun20261027Unique02"))
            with self.assertRaisesRegex(ValueError, "IDENTITY"):
                analyze(stage, scalar, 0, 0)

    def test_missing_run_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            scalar.write_text(scalar.read_text().replace(f"run_id={RUN}\n", ""))
            with self.assertRaisesRegex(ValueError, "IDENTITY"):
                analyze(stage, scalar, 0, 0)

    def test_manifest_claiming_proven_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, _ = fixture(d)
            stage.write_text(stage.read_text().replace(
                "gpu_buffer_identity=UNPROVEN", "gpu_buffer_identity=PROVEN"))
            with self.assertRaisesRegex(ValueError, "provenance"):
                read_stage(stage)

    def test_stage_nonfinite_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, _ = fixture(d, gpu_act=[float("nan")] + [0.] * 255)
            with self.assertRaisesRegex(ValueError, "nonfinite"):
                read_stage(stage)

    def test_wrong_stage_length_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, _ = fixture(d, gpu_down=[0.] * 255)
            with self.assertRaisesRegex(ValueError, "shape"):
                read_stage(stage)

    def test_wrong_stage_identity_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            stage.write_text(stage.read_text().replace("expert=44", "expert=45"))
            with self.assertRaises(ValueError):
                analyze(stage, scalar, 0, 0)

    def test_negative_tolerances_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            with self.assertRaises(ValueError):
                analyze(stage, scalar, -1, 0)

    def test_cli_never_overwrites_or_certifies(self):
        with tempfile.TemporaryDirectory() as d:
            stage, scalar = fixture(d)
            receipt = Path(d) / "receipt.json"
            args = ["--stage-manifest", str(stage),
                    "--scalar-input-manifest", str(scalar),
                    "--max-abs", "0", "--max-rms", "0",
                    "--receipt", str(receipt)]
            self.assertEqual(main(args), 0)
            result = json.loads(receipt.read_text())
            self.assertEqual(result["promote"], 0)
            self.assertFalse(result["certified"])
            self.assertEqual(main(args), 3)


if __name__ == "__main__":
    unittest.main()

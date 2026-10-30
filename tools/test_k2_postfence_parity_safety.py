"""Fail-closed source contract for canonical post-fence GPU diagnostics.

These are source-level regressions only. They do not prove synchronization,
buffer identity, or numerical accuracy on actual GPU hardware.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "src" / "deep2" / "K2NativeMoEFfn_ExpertGpu.cpp"


class PostFenceDiagnosticSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = PATH.read_text(encoding="utf-8")

    def test_aggregate_reference_cannot_skip_unavailable_experts(self):
        self.assertIn("CPU_EXPERT_INPUT_UNAVAILABLE", self.source)
        start = self.source.index('if (!r.g || !r.u || !r.d || !r.gb || !r.ub || !r.db)')
        end = self.source.index('auto gate = QuantKernelRegistry', start)
        segment = self.source[start:end]
        self.assertIn('status=BLOCKED reason=CPU_EXPERT_INPUT_UNAVAILABLE', segment)
        self.assertIn('return;', segment)
        self.assertNotIn('continue;', segment)

    def test_aggregate_is_diagnostic_only(self):
        self.assertIn("scope=DIAGNOSTIC_ONLY", self.source)
        self.assertIn('nonFinite ? "NONFINITE" : "DIAGNOSTIC"', self.source)
        self.assertNotIn("experts=%zu status=OK ", self.source)

    def test_stage_read_blocked_for_multiple_experts(self):
        self.assertIn("MULTI_EXPERT_SCRATCH_IDENTITY_UNPROVEN", self.source)
        self.assertIn("lastExpert >= 0 && work.size() == 1u", self.source)
        self.assertIn("lastExpert >= 0 && work.size() != 1u", self.source)

    def test_stage_has_no_fake_pass(self):
        self.assertIn("DIAGNOSTIC_UNPROVEN_BUFFER_IDENTITY", self.source)
        self.assertNotIn('downloaded ? "OK" : "DOWNLOAD_FAIL"', self.source)
        self.assertNotIn('actDownloaded ? "OK" : "DOWNLOAD_FAIL"', self.source)

    def test_stage_only_runs_after_fused_completion(self):
        post = self.source.index("emitAggregateParity(partial);")
        fused = self.source.index("if (!K2MoEStickEndFused(stick, ctr))")
        complete = self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))")
        self.assertLess(fused, complete)
        self.assertLess(complete, post)

    def test_failed_download_cannot_claim_finite_values(self):
        self.assertIn("downloaded && H > stageNonFinite", self.source)
        self.assertIn("actDownloaded && I > actNonFinite", self.source)
        self.assertIn("downloaded ? H - stageNonFinite : 0u", self.source)
        self.assertIn("actDownloaded ? I - actNonFinite : 0u", self.source)

    def test_aggregate_evidence_is_post_device_and_uncertified(self):
        self.assertIn("CaptureAggregateComparison(", self.source)
        self.assertIn("scope=AGGREGATE_ONLY certified=0", self.source)
        self.assertIn("if (!nonFinite)", self.source)
        self.assertLess(self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))"),
                        self.source.index("emitAggregateParity(partial);"))

    def test_production_path_stays_present(self):
        for anchor in ("K2MoEStickPinExpert(stick",
                       "K2MoEStickBeginFused(stick)",
                       "K2MoEStickExpertDevice(stick",
                       "K2MoEStickEndFused(stick, ctr)",
                       "K2MoEStickEndDevice(stick, partial, H, ctr)"):
            self.assertIn(anchor, self.source)


if __name__ == "__main__":
    unittest.main()

"""Guard against unsynchronized parity reads inside a fused GPU expert worklist.

Static regression check: runtime GPU ordering still requires hardware review.
"""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "deep2" / "K2NativeMoEFfn_ExpertGpu.cpp"


class FusedParitySafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_no_inloop_gpu_download(self):
        self.assertNotIn("DownloadBuf(vc->ArenaDown()", self.source)
        self.assertNotIn("emitParity(r)", self.source)

    def test_fail_closed_status(self):
        self.assertIn("FUSED_OUTPUT_NOT_SYNCHRONIZED", self.source)
        self.assertIn("GPU_EXPERT_PARITY status=BLOCKED", self.source)

    def test_no_capture_called_during_fused_recording(self):
        self.assertNotIn("k2_parity_capture::Capture(", self.source)

    def test_aggregate_capture_after_completed_device_partial(self):
        end = self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))")
        capture = self.source.index("GPU_STICK_PARTIAL_CAPTURE")
        fused = self.source.index("if (!K2MoEStickEndFused(stick, ctr))")
        self.assertLess(fused, end)
        self.assertLess(end, capture)
        self.assertIn("scope=AGGREGATE_STICK_PARTIAL_NOT_INDIVIDUAL_EXPERT", self.source)
        self.assertIn("certified=0", self.source)
        self.assertIn("vectorWritten", self.source)

    def test_scalar_input_witness_is_before_fusion(self):
        call = self.source.index("k2_parity_capture::CaptureScalarInputs(")
        fused = self.source.index("if (!K2MoEStickBeginFused(stick))")
        self.assertLess(call, fused)
        self.assertIn("scope=CPU_INPUTS_ONLY", self.source)
        self.assertIn("GPU_EXPERT_PARITY status=BLOCKED", self.source)

    def test_capture_helper_uses_exclusive_create(self):
        header = (ROOT / "src" / "deep2" / "K2MoEParityCapture.hpp").read_text(
            encoding="utf-8")
        self.assertEqual(header.count('std::fopen(path.string().c_str(), "wbx")'), 2)
        self.assertNotIn('std::fopen(path.string().c_str(), "wb")', header)

    def test_gpu_worklist_not_disabled(self):
        self.assertIn("K2MoEStickBeginFused(stick)", self.source)
        self.assertIn("K2MoEStickExpertDevice(stick", self.source)
        self.assertIn("K2MoEStickEndFused(stick, ctr)", self.source)


if __name__ == "__main__":
    unittest.main()

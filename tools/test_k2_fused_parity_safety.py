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

    def test_gpu_worklist_not_disabled(self):
        self.assertIn("K2MoEStickBeginFused(stick)", self.source)
        self.assertIn("K2MoEStickExpertDevice(stick", self.source)
        self.assertIn("K2MoEStickEndFused(stick, ctr)", self.source)


if __name__ == "__main__":
    unittest.main()

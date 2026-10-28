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
        # Downloads are permitted only in the post-fence stage witness.  The
        # old implementation read ArenaDown during fused recording; assert
        # that the download remains after the completed-device boundary.
        fused_begin = self.source.index("if (!K2MoEStickBeginFused(stick))")
        end_device = self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))")
        # The lambda that owns the post-fence witness is declared earlier in
        # the function, so compare the actual fused-recording region rather
        # than declaration order.
        self.assertNotIn("DownloadBuf(vc->ArenaDown()",
                         self.source[fused_begin:end_device])
        self.assertIn("DownloadBuf(vc->ArenaDown()", self.source)
        self.assertNotIn("emitParity(r)", self.source)

    def test_fail_closed_status(self):
        self.assertIn("GPU_MOE_AGGREGATE_PARITY", self.source)
        self.assertIn("GPU_MOE_LAST_DOWN_PARITY", self.source)
        self.assertIn("GPU_MOE_LAST_ACT_PARITY", self.source)

    def test_capture_helper_uses_exclusive_create(self):
        header = (ROOT / "src" / "deep2" / "K2MoEParityCapture.hpp").read_text(
            encoding="utf-8")
        self.assertEqual(header.count('std::fopen(path.string().c_str(), "wbx")'), 2)
        self.assertNotIn('std::fopen(path.string().c_str(), "wb")', header)

    def test_capture_called_only_after_completed_device(self):
        # A witness is now allowed, but only after the device completion
        # boundary.  This prevents the old in-recording read/ownership bug.
        capture = self.source.index("k2_parity_capture::Capture(")
        lambda_start = self.source.index("auto emitAggregateParity =")
        end = self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))")
        fused = self.source.index("if (!K2MoEStickEndFused(stick, ctr))")
        invoke = self.source.index("emitAggregateParity(partial)")
        self.assertLess(fused, end)
        self.assertGreater(capture, lambda_start)
        self.assertGreater(invoke, end)

    def test_aggregate_capture_after_completed_device_partial(self):
        end = self.source.index("if (!K2MoEStickEndDevice(stick, partial, H, ctr))")
        capture = self.source.index("emitAggregateParity(partial)")
        fused = self.source.index("if (!K2MoEStickEndFused(stick, ctr))")
        self.assertLess(fused, end)
        self.assertLess(end, capture)
        self.assertIn("GPU_MOE_AGGREGATE_PARITY", self.source)
        self.assertIn("DEEP2_MOE_GPU_STAGE_PARITY", self.source)

    def test_gpu_worklist_not_disabled(self):
        self.assertIn("K2MoEStickBeginFused(stick)", self.source)
        self.assertIn("K2MoEStickExpertDevice(stick", self.source)
        self.assertIn("K2MoEStickEndFused(stick, ctr)", self.source)


if __name__ == "__main__":
    unittest.main()

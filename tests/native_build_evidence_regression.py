#!/usr/bin/env python3
"""Prevent false-green native build smoke and PR summary reporting."""
from pathlib import Path
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "build.yml"

class NativeBuildEvidenceRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        cls.smoke = cls.source.split("      - name: Run Smoke Tests", 1)[1].split("      - name:", 1)[0]
        cls.summary = cls.source.split("  build-summary:", 1)[1]

    def test_missing_smoke_binary_is_fatal(self):
        self.assertIn('if (!(Test-Path $smoke)) { throw', self.smoke)
        self.assertIn('& $smoke', self.smoke)
        self.assertIn('$LASTEXITCODE -ne 0', self.smoke)
        self.assertNotIn('no native smoke binary in this configuration', self.smoke)

    def test_summary_uses_actual_job_results(self):
        for name in ("build-windows-msvc", "build-linux-gcc", "build-arm64", "build-size-analysis"):
            self.assertIn("needs." + name + ".result", self.summary)
        self.assertNotIn("All platforms built successfully", self.summary)
        self.assertNotIn("All builds** compiled successfully", self.summary)
        self.assertNotIn("## ✅ Build Verification Complete", self.summary)

    def test_clang_build_cannot_report_success_without_compilation(self):
        clang = self.source.split("  build-windows-clang:", 1)[1].split("  build-linux-gcc:", 1)[0]
        self.assertIn("Clang configure failed with exit code", clang)
        self.assertIn("cmake --build build_clang --parallel 4", clang)
        self.assertIn("Clang build failed with exit code", clang)
        self.assertNotIn("Clang build not available in this environment (optional)", clang)
        self.assertNotIn("exit 0", clang)

    def test_matrix_status_is_not_misattributed_to_individual_legs(self):
        self.assertIn("Windows (MSVC) matrix (x64/Win32, Debug/Release)", self.summary)
        self.assertIn("Aggregate only", self.summary)
        self.assertIn("Inspect individual matrix jobs", self.summary)
        for leg in ("Windows (MSVC) x64 | Debug", "Windows (MSVC) x64 | Release",
                    "Windows (MSVC) x86 | Debug", "Windows (MSVC) x86 | Release"):
            self.assertNotIn(leg, self.summary)

if __name__ == "__main__":
    unittest.main()

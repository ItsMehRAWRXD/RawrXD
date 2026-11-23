#!/usr/bin/env python3
"""Fail-closed source regression for native IDE artifact and synthetic E2E gates."""
from pathlib import Path
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


class NativeIdeArtifactE2EGateRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def section(self, name):
        marker = "      - name: " + name + "\n"
        self.assertEqual(self.source.count(marker), 1, name)
        return self.source.split(marker, 1)[1].split("\n      - name:", 1)[0]

    def test_required_native_executables_are_verified(self):
        section = self.section("Verify native IDE and CLI artifacts")
        for required in ("RawrXD-Win32IDE-Native.exe", "rawr.exe", "Get-ChildItem",
                         "Get-FileHash", "SHA256", "$exe.Length -lt 4096", "throw"):
            self.assertIn(required, section)

    def test_synthetic_e2e_discovery_fails_closed(self):
        discovery = self.section("Verify synthetic-model tests are registered")
        for required in ("ctest --test-dir build -C Release -N",
                         "Deep2CompressedModelE2E", "ZlibAutoDetectSmoke",
                         "$LASTEXITCODE -ne 0", "throw"):
            self.assertIn(required, discovery)
        run = self.section("Run Deep2 compressed synthetic-model E2E")
        for required in ("-R '^Deep2CompressedModelE2E$' --output-on-failure --no-tests=error",
                         "-R '^ZlibAutoDetectSmoke$' --output-on-failure --no-tests=error",
                         "Deep2 compressed model E2E failed", "Zlib auto-detect smoke failed",
                         "ZLIB_AUTODETECT_SMOKE=SKIPPED", "$LASTEXITCODE -ne 0"):
            self.assertIn(required, run)
        self.assertNotIn("^(Deep2CompressedModelE2E|ZlibAutoDetectSmoke)$", run)

    def test_workflow_steps_unique_and_ordered(self):
        names = ("Build Win32 IDE", "Verify native IDE and CLI artifacts",
                 "Verify synthetic-model tests are registered",
                 "Run Deep2 compressed synthetic-model E2E",
                 "Set up Python", "Install Python dependencies",
                 "HexMag swarm smoke test (/ask + /agent)")
        markers = ["      - name: " + name + "\n" for name in names]
        for marker in markers:
            self.assertEqual(self.source.count(marker), 1, marker)
        self.assertEqual([self.source.index(m) for m in markers],
                         sorted(self.source.index(m) for m in markers))
        self.assertEqual(self.source.count("          } finally {"), 1)
        run = self.section("Run Deep2 compressed synthetic-model E2E")
        self.assertEqual(run.count("ctest --test-dir build -C Release -R "), 2)


if __name__ == "__main__":
    unittest.main()

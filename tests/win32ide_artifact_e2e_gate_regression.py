#!/usr/bin/env python3
"""Guard against false-green IDE artifact and synthetic inference CI results."""
from pathlib import Path
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


class NativeIdeArtifactE2EGateRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")

    def test_required_native_executables_are_verified(self):
        section = self.source.split("      - name: Verify native IDE and CLI artifacts", 1)[1].split("      - name:", 1)[0]
        for required in ("RawrXD-Win32IDE-Native.exe", "rawr.exe", "Get-ChildItem", "Get-FileHash", "SHA256"):
            self.assertIn(required, section)
        self.assertIn("throw", section)
        self.assertIn("$exe.Length -lt 4096", section)

    def test_synthetic_e2e_discovery_fails_closed(self):
        section = self.source.split("      - name: Verify synthetic-model tests are registered", 1)[1].split("      - name:", 1)[0]
        for required in ("ctest --test-dir build -C Release -N", "Deep2CompressedModelE2E", "ZlibAutoDetectSmoke", "$LASTEXITCODE -ne 0", "throw"):
            self.assertIn(required, section)
        run = self.source.split("      - name: Run Deep2 compressed synthetic-model E2E", 1)[1].split("      - name:", 1)[0]
        self.assertIn("--output-on-failure", run)
        self.assertIn("$LASTEXITCODE -ne 0", run)
        self.assertIn("--no-tests=error", run)
        self.assertIn("ZLIB_AUTODETECT_SMOKE=SKIPPED", run)
        self.assertIn("Zlib auto-detect smoke failed", run)
        self.assertIn("Deep2 compressed model E2E failed", run)
        self.assertNotIn("^(Deep2CompressedModelE2E|ZlibAutoDetectSmoke)$", run)

    def test_workflow_steps_are_unique_and_ctest_commands_complete(self):
        for name in ("Set up Python", "Install Python dependencies",
                     "HexMag swarm smoke test (/ask + /agent)",
                     "Run Deep2 compressed synthetic-model E2E"):
            self.assertEqual(self.source.count("      - name: " + name + "\n"), 1, name)
        run = self.source.split("      - name: Run Deep2 compressed synthetic-model E2E", 1)[1].split("      - name:", 1)[0]
        self.assertIn("-R '^Deep2CompressedModelE2E
        markers = ("      - name: Build Win32 IDE",
                   "      - name: Verify native IDE and CLI artifacts",
                   "      - name: Verify synthetic-model tests are registered",
                   "      - name: Run Deep2 compressed synthetic-model E2E")
        positions = [self.source.index(m) for m in markers]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
 --output-on-failure --no-tests=error", run)
        self.assertIn("-R '^ZlibAutoDetectSmoke
        markers = ("      - name: Build Win32 IDE",
                   "      - name: Verify native IDE and CLI artifacts",
                   "      - name: Verify synthetic-model tests are registered",
                   "      - name: Run Deep2 compressed synthetic-model E2E")
        positions = [self.source.index(m) for m in markers]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
 --output-on-failure --no-tests=error", run)
        self.assertNotIn("      - name: Set up Python", run)
        self.assertEqual(self.source.count("          } finally {"), 1)
        self.assertEqual(self.source.count("          ctest --test-dir build -C Release -R "), 2)

    def test_gates_follow_build_and_precede_e2e(self):
        markers = ("      - name: Build Win32 IDE",
                   "      - name: Verify native IDE and CLI artifacts",
                   "      - name: Verify synthetic-model tests are registered",
                   "      - name: Run Deep2 compressed synthetic-model E2E")
        positions = [self.source.index(m) for m in markers]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()

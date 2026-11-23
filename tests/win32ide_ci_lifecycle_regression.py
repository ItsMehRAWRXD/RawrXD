#!/usr/bin/env python3
"""Guard the native IDE CI process lifecycle against hangs and collateral kills."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"

class IdeCiLifecycleRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = WORKFLOW.read_text(encoding="utf-8")
        marker = "      - name: HexMag swarm smoke test (/ask + /agent)"
        assert marker in cls.source, "HexMag smoke step missing"
        cls.smoke = cls.source.split(marker, 1)[1].split("\n      - name:", 1)[0]

    def test_smoke_executes_real_endpoints_and_checks_exit(self):
        self.assertIn("python test_smoke.py", self.smoke)
        self.assertIn("$LASTEXITCODE -ne 0", self.smoke)
        self.assertIn("http://localhost:8001/health", self.smoke)

    def test_startup_is_bounded_and_fails_closed(self):
        self.assertRegex(self.smoke, r"AddSeconds\(\s*\d+\s*\)")
        self.assertIn("$swarm.HasExited", self.smoke)
        self.assertIn("throw", self.smoke)
        self.assertIn("if (!$healthy)", self.smoke)

    def test_cleanup_is_scoped_and_always_runs(self):
        self.assertIn("finally {", self.smoke)
        self.assertIn("Stop-Process -Id $swarm.Id", self.smoke)
        self.assertNotRegex(self.smoke, r"(?i)(taskkill\s+/im\s+python|Stop-Process\s+-Name\s+python|Get-Process\s+python)")
        self.assertIn("-PassThru", self.smoke)

if __name__ == "__main__":
    unittest.main()

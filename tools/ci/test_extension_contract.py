#!/usr/bin/env python3
"""Source-level extension-host guard checks; NOT runtime acceptance.

Run: python3 tools/ci/test_extension_contract.py [repository-root]
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
sys.argv = sys.argv[:1]
CORE = ROOT / "~dev" / "rawrxd" / "src" / "core"

class ExtensionContract(unittest.TestCase):
    def source(self, name):
        path = CORE / name
        self.assertTrue(path.is_file(), f"missing authoritative source: {path}")
        return path.read_text(encoding="utf-8")

    def test_real_host_has_dependency_gate(self):
        src = self.source("js_extension_host.cpp")
        self.assertIn("RAWRXD_REQUIRE_QUICKJS", src)
        self.assertIn("#error", src)
        self.assertIn("RAWRXD_HAS_QUICKJS 0", src)
        self.assertIn("RAWRXD_HAS_QUICKJS 1", src)

    def test_headless_stubs_fail_closed(self):
        src = self.source("js_extension_host_headless_impl.cpp")
        for name in ("initialize", "activateExtension", "loadVSIX", "loadExtensionFromDir", "executeScript"):
            start = src.find("JSExtensionHost::" + name + "(")
            self.assertGreaterEqual(start, 0, f"missing {name}")
            body = src[start:src.find("\n}", start) + 2]
            self.assertIn("PatchResult::error(", body, f"{name} must not report a fake PASS")

    def test_production_bridge_does_not_fake_success(self):
        src = self.source("js_extension_host_production.cpp")
        for name in ("Initialize", "ExecuteScript", "LoadExtension"):
            start = src.find("bool " + name + "(")
            self.assertGreaterEqual(start, 0, f"missing {name}")
            body = src[start:src.find("\n    }", start) + 6]
            self.assertIn("return false;", body, f"{name} cannot claim success without runtime")

    def test_agent_bridge_modes_are_instance_scoped(self):
        """Guard against cross-IDE mode leakage from function static toggles."""
        header = ROOT / "src" / "win32app" / "Win32IDE_AgenticBridge.h"
        impl = ROOT / "src" / "win32app" / "Win32IDE_AgenticBridge.cpp"
        self.assertTrue(header.is_file())
        self.assertTrue(impl.is_file())
        h = header.read_text(encoding="utf-8")
        cpp = impl.read_text(encoding="utf-8")
        for mode in ("m_deepThinkEnabled", "m_deepResearchEnabled", "m_noRefusalEnabled"):
            self.assertIn("bool " + mode + " = false;", h)
            self.assertIn(mode + " = !" + mode + ";", cpp)
        self.assertNotIn("static bool t = false", cpp)
        self.assertNotIn("static bool r = false", cpp)
        self.assertNotIn("static bool n = false", cpp)

if __name__ == "__main__":
    unittest.main(verbosity=2)

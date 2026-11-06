"""Source-contract regression for the headless extension link-closure implementation.

Run: python -m unittest discover -s tests -p test_headless_extension_failclosed.py
This does not replace native runtime testing.
"""
from pathlib import Path
import re
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"

class HeadlessExtensionFailClosedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")

    def method_body(self, method):
        pattern = r"PatchResult\s+JSExtensionHost::" + re.escape(method) + r"\s*\([^)]*\)\s*\{([^{}]*)\}"
        match = re.search(pattern, self.source, re.S)
        self.assertIsNotNone(match, f"Method missing: {method}")
        return match.group(1)

    def test_unavailable_operations_fail_closed(self):
        for name in ("initialize", "activateExtension", "deactivateExtension",
                     "loadVSIX", "loadExtensionFromDir", "unloadExtension",
                     "fireEvent", "registerModuleResolver", "executeScript"):
            with self.subTest(method=name):
                body = self.method_body(name)
                self.assertIn("PatchResult::error(", body)
                self.assertNotIn("PatchResult::ok(", body)

    def test_no_false_initialized_state(self):
        self.assertIn("m_initialized = false;", self.method_body("initialize"))

    def test_shutdown_is_idempotent_success(self):
        self.assertIn("PatchResult::ok(", self.method_body("shutdown"))

if __name__ == "__main__":
    unittest.main()

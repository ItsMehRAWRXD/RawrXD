#!/usr/bin/env python3
"""Source-level regression guard for the intentionally unavailable headless JS host.

This is a static contract check, NOT a native integration or QuickJS execution test.
Run: python3 tests/test_headless_extension_contract.py
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"

def body_of(source: str, name: str) -> str:
    pattern = rf"\b(?:PatchResult|bool)\s+JSExtensionHost::{re.escape(name)}\s*\([^)]*\)\s*(?:const\s*)?\{{"
    match = re.search(pattern, source)
    if match is None:
        raise AssertionError(f"Missing method: {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"Unclosed method: {name}")

class HeadlessExtensionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text(encoding="utf-8")

    def test_unsupported_methods_fail_closed(self):
        methods = (
            "initialize", "activateExtension", "deactivateExtension",
            "unloadExtension", "loadVSIX", "loadExtensionFromDir",
            "fireEvent", "registerModuleResolver", "executeScript",
        )
        for name in methods:
            with self.subTest(method=name):
                body = body_of(self.source, name)
                self.assertIn("PatchResult::error(", body)
                self.assertNotIn("PatchResult::ok(", body)

    def test_initialize_never_claims_ready(self):
        body = body_of(self.source, "initialize")
        self.assertIn("m_initialized = false;", body)
        self.assertNotIn("m_initialized = true;", body)

    def test_shutdown_clears_ready_state(self):
        body = body_of(self.source, "shutdown")
        self.assertIn("m_initialized = false;", body)

    def test_failed_script_execution_clears_output(self):
        body = body_of(self.source, "executeScript")
        self.assertIn("if (outResult && maxResultLen)", body)
        self.assertIn("outResult[0] = '\\0';", body)

    def test_failed_vsix_verification_is_not_valid_or_signed(self):
        body = body_of(self.source, "verifyVSIX")
        for statement in ("r.isValid = false;", "r.isSigned = false;", "r.signatureVerified = false;"):
            self.assertIn(statement, body)

    def test_unavailable_js_extension_predicate(self):
        body = body_of(self.source, "isJSExtension")
        self.assertIn("return false;", body)

if __name__ == "__main__":
    unittest.main(verbosity=2)

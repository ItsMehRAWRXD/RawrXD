"""Regression tests for extension_headless_contract.py (fixture-based, no model)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("extension_headless_contract.py")
METHODS = (
    "initialize", "shutdown", "activateExtension", "deactivateExtension",
    "loadVSIX", "loadExtensionFromDir", "unloadExtension", "fireEvent",
    "registerModuleResolver", "executeScript",
)

class HeadlessContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        directory = self.root / "~dev/rawrxd/src/core"
        directory.mkdir(parents=True)
        self.header = directory / "js_extension_host.hpp"
        self.stub = directory / "js_extension_host_headless_impl.cpp"
        self.header.write_text("\n".join("PatchResult " + name + "();" for name in METHODS), encoding="utf-8")
        functions = [
            "JSExtensionHost::JSExtensionHost() : m_jsRuntime(nullptr), m_jsContext(nullptr), m_queueEvent(nullptr), m_nextTimerId(0), m_initialized(false), m_shutdownCompleted(false), m_hostThread(nullptr), m_running(false), m_stats{} {}",
        ]
        for name in METHODS:
            body = 'return PatchResult::error("unsupported");'
            if name == "initialize":
                body = "m_initialized = false; " + body
            if name == "executeScript":
                body = "outResult[0] = '\\0'; " + body
            functions.append("PatchResult JSExtensionHost::" + name + "() { " + body + " }")
        functions.extend([
            "uint64_t JSExtensionHost::createTimer() { return 0; }",
            "void JSExtensionHost::getLoadedExtensions() const { *outCount = 0; }",
            "JSExtensionHost::VSIXVerificationResult JSExtensionHost::verifyVSIX() const { r.isValid = false; r.signatureVerified = false; }",
        ])
        self.stub.write_text("\n".join(functions), encoding="utf-8")

    def run_gate(self):
        process = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--json"],
            capture_output=True, text=True, check=False,
        )
        return process, json.loads(process.stdout)

    def test_valid_fixture_passes_all_source_contracts(self):
        process, report = self.run_gate()
        self.assertEqual(process.returncode, 0, report)
        self.assertEqual(report["passed"], 16)
        self.assertEqual(report["failed"], 0)
        self.assertFalse(report["native_runtime_executed"])

    def test_missing_constructor_initializer_fails_closed(self):
        source = self.stub.read_text(encoding="utf-8")
        self.stub.write_text(source.replace("m_queueEvent(nullptr), ", ""), encoding="utf-8")
        process, report = self.run_gate()
        self.assertNotEqual(process.returncode, 0)
        self.assertIn("headless_constructor_state_initialized",
                      [r["gate"] for r in report["results"] if r["status"] == "FAIL"])

    def test_missing_source_fails_closed(self):
        self.stub.unlink()
        process, report = self.run_gate()
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(report["failed"], 1)

    def test_false_success_fails_closed(self):
        source = self.stub.read_text(encoding="utf-8")
        self.stub.write_text(source.replace('PatchResult::error("unsupported")', "PatchResult::success()", 1), encoding="utf-8")
        process, report = self.run_gate()
        self.assertNotEqual(process.returncode, 0)
        self.assertGreater(report["failed"], 0)

    def test_missing_method_fails_closed(self):
        source = self.header.read_text(encoding="utf-8")
        self.header.write_text(source.replace("PatchResult activateExtension();", ""), encoding="utf-8")
        process, report = self.run_gate()
        self.assertNotEqual(process.returncode, 0)
        self.assertGreater(report["failed"], 0)

if __name__ == "__main__":
    unittest.main()

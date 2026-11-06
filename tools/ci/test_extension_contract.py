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

    def test_extension_loader_rejects_invalid_entry_before_registration(self):
        """Source guard only: fail-closed loader checks must remain wired."""
        src = self.source("js_extension_host.cpp")
        start = src.index("PatchResult JSExtensionHost::loadExtensionFromDir(")
        end = src.index("PatchResult JSExtensionHost::activateExtension(", start)
        loader = src[start:end]
        for check in (
            'if (mainEntry.empty()) mainEntry = "extension.js";',
            "validRelativeMain(mainEntry)",
            "entryWithinRoot(",
            "mainSize == 0 || mainSize > 10 * 1024 * 1024",
            'if (mainSource.empty())',
        ):
            self.assertIn(check, loader)
        self.assertLess(loader.index('if (mainSource.empty())'),
                        loader.index('m_extensions.emplace('))

    def test_activation_failure_invalidates_native_callbacks(self):
        """Source guard only: never free a context with live command callbacks."""
        src = self.source("js_extension_host.cpp")
        start = src.index("PatchResult JSExtensionHost::activateExtension(")
        end = src.index("PatchResult JSExtensionHost::deactivateExtension(", start)
        activation = src[start:end]
        failure = activation[activation.index("if (JS_IsException(result))"):]
        self.assertLess(failure.index("binding.ctx = nullptr;"),
                        failure.index("JS_FreeContext(extCtx);"))
        self.assertLess(failure.index("JS_FreeContext(extCtx);"),
                        failure.index("state->jsContext = nullptr;"))

    def test_activation_microtask_failure_is_fail_closed(self):
        """Source contract: failed QuickJS jobs must not count as activation."""
        src = self.source("js_extension_host.cpp")
        start = src.index("PatchResult JSExtensionHost::activateExtension(")
        end = src.index("PatchResult JSExtensionHost::deactivateExtension(", start)
        activation = src[start:end]
        self.assertIn("jobResult < 0", activation)
        self.assertIn('PatchResult::error("Extension activation microtask failed")', activation)
        failure = activation[activation.index("if (jobResult < 0)"):]
        self.assertLess(failure.index("binding.ctx = nullptr;"),
                        failure.index("JS_FreeContext(extCtx);"))
        self.assertLess(failure.index("JS_FreeContext(extCtx);"),
                        failure.index('return PatchResult::error("Extension activation microtask failed")'))
        self.assertLess(failure.index('return PatchResult::error("Extension activation microtask failed")'),
                        failure.index("state->activated = true;"))

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

    def test_agent_loop_rejects_invalid_inputs(self):
        cpp = (ROOT / "src" / "win32app" / "Win32IDE_AgenticBridge.cpp").read_text(encoding="utf-8")
        start = cpp.index("bool AgenticBridge::StartAgentLoop(")
        end = cpp.index("void AgenticBridge::StopAgentLoop()", start)
        body = cpp[start:end]
        self.assertIn("initialPrompt.empty()", body)
        self.assertIn("maxIterations <= 0", body)
        self.assertLess(body.index("initialPrompt.empty()"), body.index("m_agentThread = std::thread("))

    def test_agent_bridge_releases_child_pipe_endpoints(self):
        """Static guard only; Windows process lifecycle still needs runtime testing."""
        cpp = (ROOT / "src" / "win32app" / "Win32IDE_AgenticBridge.cpp").read_text(encoding="utf-8")
        start = cpp.index("m_hProcess = piProcInfo.hProcess;")
        end = cpp.index("return true;", start)
        success = cpp[start:end]
        for handle in ("m_hStdoutWrite", "m_hStdinRead"):
            self.assertIn("CloseHandle(" + handle + ");", success)
            self.assertIn(handle + " = nullptr;", success)

if __name__ == "__main__":
    unittest.main(verbosity=2)

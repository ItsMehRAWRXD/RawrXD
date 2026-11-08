"""Static integration contracts; NEVER a substitute for native GUI or QuickJS runtime tests."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SIDEBAR = (ROOT / "src/win32app/Win32IDE_Sidebar.cpp").read_text(encoding="utf-8")
HOST = (ROOT / "~dev/rawrxd/src/core/js_extension_host.cpp").read_text(encoding="utf-8")
CMAKE = (ROOT / "~dev/rawrxd/CMakeLists.txt").read_text(encoding="utf-8")
STORE = (ROOT / "src/win32app/OfflineExtensionStore.h").read_text(encoding="utf-8")

class ExtensionIntegrationSourceContracts(unittest.TestCase):
    def test_sidebar_uses_real_offline_store(self):
        self.assertIn('#include "OfflineExtensionStore.h"', SIDEBAR)
        self.assertGreaterEqual(SIDEBAR.count("OfflineExtensions::Store store(extensionRoot())"), 7)

    def test_sidebar_has_no_fabricated_installed_extensions(self):
        self.assertNotIn('"github.copilot", "GitHub Copilot"', SIDEBAR)
        self.assertNotIn('"powershell.vscode", "PowerShell"', SIDEBAR)

    def test_extension_controls_receive_command_notifications(self):
        self.assertIn("SetWindowLongPtrA(m_hwndSidebarContent, GWLP_WNDPROC, (LONG_PTR)SidebarProc)", SIDEBAR)
        self.assertIn("case WM_COMMAND:", SIDEBAR)
        self.assertIn("case WM_SIZE:", SIDEBAR)
        self.assertIn("hwnd == pThis->m_hwndSidebar", SIDEBAR)

    def test_extension_search_uses_list_index_params(self):
        self.assertIn("ListView_GetItemA(", SIDEBAR)
        self.assertIn("ListView_InsertItemA(", SIDEBAR)
        self.assertIn("item.lParam = static_cast<LPARAM>(i)", SIDEBAR)

    def test_sidebar_does_not_claim_runtime_activation(self):
        self.assertIn("host activation not implied", SIDEBAR)
        self.assertIn("Execution status: not verified", SIDEBAR)

    def test_external_extensions_have_read_only_details(self):
        self.assertIn("External extension: ", SIDEBAR)
        self.assertIn("Management: read-only (use VS Code/Cursor)", SIDEBAR)
        self.assertIn("Runtime compatibility: not verified", SIDEBAR)

    def test_cli_is_in_native_build(self):
        self.assertIn("include(cmake/OfflineExtensionsCli.cmake)", CMAKE)
        fragment = (ROOT / "~dev/rawrxd/cmake/OfflineExtensionsCli.cmake").read_text(encoding="utf-8")
        self.assertIn("add_executable(RawrXD-ExtensionsCLI", fragment)

    def test_api_namespaces_not_overwritten_after_bind(self):
        beg = HOST.index("void JSExtensionHost::bindVSCodeAPI(")
        end = HOST.index("void JSExtensionHost::bindVSCodeCommands(", beg)
        body = HOST[beg:end]
        self.assertLess(body.index('JS_SetPropertyStr(cx, global, "vscode", JS_NewObject(cx))'),
                        body.index("bindVSCodeCommands(ctx);"))
        self.assertEqual(body.count('JS_SetPropertyStr(cx, global, "vscode"'), 1)

    def test_entry_path_must_resolve_inside_extension(self):
        self.assertIn("rawrxd::extensions::entryWithinRoot(", HOST)
        self.assertIn("Extension main entry escapes installation root", HOST)
        self.assertIn("std::filesystem::is_regular_file(mainPath", HOST)

    def test_unsigned_vsix_is_not_silently_accepted(self):
        self.assertIn("Unsigned or unverified VSIX rejected", HOST)
        self.assertIn("explicitOptIn", HOST)
        self.assertIn("return result;", HOST)

    def test_extraction_rejects_unsafe_shell_inputs(self):
        self.assertIn("VSIX extraction path contains unsafe command characters", HOST)
        self.assertIn("-LiteralPath", HOST)
        self.assertIn("VSIX extraction command exceeds safe length", HOST)

    def test_store_has_rollback_recovery(self):
        self.assertIn("fs::rename(dest, backup)", STORE)
        self.assertIn("size_t recover()", STORE)
        self.assertIn("Invalid extension ID", STORE)

    def test_store_will_not_execute_package_js(self):
        self.assertNotIn("system(", STORE)
        self.assertNotIn("CreateProcess", STORE)
        self.assertNotIn("JS_Eval", STORE)

if __name__ == "__main__":
    unittest.main()

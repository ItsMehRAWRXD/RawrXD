"""Static guard for manifest-controlled JS extension entry-point containment.

Run: python -m unittest discover -s tests -p test_extension_entry_containment.py
Native path/junction tests must also run on Windows.
"""
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "~dev/rawrxd/src/core/js_extension_host.cpp"

class ExtensionEntryContainmentTests(unittest.TestCase):
    def test_canonical_root_and_entry_checked_before_registration(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("PatchResult JSExtensionHost::loadExtensionFromDir(")
        end = source.index("// Extension Lifecycle", start)
        body = source[start:end]
        for required in (
            "weakly_canonical(extRoot", "weakly_canonical(mainPath",
            "entry.lexically_relative(root)", 'std::filesystem::path("..")',
            "std::filesystem::is_regular_file(entry",
            "m_extensions[extensionId] = std::move(state)"
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertLess(body.index("entry.lexically_relative(root)"),
                        body.index("m_extensions[extensionId] = std::move(state)"))

    def test_duplicate_extension_rejected_before_registration(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("PatchResult JSExtensionHost::loadExtensionFromDir(")
        end = source.index("// Extension Lifecycle", start)
        body = source[start:end]
        self.assertIn("m_extensions.find(extensionId) != m_extensions.end()", body)
        self.assertIn('return PatchResult::error("Extension already loaded', body)
        self.assertIn("m_extensions.emplace(extensionId, std::move(state))", body)
        self.assertNotIn("m_extensions[extensionId] = std::move(state)", body)

    def test_incomplete_manifest_reads_are_rejected(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("std::string readFileToString(")
        end = source.index("// Write string to file", start)
        body = source[start:end]
        self.assertIn('if (!ok || bytesRead != content.size()) return "";', body)

    def test_deactivation_error_prevents_unload(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("PatchResult JSExtensionHost::unloadExtension(")
        end = source.index("// JS Extension detection", start)
        body = source[start:end]
        self.assertIn("PatchResult deactivateResult = deactivateExtension(extensionId)", body)
        self.assertIn("if (!deactivateResult.success) return deactivateResult;", body)
        self.assertLess(body.index("if (!deactivateResult.success)"),
                        body.index("m_extensions.erase(it)"))

    def test_deactivate_js_exception_is_reported(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("PatchResult JSExtensionHost::deactivateExtension(")
        end = source.index("PatchResult JSExtensionHost::unloadExtension(", start)
        body = source[start:end]
        self.assertIn("sizeof(deactivateScript) - 1", body)
        self.assertIn("JS_IsException(result)", body)
        self.assertIn('return PatchResult::error("Extension deactivate callback failed")', body)

if __name__ == "__main__":
    unittest.main()

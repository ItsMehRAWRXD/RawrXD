#!/usr/bin/env python3
"""15 deterministic simulator checks; no claim of native runtime coverage."""
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from extension_lifecycle_sim import SimulatedExtensionHost, ExtensionError

MANIFEST = {"publisher": "test", "name": "sample", "version": "1.0.0"}

class ExtensionLifecycleSimulationTests(unittest.TestCase):
    def setUp(self):
        self.host = SimulatedExtensionHost()

    def installed(self):
        return self.host.install_manifest(dict(MANIFEST))

    def test_01_valid_manifest(self):
        self.assertEqual(self.installed(), "test.sample")

    def test_02_missing_field(self):
        with self.assertRaises(ExtensionError):
            self.host.install_manifest({"name": "sample", "version": "1.0.0"})

    def test_03_bad_version(self):
        with self.assertRaises(ExtensionError):
            self.host.install_manifest({**MANIFEST, "version": "latest"})

    def test_04_duplicate(self):
        self.installed()
        with self.assertRaises(ExtensionError):
            self.installed()

    def test_05_activation(self):
        key = self.installed()
        self.host.activate(key)
        self.assertTrue(self.host.extensions[key].active)

    def test_06_unknown_activation(self):
        with self.assertRaises(ExtensionError):
            self.host.activate("missing")

    def test_07_deactivation(self):
        key = self.installed()
        self.host.activate(key)
        self.host.deactivate(key)
        self.assertFalse(self.host.extensions[key].active)

    def test_08_command_requires_activation(self):
        key = self.installed()
        with self.assertRaises(ExtensionError):
            self.host.register_command(key, "hello", lambda: 1)

    def test_09_command_execution(self):
        key = self.installed()
        self.host.activate(key)
        self.host.register_command(key, "hello", lambda x: x + 1)
        self.assertEqual(self.host.execute_command("hello", 3), 4)

    def test_10_duplicate_command(self):
        key = self.installed()
        self.host.activate(key)
        self.host.register_command(key, "hello", lambda: None)
        with self.assertRaises(ExtensionError):
            self.host.register_command(key, "hello", lambda: None)

    def test_11_deactivation_clears_commands(self):
        key = self.installed()
        self.host.activate(key)
        self.host.register_command(key, "hello", lambda: None)
        self.host.deactivate(key)
        with self.assertRaises(ExtensionError):
            self.host.execute_command("hello")

    def test_12_event_recording(self):
        self.host.fire_event("onSave", {"file": "a"})
        self.assertEqual(self.host.events, [("onSave", {"file": "a"})])

    def test_13_uninstall(self):
        key = self.installed()
        self.host.uninstall(key)
        self.assertNotIn(key, self.host.extensions)

    def _vsix(self, entries):
        f = tempfile.NamedTemporaryFile(suffix=".vsix", delete=False)
        f.close()
        self.addCleanup(lambda: Path(f.name).unlink(missing_ok=True))
        with zipfile.ZipFile(f.name, "w") as z:
            for name, data in entries.items():
                z.writestr(name, data)
        return f.name

    def test_14_valid_vsix(self):
        archive = self._vsix({"extension/package.json": json.dumps(MANIFEST)})
        self.assertEqual(self.host.install_vsix(archive), "test.sample")

    def test_15_traversal_rejected(self):
        archive = self._vsix({"../escape": "x", "extension/package.json": json.dumps(MANIFEST)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_16_windows_drive_path_rejected(self):
        archive = self._vsix({"C:/evil.txt": "x", "extension/package.json": json.dumps(MANIFEST)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_17_backslash_traversal_rejected(self):
        archive = self._vsix({"..\\\\evil.txt": "x", "extension/package.json": json.dumps(MANIFEST)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_18_case_colliding_entries_rejected(self):
        archive = self._vsix({"extension/package.json": json.dumps(MANIFEST), "Extension/Package.json": "{}"})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_19_invalid_json_rejected(self):
        archive = self._vsix({"extension/package.json": "{bad"})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_20_missing_manifest_rejected(self):
        archive = self._vsix({"extension/README.md": "readme"})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_21_absolute_path_rejected(self):
        archive = self._vsix({"/tmp/evil": "x", "extension/package.json": json.dumps(MANIFEST)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_22_oversized_manifest_rejected(self):
        archive = self._vsix({"extension/package.json": " " * (256 * 1024 + 1)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_23_symlink_entry_rejected(self):
        archive = self._vsix({"extension/package.json": json.dumps(MANIFEST)})
        with zipfile.ZipFile(archive, "a") as z:
            info = zipfile.ZipInfo("extension/link")
            info.create_system = 3
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "target")
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_24_archive_total_size_rejected(self):
        entries = {"extension/package.json": json.dumps(MANIFEST)}
        for n in range(5):
            entries[f"extension/data{n}"] = "a" * (8 * 1024 * 1024)
        archive = self._vsix(entries)
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_25_manifest_not_object_rejected(self):
        archive = self._vsix({"extension/package.json": "[]"})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_26_single_backslash_traversal_rejected(self):
        archive = self._vsix({chr(46)+chr(46)+chr(92)+"evil.txt": "x", "extension/package.json": json.dumps(MANIFEST)})
        with self.assertRaises(ExtensionError):
            self.host.install_vsix(archive)

    def test_27_backslash_manifest_supported(self):
        archive = self._vsix({"extension"+chr(92)+"package.json": json.dumps(MANIFEST)})
        self.assertEqual(self.host.install_vsix(archive), "test.sample")

    def test_28_case_variant_manifest_supported(self):
        archive = self._vsix({"Extension/Package.json": json.dumps(MANIFEST)})
        self.assertEqual(self.host.install_vsix(archive), "test.sample")

if __name__ == "__main__":
    unittest.main(verbosity=2)

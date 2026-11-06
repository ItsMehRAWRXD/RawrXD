"""Black-box, subprocess-based C++ extension tests. No network, Ollama or model required."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

EXE = Path(os.environ.get("RAWRXD_EXTENSIONS_BIN", str(
    Path(__file__).resolve().parents[1] / ("rawrxd-extensions.exe" if os.name == "nt" else "rawrxd-extensions"))))

class OfflineExtensionAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.installed = self.home / "installed"

    def package(self, folder="package", name="sample", publisher="example", version="1.0.0"):
        src = self.home / folder
        src.mkdir()
        (src / "package.json").write_text(json.dumps(dict(
            name=name, publisher=publisher, version=version, description="test")), encoding="utf-8")
        (src / "main.js").write_text('throw new Error("should not execute")', encoding="utf-8")
        return src

    def cli(self, *argv, ok=True):
        proc = subprocess.run([str(EXE), "--root", str(self.installed), "--approve-mutations", *map(str, argv)],
                              capture_output=True, text=True, timeout=15)
        if ok:
            self.assertEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
        else:
            self.assertNotEqual(proc.returncode, 0, (proc.stdout, proc.stderr))
        return proc.stdout

    def test_01_empty_listing(self):
        self.assertEqual(self.cli("list"), "")

    def test_02_install_and_info(self):
        self.cli("install", self.package())
        self.assertIn("example.sample\t1.0.0\tenabled", self.cli("info", "example.sample"))

    def test_03_list_installed(self):
        self.cli("install", self.package())
        self.assertIn("example.sample", self.cli("list"))

    def test_04_disable_persists(self):
        self.cli("install", self.package())
        self.cli("disable", "example.sample")
        self.assertIn("disabled", self.cli("list"))

    def test_05_enable_persists(self):
        self.cli("install", self.package())
        self.cli("disable", "example.sample")
        self.cli("enable", "example.sample")
        self.assertIn("enabled", self.cli("list"))

    def test_06_update_preserves_disabled_state(self):
        self.cli("install", self.package())
        self.cli("disable", "example.sample")
        self.cli("update", self.package("replacement", version="2.0.0"))
        self.assertIn("example.sample\t2.0.0\tdisabled", self.cli("info", "example.sample"))

    def test_07_uninstall(self):
        self.cli("install", self.package())
        self.cli("remove", "example.sample")
        self.assertEqual(self.cli("list"), "")

    def test_08_duplicate_install_rejected(self):
        src = self.package()
        self.cli("install", src)
        self.cli("install", src, ok=False)

    def test_09_invalid_id_rejected(self):
        self.cli("remove", "../../outside", ok=False)
        self.cli("disable", "C:\\Windows\\System32", ok=False)

    def test_10_reserved_windows_id_rejected(self):
        self.cli("install", self.package(publisher="CON"), ok=False)

    def test_11_malformed_manifest_rejected(self):
        src = self.package()
        (src / "package.json").write_text("{not json")
        self.cli("install", src, ok=False)

    def test_12_symlinked_root_rejected(self):
        src = self.package()
        external = self.home / "external"
        external.mkdir()
        try:
            self.installed.symlink_to(external, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks unavailable")
        self.cli("install", src, ok=False)

    def test_13_symlinked_package_member_rejected(self):
        src = self.package()
        try:
            (src / "external").symlink_to(self.home, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks unavailable")
        self.cli("install", src, ok=False)

    def test_14_rollback_preserves_original(self):
        self.cli("install", self.package())
        (self.installed / "example.sample.rawrxd-backup").mkdir()
        self.cli("update", self.package("replacement", version="3.0.0"), ok=False)
        self.assertIn("\t1.0.0\t", self.cli("info", "example.sample"))

    def test_15_interrupted_update_recovery(self):
        self.cli("install", self.package())
        (self.installed / "example.sample").rename(
            self.installed / "example.sample.rawrxd-backup")
        self.assertIn("restored\t1", self.cli("recover"))
        self.assertIn("example.sample", self.cli("list"))

    def test_16_invalid_extension_ignored(self):
        self.installed.mkdir()
        broken = self.installed / "bad.extension"
        broken.mkdir()
        (broken / "package.json").write_text("{garbled")
        self.assertEqual(self.cli("list"), "")

    def test_17_source_inside_store_rejected(self):
        self.installed.mkdir()
        source = self.installed / "unpacked"
        source.mkdir()
        (source / "package.json").write_text(json.dumps(dict(
            name="sample", publisher="example", version="1.0.0")))
        self.cli("install", source, ok=False)

    def test_18_no_execution_during_install(self):
        self.cli("install", self.package())
        self.assertTrue((self.installed / "example.sample" / "main.js").exists())

    def test_19_mutations_require_explicit_approval(self):
        src = self.package()
        proc = subprocess.run([str(EXE), "--root", str(self.installed), "install", str(src)],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("--approve-mutations", proc.stderr)
        self.assertFalse(self.installed.exists())

    def test_19_unsupported_commands_fail(self):
        self.cli("execute", "example.sample", ok=False)

    def test_20_unknown_extensions_fail(self):
        self.cli("info", "nonexistent.extension", ok=False)
        self.cli("remove", "nonexistent.extension", ok=False)

if __name__ == "__main__":
    unittest.main()

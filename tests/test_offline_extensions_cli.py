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
        self.assertIn("recovered\t1", self.cli("recover"))
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
        src = self.package()
        marker = self.home / "executed-by-extension"
        (src / "main.js").write_text(
            'require("fs").writeFileSync(' + json.dumps(str(marker)) + ', "executed")',
            encoding="utf-8")
        self.cli("install", src)
        self.assertTrue((self.installed / "example.sample" / "main.js").exists())
        self.assertFalse(marker.exists(), "Installing must not activate extension JS")

    def test_19_mutations_require_explicit_approval(self):
        src = self.package()
        proc = subprocess.run([str(EXE), "--root", str(self.installed), "install", str(src)],
                              capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 3)
        self.assertIn("--approve-mutations", proc.stderr)
        self.assertFalse(self.installed.exists())

    def test_19_unsupported_commands_fail(self):
        self.cli("execute", "example.sample", ok=False)

    def test_21_duplicate_manifest_keys_rejected(self):
        src = self.package()
        (src / "package.json").write_text(
            '{"name":"sample","name":"other","publisher":"example","version":"1.0.0"}',
            encoding="utf-8")
        self.cli("install", src, ok=False)

    def test_22_malformed_json_numeric_token_rejected(self):
        src = self.package()
        (src / "package.json").write_text(
            '{"name":"sample","publisher":"example","version":"1.0.0","count":1e}',
            encoding="utf-8")
        self.cli("install", src, ok=False)

    def test_23_disable_idempotent(self):
        self.cli("install", self.package())
        self.cli("disable", "example.sample")
        self.cli("disable", "example.sample")
        self.assertIn("disabled", self.cli("list"))

    def test_24_recover_orphaned_install_stage(self):
        src = self.package()
        self.installed.mkdir()
        import shutil
        stage = self.installed / "example.sample.rawrxd-stage"
        shutil.copytree(src, stage)
        self.assertIn("recovered\t1", self.cli("recover"))
        self.assertFalse(stage.exists())
        self.cli("install", src)
        self.assertIn("example.sample", self.cli("list"))

    def test_25_recover_update_with_stage_and_backup(self):
        src = self.package()
        self.cli("install", src)
        self.cli("disable", "example.sample")
        import shutil
        replacement = self.package("v2", version="2.0.0")
        stage = self.installed / "example.sample.rawrxd-stage"
        shutil.copytree(replacement, stage)
        (self.installed / "example.sample").rename(
            self.installed / "example.sample.rawrxd-backup")
        self.assertIn("recovered\t2", self.cli("recover"))
        self.assertIn("example.sample\t1.0.0\tdisabled", self.cli("info", "example.sample"))
        self.assertFalse(stage.exists())
        self.cli("update", replacement)
        self.assertIn("2.0.0\tdisabled", self.cli("info", "example.sample"))

    def test_26_cleanup_backup_after_committed_update(self):
        src = self.package()
        self.cli("install", src)
        import shutil
        backup = self.installed / "example.sample.rawrxd-backup"
        shutil.copytree(self.installed / "example.sample", backup)
        self.assertIn("recovered\t1", self.cli("recover"))
        self.assertFalse(backup.exists())
        self.assertIn("1.0.0", self.cli("info", "example.sample"))

    def test_27_reject_package_internal_control_files(self):
        src = self.package()
        (src / ".rawrxd-disabled").write_text("disabled")
        self.cli("install", src, ok=False)
        self.assertEqual(self.cli("list"), "")

    def test_28_recover_rejects_symlinked_staging(self):
        src = self.package()
        self.installed.mkdir()
        stage = self.installed / "example.sample.rawrxd-stage"
        try:
            stage.symlink_to(src, target_is_directory=True)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks unavailable")
        self.assertIn("recovered\t0", self.cli("recover"))
        self.assertTrue(stage.is_symlink())

    def test_29_recover_rejects_mismatched_backup(self):
        src = self.package(name="other")
        self.installed.mkdir()
        import shutil
        backup = self.installed / "example.sample.rawrxd-backup"
        shutil.copytree(src, backup)
        self.assertIn("recovered\t0", self.cli("recover"))
        self.assertTrue(backup.exists())

    def test_30_manifest_description_cannot_forge_cli_lines(self):
        src = self.package()
        (src / "package.json").write_text(json.dumps(dict(
            name="sample", publisher="example", version="1.0.0",
            description="line1\nINJECTED\tROW\r")), encoding="utf-8")
        self.cli("install", src)
        rows = self.cli("list").splitlines()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("\nINJECTED", rows[0])
        self.assertEqual(len(rows[0].split("\t")), 4)

    def test_31_default_data_root_persists_across_processes(self):
        src = self.package()
        home = self.home / "xdg"
        env = os.environ.copy()
        env.pop("LOCALAPPDATA", None)
        env["XDG_DATA_HOME"] = str(home)
        run = lambda *args: subprocess.run(
            [str(EXE), "--approve-mutations", *args],
            env=env, capture_output=True, text=True, timeout=15)
        created = run("install", str(src))
        self.assertEqual(created.returncode, 0, created.stderr)
        self.assertTrue((home / "RawrXD" / "extensions" / "example.sample" / "package.json").exists())
        listed = run("list")
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("example.sample", listed.stdout)

    def test_32_install_unpacked_nested_vsix_layout(self):
        src = self.home / "nested"
        nested = src / "extension"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text(json.dumps(dict(
            name="sample", publisher="example", version="2.3.4")), encoding="utf-8")
        (nested / "main.js").write_text("module.exports = {}", encoding="utf-8")
        self.cli("install", src)
        self.assertIn("example.sample\t2.3.4", self.cli("list"))

    def test_33_enable_idempotent(self):
        self.cli("install", self.package())
        self.cli("enable", "example.sample")
        self.cli("enable", "example.sample")
        self.assertIn("enabled", self.cli("list"))

    def test_34_malformed_state_marker_fails_closed(self):
        self.cli("install", self.package())
        marker = self.installed / "example.sample" / ".rawrxd-disabled"
        marker.write_text("NOT_DISABLED")
        self.cli("info", "example.sample", ok=False)
        self.cli("enable", "example.sample", ok=False)
        self.cli("disable", "example.sample", ok=False)
        self.assertEqual(self.cli("list"), "")

    def test_35_directory_state_marker_fails_closed(self):
        self.cli("install", self.package())
        marker = self.installed / "example.sample" / ".rawrxd-disabled"
        marker.mkdir()
        self.cli("info", "example.sample", ok=False)
        self.cli("disable", "example.sample", ok=False)
        self.assertEqual(self.cli("list"), "")

    def test_20_unknown_extensions_fail(self):
        self.cli("info", "nonexistent.extension", ok=False)
        self.cli("remove", "nonexistent.extension", ok=False)

if __name__ == "__main__":
    unittest.main()

"""Native REAP CLI fail-closed regression suite. No third-party dependencies.

Set RAWR_REAP_EXE to the built rawr-reap executable.
Run: python -m unittest discover -s tests -p 'test_reap_cli_contract.py' -v
"""
import json
import os
from pathlib import Path
import subprocess
import unittest

EXE = os.environ.get("RAWR_REAP_EXE")
if not EXE:
    for candidate in ("build_msvc/bin/rawr-reap.exe", "build_msvc/bin/rawr-reap",
                      "build/bin/rawr-reap.exe", "build/bin/rawr-reap"):
        if Path(candidate).is_file():
            EXE = candidate
            break

@unittest.skipUnless(EXE and Path(EXE).is_file(), "Set RAWR_REAP_EXE to the built CLI")
class ReapCliContract(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([str(Path(EXE).resolve()), *args],
                              capture_output=True, text=True, timeout=30)

    def assert_usage_error(self, *args):
        p = self.run_cli(*args)
        self.assertEqual(p.returncode, 2, (p.stdout, p.stderr))

    def test_01_no_args(self): self.assert_usage_error()
    def test_02_unknown_command(self): self.assert_usage_error("rewrite", "missing.gguf")
    def test_03_inspect_missing_argument(self): self.assert_usage_error("inspect")
    def test_04_plan_missing_argument(self): self.assert_usage_error("plan")
    def test_05_plan_missing_size_flag(self): self.assert_usage_error("plan", "missing.gguf")
    def test_06_plan_extra_argument(self): self.assert_usage_error("plan", "missing.gguf", "--size", "30GB", "extra")
    def test_07_capabilities_missing_argument(self): self.assert_usage_error("capabilities")

    def test_08_capabilities_unknown_extension(self):
        p = self.run_cli("capabilities", "missing.txt")
        self.assertEqual(p.returncode, 4)
        self.assertFalse(json.loads(p.stdout)["transformable"])

    def test_09_capabilities_unknown_format(self):
        p = self.run_cli("capabilities", "missing.txt")
        self.assertEqual(json.loads(p.stdout)["format"], "unknown")

    def test_10_capabilities_nonexistent_gguf(self):
        p = self.run_cli("capabilities", "__nonexistent_reap_test__.gguf")
        self.assertEqual(p.returncode, 4)
        self.assertFalse(json.loads(p.stdout)["inspectable"])

    def test_11_capabilities_nonexistent_not_transformable(self):
        p = self.run_cli("capabilities", "__nonexistent_reap_test__.gguf")
        self.assertFalse(json.loads(p.stdout)["transformable"])

    def test_12_capabilities_json_backslash(self):
        name = r"missing\model.txt"
        p = self.run_cli("capabilities", name)
        self.assertEqual(json.loads(p.stdout)["source"], name)

    def test_13_capabilities_json_quote(self):
        name = 'missing"model.txt'
        p = self.run_cli("capabilities", name)
        self.assertEqual(json.loads(p.stdout)["source"], name)

    def test_14_capabilities_json_newline(self):
        name = "missing\nmodel.txt"
        p = self.run_cli("capabilities", name)
        self.assertEqual(json.loads(p.stdout)["source"], name)

    def test_15_capabilities_json_tab(self):
        name = "missing\tmodel.txt"
        p = self.run_cli("capabilities", name)
        self.assertEqual(json.loads(p.stdout)["source"], name)

if __name__ == "__main__":
    unittest.main()

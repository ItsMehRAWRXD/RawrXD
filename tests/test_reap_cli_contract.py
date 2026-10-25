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
    def test_05_invalid_subcommand(self): self.assert_usage_error("calibrate", "missing.gguf")
    def test_06_invalid_reap_subcommand(self): self.assert_usage_error("prune", "missing.gguf")
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

    # Batch 2: 15 additional negative-contract and parser boundary cases.
    def test_16_capabilities_extra_argument(self):
        self.assert_usage_error("capabilities", "missing.gguf", "extra")

    def test_17_inspect_extra_argument(self):
        self.assert_usage_error("inspect", "missing.gguf", "extra")

    def test_18_plan_missing_size(self):
        self.assert_usage_error("plan", "missing.gguf", "--size")

    def test_19_plan_wrong_flag(self):
        self.assert_usage_error("plan", "missing.gguf", "--target", "30GB")

    def test_20_plan_extra_argument(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "30GB", "extra")

    def test_21_plan_zero(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "0GB")

    def test_22_plan_negative(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "-1GB")

    def test_23_plan_unknown_unit(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "30XB")

    def test_24_plan_missing_unit(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "30")

    def test_25_plan_multiple_decimal_points(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "1.2.3GB")

    def test_26_plan_tiny_fractional_byte(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "0.1B")

    def test_27_plan_fractional_byte(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "1.5B")

    def test_28_plan_uint64_overflow(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "18446744073709551616B")

    def test_29_plan_extreme_exponent(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "1e99GB")

    def test_30_plan_trailing_whitespace(self):
        self.assert_usage_error("plan", "missing.gguf", "--size", "30GB ")

    # Batch 3: 15 additional parser-admission checks. A valid size reaches
    # the missing-model load error (exit 1), rather than usage error (exit 2).
    def assert_size_admitted(self, size):
        p = self.run_cli("plan", "__nonexistent_reap_size_test__.gguf", "--size", size)
        self.assertEqual(p.returncode, 1, (size, p.stdout, p.stderr))
        self.assertIn("GGUF_LOAD_FAILED", p.stderr)

    def test_31_bytes_unit(self): self.assert_size_admitted("1B")
    def test_32_megabytes(self): self.assert_size_admitted("30MB")
    def test_33_mebibytes(self): self.assert_size_admitted("30MiB")
    def test_34_gigabytes(self): self.assert_size_admitted("30GB")
    def test_35_gibibytes(self): self.assert_size_admitted("30GiB")
    def test_36_terabytes(self): self.assert_size_admitted("1TB")
    def test_37_tebibytes(self): self.assert_size_admitted("1TiB")
    def test_38_lowercase_unit(self): self.assert_size_admitted("30gb")
    def test_39_mixedcase_unit(self): self.assert_size_admitted("30gB")
    def test_40_decimal_integral_bytes(self): self.assert_size_admitted("1.0B")
    def test_41_decimal_megabytes(self): self.assert_size_admitted("1.5MB")
    def test_42_decimal_gigabytes(self): self.assert_size_admitted("0.5GB")
    def test_43_leading_zero(self): self.assert_size_admitted("00030GB")
    def test_44_leading_decimal(self): self.assert_size_admitted(".5GB")
    def test_45_uint64_max(self): self.assert_size_admitted("18446744073709551615B")

if __name__ == "__main__":
    unittest.main()

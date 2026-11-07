#!/usr/bin/env python3
"""Executable CLI acceptance gate. Requires a freshly built RawrXD binary.

This test does NOT substitute a mock CLI for the production executable.
Set RAWRXD_CLI_EXE to the real built path. Missing binary = failure.
"""
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

EXE = os.environ.get("RAWRXD_CLI_EXE", "")

class CLIExecutableSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not EXE:
            raise AssertionError("RAWRXD_CLI_EXE is required; no binary was tested")
        cls.exe = pathlib.Path(EXE).resolve()
        if not cls.exe.is_file():
            raise AssertionError(f"Built CLI does not exist: {cls.exe}")

    def run_cli(self, *args):
        with tempfile.TemporaryDirectory(prefix="rawrxd-cli-smoke-") as root:
            try:
                return subprocess.run(
                    [str(self.exe), *args], cwd=root, text=True,
                    capture_output=True, timeout=20, check=False,
                    env={**os.environ, "RAWRXD_SMOKE_TEST": "1"}
                )
            except subprocess.TimeoutExpired as exc:
                self.fail(f"CLI timed out for {args}: {exc}")

    def test_help_terminates_without_model(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0,
            f"help failed: stdout={result.stdout[-1500:]} stderr={result.stderr[-1500:]}")
        self.assertTrue((result.stdout + result.stderr).strip(),
            "help returned no output")

    def test_unknown_command_is_not_success(self):
        result = self.run_cli("__rawrxd_invalid_command_for_smoke__")
        self.assertNotEqual(result.returncode, 0,
            "Unknown command returned success (possible silent fallback)")

if __name__ == "__main__":
    unittest.main(verbosity=2)

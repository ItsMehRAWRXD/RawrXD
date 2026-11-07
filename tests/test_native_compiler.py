"""No-model compiler/linker acceptance gates. Run: python -m unittest discover -s tests -p test_native_compiler.py"""
import contextlib
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rawrxd_native_compiler as builder


class NativeCompilerTests(unittest.TestCase):
    def invoke(self, *argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = builder.main(list(argv))
        return code, json.loads(output.getvalue())

    def test_missing_source_fails(self):
        with tempfile.TemporaryDirectory() as root:
            code, result = self.invoke("--compiler", "g++", "--source", "missing.cpp",
                                       "--output", "test", "--cwd", root)
            self.assertNotEqual(code, 0)
            self.assertFalse(result["ok"])

    def test_missing_compiler_fails(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.cpp").write_text("int main(){return 0;}")
            with patch.object(builder.shutil, "which", return_value=None):
                code, result = self.invoke("--compiler", "cl", "--source", "main.cpp",
                                           "--output", "test", "--cwd", root)
            self.assertNotEqual(code, 0)
            self.assertFalse(result["ok"])

    @unittest.skipUnless(shutil.which("g++"), "g++ unavailable")
    def test_compile_link_and_stale_binary(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.cpp").write_text("int main(){return 0;}")
            output = Path(root, "test")
            output.write_text("stale")
            code, result = self.invoke("--compiler", "g++", "--source", "main.cpp",
                                       "--output", "test", "--cwd", root)
            self.assertEqual(code, 0, result)
            self.assertTrue(result["ok"])
            self.assertNotEqual(output.read_bytes(), b"stale")

    @unittest.skipUnless(shutil.which("g++"), "g++ unavailable")
    def test_compiler_error_fails_without_output(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.cpp").write_text("this is not C++;")
            code, result = self.invoke("--compiler", "g++", "--source", "main.cpp",
                                       "--output", "test", "--cwd", root)
            self.assertNotEqual(code, 0)
            self.assertFalse(result["ok"])
            self.assertFalse(Path(root, "test").exists())


if __name__ == "__main__":
    unittest.main()

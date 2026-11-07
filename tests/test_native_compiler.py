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

    @unittest.skipUnless(shutil.which("g++"), "g++ unavailable")
    def test_two_translation_units_compile_link_execute(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.cpp").write_text('extern int answer(); int main(){return answer()==42?0:1;}')
            Path(root, "answer.cpp").write_text('int answer(){return 42;}')
            code, result = self.invoke("--compiler", "g++",
                                       "--source", "main.cpp", "--source", "answer.cpp",
                                       "--output", "test", "--cwd", root)
            self.assertEqual(code, 0, result)
            self.assertEqual([x["phase"] for x in result["steps"]], ["compile", "compile", "link"])
            self.assertEqual(subprocess.run([str(Path(root, "test"))], check=False).returncode, 0)

    def test_timeout_kills_child_and_reports_failure(self):
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as root:
            code = 'import time; print("started", flush=True); time.sleep(60)'
            result = builder.run_process([sys.executable, "-c", code], Path(root), 0.2)
            self.assertFalse(result["ok"])
            self.assertTrue(result["timed_out"])
            self.assertIn("started", result["stdout"])

    @unittest.skipUnless(shutil.which("gcc"), "gcc unavailable")
    def test_c_pipeline(self):
        import subprocess
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.c").write_text('extern int answer(void); int main(void){return answer()==42?0:1;}')
            Path(root, "answer.c").write_text('int answer(void){return 42;}')
            code, result = self.invoke("--compiler", "gcc",
                                       "--source", "main.c", "--source", "answer.c",
                                       "--output", "test", "--cwd", root)
            self.assertEqual(code, 0, result)
            self.assertEqual(subprocess.run([str(Path(root, "test"))], check=False).returncode, 0)

    def test_concurrent_large_stdout_stderr_capture(self):
        with tempfile.TemporaryDirectory() as root:
            code = ('import sys; '
                    'sys.stdout.write("O"*200000); sys.stdout.flush(); '
                    'sys.stderr.write("E"*200000); sys.stderr.flush()')
            result = builder.run_process([sys.executable, "-c", code], Path(root), 10)
            self.assertTrue(result["ok"], result)
            self.assertEqual(len(result["stdout"]), 200000)
            self.assertEqual(len(result["stderr"]), 200000)

    @unittest.skipUnless(shutil.which("g++"), "g++ unavailable")
    def test_link_failure_removes_output(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.cpp").write_text("extern int missing(); int main(){return missing();}")
            code, result = self.invoke("--compiler", "g++", "--source", "main.cpp",
                                       "--output", "test", "--cwd", root)
            self.assertNotEqual(code, 0)
            self.assertFalse(result["ok"])
            self.assertEqual([s["phase"] for s in result["steps"]], ["compile", "link"])
            self.assertFalse(Path(root, "test").exists())


if __name__ == "__main__":
    unittest.main()

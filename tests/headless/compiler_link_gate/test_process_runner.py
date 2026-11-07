"""Compile -> object -> link -> executable, timeout and pipe-pressure gates."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from process_runner import run


class RunnerTests(unittest.TestCase):
    def test_concurrent_full_pipes(self):
        with tempfile.TemporaryDirectory() as folder:
            code = "import sys; sys.stdout.buffer.write(b'A'*1048576); sys.stderr.buffer.write(b'B'*1048576)"
            result = run([sys.executable, "-c", code], cwd=folder, timeout=15)
            self.assertFalse(result.timed_out)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(result.stdout), 1048576)
            self.assertEqual(len(result.stderr), 1048576)

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run([sys.executable, "-c", "import time; time.sleep(60)"],
                         cwd=folder, timeout=0.3)
            self.assertTrue(result.timed_out)
            self.assertNotEqual(result.returncode, 0)

    def test_exit_code_and_output(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run([sys.executable, "-c",
                          "import sys; print('bad', file=sys.stderr); sys.exit(23)"],
                         cwd=folder)
            self.assertEqual(result.returncode, 23)
            self.assertIn(b"bad", result.stderr)

    def test_output_limit_still_drains(self):
        with tempfile.TemporaryDirectory() as folder:
            result = run([sys.executable, "-c",
                          "import sys; sys.stdout.buffer.write(b'x'*2000000)"],
                         cwd=folder, max_output_bytes=1024)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(len(result.stdout), 1024)


class NativePipelineTests(unittest.TestCase):
    def test_compile_object_link_execute(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "main.cpp"
            source.write_text('#include <iostream>\nint main(){std::cout << "native-ok"; return 0;}\n')
            if os.name == "nt":
                compiler = shutil.which("cl.exe")
                if not compiler:
                    self.skipTest("MSVC developer environment unavailable")
                obj = root / "main.obj"
                exe = root / "main.exe"
                steps = [[compiler, "/nologo", "/EHsc", "/c", str(source), "/Fo" + str(obj)],
                         [compiler, "/nologo", str(obj), "/Fe" + str(exe)]]
            else:
                compiler = shutil.which("c++")
                if not compiler:
                    self.skipTest("C++ compiler unavailable")
                obj = root / "main.o"
                exe = root / "main"
                steps = [[compiler, "-std=c++20", "-c", str(source), "-o", str(obj)],
                         [compiler, str(obj), "-o", str(exe)]]
            for command in steps:
                result = run(command, cwd=root, timeout=60)
                self.assertFalse(result.timed_out, result.stderr)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            result = run([str(exe)], cwd=root, timeout=10)
            self.assertFalse(result.timed_out)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertEqual(result.stdout, b"native-ok")


if __name__ == "__main__":
    unittest.main()

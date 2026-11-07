"""Real process and Windows MSVC compile->object->link->exe acceptance tests."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from native_build_runner import execute


class RunnerTests(unittest.TestCase):
    def test_concurrent_pipe_drain(self):
        code = ("import sys; "
                "sys.stdout.write('A'*200000);sys.stdout.flush();"
                "sys.stderr.write('B'*200000);sys.stderr.flush()")
        r = execute([sys.executable, "-c", code], 15)
        self.assertEqual(r["exit_code"], 0, r)
        self.assertEqual(len(r["stdout"]), 200000)
        self.assertEqual(len(r["stderr"]), 200000)

    def test_nonzero_and_timeout(self):
        r = execute([sys.executable, "-c", "import sys;sys.exit(17)"], 5)
        self.assertEqual(r["exit_code"], 17)
        self.assertFalse(r["timed_out"])
        r = execute([sys.executable, "-c", "import time;time.sleep(30)"], 0.5)
        self.assertTrue(r["timed_out"])
        self.assertIsNotNone(r["exit_code"])

    def test_launch_error(self):
        r = execute(["__rawrxd_missing_compiler_12345__"], 5)
        self.assertIsNotNone(r["launch_error"])

    @unittest.skipUnless(os.name == "nt", "Windows MSVC gate")
    def test_msvc_compile_link_execute(self):
        if not shutil.which("cl") or not shutil.which("link"):
            self.skipTest("MSVC developer environment not configured")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "hello.cpp"
            obj = root / "hello.obj"
            exe = root / "hello.exe"
            src.write_text('#include <cstdio>\nint main(){std::puts("RAWRXD_NATIVE_OK");return 0;}\n')
            compile_result = execute(["cl", "/nologo", "/EHsc", "/c", str(src),
                                      "/Fo" + str(obj)], 60, tmp)
            self.assertEqual(compile_result["exit_code"], 0, compile_result)
            self.assertTrue(obj.is_file())
            link_result = execute(["link", "/nologo", str(obj),
                                   "/OUT:" + str(exe)], 60, tmp)
            self.assertEqual(link_result["exit_code"], 0, link_result)
            self.assertTrue(exe.is_file())
            run_result = execute([str(exe)], 10, tmp)
            self.assertEqual(run_result["exit_code"], 0, run_result)
            self.assertEqual(run_result["stdout"].strip(), "RAWRXD_NATIVE_OK")


if __name__ == "__main__":
    unittest.main()

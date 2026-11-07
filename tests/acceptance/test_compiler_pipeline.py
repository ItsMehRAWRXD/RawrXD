"""Real compile/object/link/run gates. Run with python -m unittest discover -s tests/acceptance -p test_compiler_pipeline.py"""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("compiler_pipeline", ROOT / "tools/compiler_pipeline.py")
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)

class CompilerPipelineTests(unittest.TestCase):
    def test_concurrent_capture(self):
        code = "import sys;sys.stdout.write('a'*200000);sys.stdout.flush();sys.stderr.write('b'*200000);sys.stderr.flush()"
        r = pipeline.run_command([sys.executable, "-c", code], ROOT, 20)
        self.assertEqual(r["exit_code"], 0)
        self.assertEqual(len(r["stdout"]), 200000)
        self.assertEqual(len(r["stderr"]), 200000)

    def test_timeout(self):
        r = pipeline.run_command([sys.executable, "-c", "import time;time.sleep(30)"], ROOT, 0.5)
        self.assertTrue(r["timed_out"])

    def test_nonzero(self):
        r = pipeline.run_command([sys.executable, "-c", "import sys;sys.exit(19)"], ROOT, 10)
        self.assertEqual(r["exit_code"], 19)

    def test_real_cpp_compile_link_run(self):
        mode = "msvc" if os.name == "nt" else "gnu"
        compiler = shutil.which("cl" if os.name == "nt" else "g++")
        linker = shutil.which("link" if os.name == "nt" else "g++")
        self.assertIsNotNone(compiler, "Compiler missing")
        self.assertIsNotNone(linker, "Linker missing")
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "main.cpp"
            source.write_text('#include <iostream>\nint main(){std::cout<<"RAWRXD_OK";return 0;}\n')
            exe = Path(td) / ("test.exe" if os.name == "nt" else "test")
            r = pipeline.build([source], exe, compiler, linker, 60, mode)
            self.assertTrue(r["ok"], r)
            self.assertEqual([s["stage"] for s in r["steps"]], ["compile", "link"])
            executed = pipeline.run_command([str(exe)], td, 10)
            self.assertEqual(executed["exit_code"], 0, executed)
            self.assertEqual(executed["stdout"], "RAWRXD_OK")

if __name__ == "__main__":
    unittest.main()

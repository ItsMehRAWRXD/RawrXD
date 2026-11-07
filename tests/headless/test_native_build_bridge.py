"""Real compiler+linker smoke; skips only if no host C++ compiler exists."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_build_bridge", ROOT / "tools/native_build_bridge.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class NativeBuildBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "main.cpp"
        self.output = self.root / ("hello.exe" if __import__("os").name == "nt" else "hello")
        self.compiler = next((x for x in ("c++", "g++", "clang++", "cl") if shutil.which(x)), None)

    def test_missing_source_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            module.run_build(self.source, self.output, self.compiler or "c++")

    def test_reject_non_source_file(self):
        self.source = self.root / "bad.txt"
        self.source.write_text("text")
        with self.assertRaises(ValueError):
            module.run_build(self.source, self.output, self.compiler or "c++")

    def test_reject_source_overwrite(self):
        self.source.write_text("int main(){}")
        with self.assertRaises(ValueError):
            module.run_build(self.source, self.source, self.compiler or "c++")

    def test_reject_invalid_timeout(self):
        self.source.write_text("int main(){}")
        with self.assertRaises(ValueError):
            module.run_build(self.source, self.output, self.compiler or "c++", 0)

    def test_missing_compiler_fails_closed(self):
        self.source.write_text("int main(){}")
        with self.assertRaises(FileNotFoundError):
            module.run_build(self.source, self.output, "nonexistent-rawrxd-compiler-xyz")

    def test_compile_and_link_real_executable(self):
        if not self.compiler:
            self.skipTest("no C++ compiler installed")
        self.source.write_text("int main(){return 0;}\n")
        result = module.run_build(self.source, self.output, self.compiler)
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.output.is_file())

    def test_compile_failure_reports_error(self):
        if not self.compiler:
            self.skipTest("no C++ compiler installed")
        self.source.write_text("int main( {")
        result = module.run_build(self.source, self.output, self.compiler)
        self.assertFalse(result["ok"])
        self.assertNotEqual(result["exit_code"], 0)
        self.assertIsNone(result["artifact"])

    def test_compile_object_link_run_cpp(self):
        if not self.compiler:
            self.skipTest("no C++ compiler installed")
        self.source.write_text("int main(){return 0;}\\n")
        result = module.run_build(self.source, self.output, self.compiler, run=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual([x["stage"] for x in result["stages"]], ["compile", "link", "run"])
        self.assertTrue(self.output.with_suffix(".obj" if __import__("os").name == "nt" else ".o").is_file())

    def test_compile_object_link_run_c(self):
        compiler = next((x for x in (("cl",) if __import__("os").name == "nt" else ("cc", "gcc", "clang")) if shutil.which(x)), None)
        if not compiler:
            self.skipTest("no C compiler installed")
        source = self.root / "main.c"
        source.write_text("int main(void){return 0;}\\n")
        result = module.run_build(source, self.output, compiler, run=True)
        self.assertTrue(result["ok"], result)

    def test_subprocess_concurrent_stdout_stderr(self):
        script = "import sys;sys.stdout.write('o'*100000);sys.stdout.flush();sys.stderr.write('e'*100000);sys.stderr.flush()"
        result = module.execute([__import__("sys").executable, "-c", script], timeout=10)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["stdout"]), 32768)
        self.assertEqual(len(result["stderr"]), 32768)

    def test_subprocess_timeout(self):
        result = module.execute([__import__("sys").executable, "-c",
                                 "import time;time.sleep(10)"], timeout=0.2)
        self.assertFalse(result["ok"])
        self.assertTrue(result["timed_out"])

    def test_nonzero_program_exit_fails(self):
        if not self.compiler:
            self.skipTest("no C++ compiler installed")
        self.source.write_text("int main(){return 7;}\\n")
        result = module.run_build(self.source, self.output, self.compiler, run=True)
        self.assertFalse(result["ok"])
        self.assertEqual(result["stage"], "run")
        self.assertEqual(result["exit_code"], 7)

if __name__ == "__main__":
    unittest.main()

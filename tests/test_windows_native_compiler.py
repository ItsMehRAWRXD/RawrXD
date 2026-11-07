"""Windows MSVC end-to-end acceptance: C and C++ -> .obj -> link -> .exe -> execute."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import rawrxd_native_compiler as builder


@unittest.skipUnless(os.name == "nt" and shutil.which("cl") and shutil.which("link"),
                     "MSVC developer command prompt required")
class WindowsMSVCPipeline(unittest.TestCase):
    def run_build(self, root, *sources):
        capture = io.StringIO()
        with contextlib.redirect_stdout(capture):
            code = builder.main(["--compiler", "cl", "--cwd", str(root),
                                 "--output", "program.exe", "--timeout", "60",
                                 *sum((["--source", name] for name in sources), [])])
        return code, json.loads(capture.getvalue())

    def test_cpp_object_link_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.cpp").write_text("extern int answer(); int main(){return answer()==42?0:1;}")
            (root / "answer.cpp").write_text("int answer(){return 42;}")
            code, report = self.run_build(root, "main.cpp", "answer.cpp")
            self.assertEqual(code, 0, report)
            self.assertEqual([s["phase"] for s in report["steps"]], ["compile", "compile", "link"])
            self.assertEqual(subprocess.run([str(root / "program.exe")], check=False).returncode, 0)

    def test_c_object_link_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.c").write_text("extern int answer(void); int main(void){return answer()==42?0:1;}")
            (root / "answer.c").write_text("int answer(void){return 42;}")
            code, report = self.run_build(root, "main.c", "answer.c")
            self.assertEqual(code, 0, report)
            self.assertEqual(subprocess.run([str(root / "program.exe")], check=False).returncode, 0)

    def test_compile_failure_never_returns_stale_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.cpp").write_text("not valid C++")
            (root / "program.exe").write_bytes(b"stale")
            code, report = self.run_build(root, "main.cpp")
            self.assertNotEqual(code, 0)
            self.assertFalse(report["ok"])
            self.assertFalse((root / "program.exe").exists())


if __name__ == "__main__":
    unittest.main()

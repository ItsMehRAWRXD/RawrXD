"""Fail-closed integration tests for RawrXD's OWN PE/COFF linker.

These tests compile real AMD64 COFF fixtures with clang-cl or MSVC cl, link
them with rawrxd_link, and inspect resulting PE headers. No dummy PASS.
"""
import argparse
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--linker", required=True)
parser.add_argument("--checker", required=True)
args, others = parser.parse_known_args()

class LinkerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shutil.which("clang-cl") or shutil.which("cl")
        if not cls.compiler:
            raise AssertionError("AMD64 COFF compiler missing: required for native linker gate")
        for path in (args.linker, args.checker):
            if not Path(path).is_file():
                raise AssertionError("Native linker/checker missing: " + path)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.code = self.root / "main.c"
        self.code.write_text("int main(void) { return 3; }\n", encoding="ascii")
        self.obj = self.root / "main.obj"
        self.compile(self.code, self.obj)
        self.exe = self.root / "a.exe"

    def compile(self, source, output):
        cmd = [self.compiler, "/nologo", "/c", str(source), "/Fo" + str(output)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertTrue(output.is_file())

    def link(self, *argv, success):
        p = subprocess.run([args.linker, *map(str, argv)], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode == 0, success, p.stderr + p.stdout)
        return p

    def assert_pe(self, path):
        b = path.read_bytes()
        self.assertGreaterEqual(len(b), 512)
        self.assertEqual(b[:2], b"MZ")
        pe = struct.unpack_from("<I", b, 0x3c)[0]
        self.assertEqual(b[pe:pe+4], b"PE\x00\x00")
        self.assertEqual(struct.unpack_from("<H", b, pe+4)[0], 0x8664)
        self.assertGreater(struct.unpack_from("<H", b, pe+6)[0], 0)
        self.assertEqual(struct.unpack_from("<H", b, pe+24)[0], 0x20b)
        self.assertGreater(struct.unpack_from("<I", b, pe+40)[0], 0)

    def test_01_real_coff_to_pe(self):
        self.link("-o", self.exe, "-entry", "main", self.obj, success=True)
        self.assert_pe(self.exe)
        check = subprocess.run([args.checker, str(self.exe)], capture_output=True, text=True, timeout=15)
        self.assertEqual(check.returncode, 0, check.stderr + check.stdout)

    def test_02_missing_object_cannot_make_partial_exe(self):
        self.link("-o", self.exe, self.obj, self.root / "missing.obj", success=False)
        self.assertFalse(self.exe.exists())

    def test_03_missing_explicit_entry_is_fatal(self):
        self.link("-o", self.exe, "-entry", "NOT_DEFINED", self.obj, success=False)
        self.assertFalse(self.exe.exists())

    def test_04_no_entry_is_fatal(self):
        self.code.write_text("int data_symbol = 1;\n", encoding="ascii")
        self.compile(self.code, self.obj)
        self.link("-o", self.exe, self.obj, success=False)
        self.assertFalse(self.exe.exists())

    def test_05_invalid_subsystem_is_fatal(self):
        self.link("-o", self.exe, "-subsys", "65539", self.obj, success=False)
        self.assertFalse(self.exe.exists())

    def test_06_bad_image_base_is_fatal(self):
        self.link("-o", self.exe, "-base", "garbage", self.obj, success=False)
        self.assertFalse(self.exe.exists())
        self.link("-o", self.exe, "-base", "0x10100", self.obj, success=False)

    def test_07_unsupported_machine_is_rejected(self):
        b = bytearray(self.obj.read_bytes())
        b[0:2] = struct.pack("<H", 0x014c)
        bad = self.root / "wrong-machine.obj"
        bad.write_bytes(b)
        self.link("-o", self.exe, bad, success=False)
        self.assertFalse(self.exe.exists())

    def test_08_truncated_object_is_rejected(self):
        bad = self.root / "bad.obj"
        bad.write_bytes(b"\x64\x86\x01")
        self.link("-o", self.exe, bad, success=False)
        self.assertFalse(self.exe.exists())

    def test_09_map_in_dotted_directory(self):
        folder = self.root / "folder.with.dots"
        folder.mkdir()
        exe = folder / "hello.exe"
        self.link("-map", "-o", exe, "-entry", "main", self.obj, success=True)
        self.assert_pe(exe)
        self.assertTrue((folder / "hello.map").is_file())

    def test_10_invalid_reserves_are_fatal(self):
        self.link("-o", self.exe, "-stack", "0", self.obj, success=False)
        self.link("-o", self.exe, "-heap", "12oops", self.obj, success=False)
        self.assertFalse(self.exe.exists())

if __name__ == "__main__":
    unittest.main(argv=[__file__, *others], verbosity=2)

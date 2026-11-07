"""Black-box regression gates for local compiler, builder and linker."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "rawrxd_native_toolchain.py"
PE_AVAILABLE = bool((shutil.which("clang-cl") or shutil.which("cl")) and
                    (shutil.which("lld-link") or shutil.which("link")))
HOST_AVAILABLE = sys.platform.startswith("linux") and bool(shutil.which("clang") or shutil.which("gcc"))


class NativeToolchainAcceptance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "a.c").write_text("int answer(void){return 42;}\n")
        (self.root / "b.c").write_text("extern int answer(void); int main(void){return answer();}\n")

    def invoke(self, *args, ok=True, extra=None):
        cmd = [sys.executable, str(SCRIPT), *args, "--workspace", str(self.root)]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        self.assertTrue(p.stdout, (p.stdout, p.stderr))
        data = json.loads(p.stdout)
        self.assertEqual(p.returncode == 0, ok, (cmd, data, p.stderr))
        self.assertEqual(data["ok"], ok, data)
        return data

    @unittest.skipUnless(PE_AVAILABLE, "PE toolchain unavailable")
    def test_01_compile_link_pe(self):
        a = self.invoke("compile", "--format", "pe", "--source", "a.c", "--output", "a.obj", "--approve-mutations")
        b = self.invoke("compile", "--format", "pe", "--source", "b.c", "--output", "b.obj", "--approve-mutations")
        self.assertEqual(a["type"], "AMD64-COFF")
        self.assertEqual(b["type"], "AMD64-COFF")
        exe = self.invoke("link", "--format", "pe", "--object", "a.obj", "--object", "b.obj",
                          "--output", "linked.exe", "--approve-mutations")
        self.assertEqual(exe["type"], "AMD64-PE32+")
        self.assertEqual(self.invoke("verify", "--format", "pe", "--output", "linked.exe")["sha256"], exe["sha256"])

    @unittest.skipUnless(PE_AVAILABLE, "PE toolchain unavailable")
    def test_02_build_multi_file_pe(self):
        artifact = self.invoke("build", "--source", "a.c", "--source", "b.c", "--format", "pe",
                               "--output", "app.exe", "--approve-mutations")
        self.assertEqual(len(artifact["commands"]), 3)
        self.assertTrue((self.root / "app.exe").read_bytes().startswith(b"MZ"))

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_03_host_build_and_execute(self):
        result = self.invoke("build", "--source", "a.c", "--source", "b.c", "--format", "host",
                             "--output", "app", "--approve-mutations")
        self.assertEqual(result["type"], "x86_64-ELF")
        p = subprocess.run([str(self.root / "app")], timeout=10)
        self.assertEqual(p.returncode, 42)

    def test_04_approval_required(self):
        d = self.invoke("build", "--source", "a.c", "--format", "host", "--output", "nope", ok=False)
        self.assertEqual(d["code"], 3)
        self.assertFalse((self.root / "nope").exists())

    def test_05_path_escape_input(self):
        d = self.invoke("compile", "--source", "../outside.c", "--format", "host", "--output", "x.o",
                        "--approve-mutations", ok=False)
        self.assertIn("Path escapes workspace", d["error"])

    def test_06_path_escape_output(self):
        d = self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "../outside.o",
                        "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 3)

    def test_07_output_cannot_overwrite_input(self):
        self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "a.c",
                    "--approve-mutations", ok=False)
        self.assertIn("answer", (self.root / "a.c").read_text())

    def test_08_malicious_tool_is_refused(self):
        d = self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "out.o",
                        "--compiler", "/usr/bin/python3", "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 3)

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_09_no_stale_success_on_link_failure(self):
        old = self.root / "old"
        old.write_bytes(b"PREEXISTING")
        d = self.invoke("build", "--source", "b.c", "--format", "host", "--output", "old",
                        "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 4)
        self.assertEqual(old.read_bytes(), b"PREEXISTING")

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_10_no_stale_success_on_compile_failure(self):
        (self.root / "bad.c").write_text("int invalid( {\n")
        old = self.root / "a.o"
        old.write_bytes(b"OLD")
        d = self.invoke("compile", "--source", "bad.c", "--format", "host", "--output", "a.o",
                        "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 4)
        self.assertEqual(old.read_bytes(), b"OLD")

    def test_11_verify_rejects_invalid_elf(self):
        (self.root / "fake").write_bytes(b"not an executable")
        self.assertEqual(self.invoke("verify", "--format", "host", "--output", "fake", ok=False)["code"], 6)

    def test_12_verify_rejects_invalid_pe(self):
        (self.root / "fake.exe").write_bytes(b"MZ" + bytes(1024))
        self.assertEqual(self.invoke("verify", "--format", "pe", "--output", "fake.exe", ok=False)["code"], 6)

    def test_13_unsupported_source_extension(self):
        (self.root / "bad.txt").write_text("int main(){}")
        self.invoke("compile", "--source", "bad.txt", "--format", "host", "--output", "b.o",
                    "--approve-mutations", ok=False)

    def test_14_missing_input_rejected(self):
        self.invoke("build", "--format", "host", "--output", "missing", "--approve-mutations", ok=False)

    def test_15_symlink_escape_rejected(self):
        outside = self.root.parent / (self.root.name + "-outside.c")
        outside.write_text("int main(void){return 0;}")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        try:
            (self.root / "external.c").symlink_to(outside)
        except OSError:
            self.skipTest("Symlinks unsupported")
        self.invoke("compile", "--source", "external.c", "--format", "host", "--output", "x.o",
                    "--approve-mutations", ok=False)

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_16_argv_no_shell_injection(self):
        hacked = self.root / "HACKED"
        source = "foo;touch HACKED.c"
        (self.root / source).write_text("int main(void){return 0;}")
        d = self.invoke("compile", "--source", source, "--format", "host", "--output", "s.o",
                        "--approve-mutations")
        self.assertTrue(d["ok"])
        self.assertFalse(hacked.exists())

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_17_project_cmake_build(self):
        if not shutil.which("cmake"):
            self.skipTest("CMake unavailable")
        (self.root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\nproject(rawrxd_smoke C)\nadd_executable(smoke b.c a.c)\n")
        p = self.invoke("project", "--project-dir", ".", "--target", "smoke", "--artifact", "smoke",
                        "--generator", "Ninja", "--format", "host", "--output", "built",
                        "--approve-mutations")
        self.assertEqual(p["type"], "x86_64-ELF")
        self.assertEqual(subprocess.run([str(self.root / "built")]).returncode, 42)

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_18_project_rejects_stale_missing_artifact(self):
        (self.root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\nproject(rawrxd_smoke C)\nadd_executable(smoke b.c a.c)\n")
        (self.root / "existing").write_bytes(b"unchanged")
        d = self.invoke("project", "--project-dir", ".", "--target", "smoke", "--artifact", "not-found",
                        "--generator", "Ninja", "--format", "host", "--output", "existing",
                        "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 6)  # stale or missing linked artifacts never count as success
        self.assertEqual((self.root / "existing").read_bytes(), b"unchanged")

    @unittest.skipUnless(PE_AVAILABLE, "PE toolchain unavailable")
    def test_19_unresolved_pe_symbol_fails_closed(self):
        self.invoke("build", "--source", "b.c", "--format", "pe", "--output", "bad.exe",
                    "--approve-mutations", ok=False)
        self.assertFalse((self.root / "bad.exe").exists())

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_20_timeout_is_real_failure(self):
        fake = self.root / "tools" / "clang"
        fake.parent.mkdir()
        fake.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(3)\n")
        fake.chmod(0o755)
        d = self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "timeout.o",
                        "--compiler", str(fake), "--timeout", "1", "--approve-mutations", ok=False)
        self.assertIn("timeout", d["error"].lower())

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_21_fake_compiler_success_without_object_fails(self):
        fake = self.root / "tools" / "clang"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o755)
        self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "noobj.o",
                    "--compiler", str(fake), "--approve-mutations", ok=False)

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_23_invalid_cli_args_remain_machine_readable(self):
        d = self.invoke("build", "--format", "host", "--output", "out",
                        "--timeout", "0", "--approve-mutations", ok=False)
        self.assertEqual(d["code"], 2)
        self.assertEqual(d["operation"], "parse")

    @unittest.skipUnless(PE_AVAILABLE, "PE toolchain unavailable")
    def test_24_compile_and_link_cpp_pe(self):
        (self.root / "cpp_a.cpp").write_text('extern "C" int answer(){return 42;}\n')
        (self.root / "cpp_b.cpp").write_text('extern "C" int answer(); int main(){return answer();}\n')
        result = self.invoke("build", "--source", "cpp_a.cpp", "--source", "cpp_b.cpp",
                             "--format", "pe", "--output", "cpp.exe", "--approve-mutations")
        self.assertEqual(result["type"], "AMD64-PE32+")

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_25_compile_and_execute_cpp_host(self):
        (self.root / "cpp_a.cpp").write_text('extern "C" int answer(){return 42;}\n')
        (self.root / "cpp_b.cpp").write_text('extern "C" int answer(); int main(){return answer();}\n')
        result = self.invoke("build", "--source", "cpp_a.cpp", "--source", "cpp_b.cpp",
                             "--format", "host", "--output", "cpp", "--approve-mutations")
        self.assertEqual(result["type"], "x86_64-ELF")
        self.assertEqual(subprocess.run([str(self.root / "cpp")]).returncode, 42)

    @unittest.skipUnless(PE_AVAILABLE, "PE toolchain unavailable")
    def test_26_missing_pe_entry_never_links(self):
        self.invoke("build", "--source", "a.c", "--source", "b.c", "--format", "pe",
                    "--entry", "missingEntry", "--output", "wrongentry.exe",
                    "--approve-mutations", ok=False)
        self.assertFalse((self.root / "wrongentry.exe").exists())

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_27_packaged_cli_import_and_cold_start(self):
        # Production installation must ship its sibling process runner.
        package = self.root / "package" / "bin"
        package.mkdir(parents=True)
        shutil.copy2(SCRIPT, package / SCRIPT.name)
        shutil.copy2(SCRIPT.parent / "rawrxd_process_runner.py", package / "rawrxd_process_runner.py")
        command = [sys.executable, str(package / SCRIPT.name), "build", "--workspace", str(self.root),
                   "--source", "a.c", "--source", "b.c", "--output", "app",
                   "--format", "host", "--approve-mutations"]
        proc = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertTrue(json.loads(proc.stdout)["ok"])
        self.assertEqual(subprocess.run([str(self.root / "app")]).returncode, 42)

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_28_compiler_output_flood_is_fatal_and_old_output_preserved(self):
        fake = self.root / "tools" / "clang"
        fake.parent.mkdir()
        fake.write_text("#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(b'x'*(17*1024*1024))\nsys.stdout.flush()\n")
        fake.chmod(0o755)
        original = self.root / "out.o"
        original.write_bytes(b"OLD_OUTPUT")
        result = self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "out.o",
                             "--compiler", str(fake), "--approve-mutations", ok=False)
        self.assertEqual(result["code"], 4)
        self.assertTrue(result["commands"][0].get("output_limit"))
        self.assertLessEqual(len(result["commands"][0]["stdout"]), 32768)
        self.assertEqual(original.read_bytes(), b"OLD_OUTPUT")

    @unittest.skipUnless(HOST_AVAILABLE, "Host ELF compiler tests require Linux")
    def test_29_compiler_diagnostics_keep_stdout_and_stderr_separate(self):
        fake = self.root / "tools" / "clang"
        fake.parent.mkdir()
        fake.write_text("#!/usr/bin/env python3\nimport sys\nprint('LOG_STDOUT')\nprint('DIAGNOSTIC_STDERR',file=sys.stderr)\nsys.exit(7)\n")
        fake.chmod(0o755)
        result = self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "out.o",
                             "--compiler", str(fake), "--approve-mutations", ok=False)
        self.assertEqual(result["code"], 4)
        self.assertIn("LOG_STDOUT", result["commands"][0]["stdout"])
        self.assertIn("DIAGNOSTIC_STDERR", result["commands"][0]["stderr"])
        self.assertEqual(result["commands"][0]["returncode"], 7)
        self.assertFalse((self.root / "out.o").exists())

    def test_22_fake_compiler_bad_object_fails(self):
        fake = self.root / "tools" / "clang"
        fake.parent.mkdir()
        fake.write_text("#!/usr/bin/env python3\nimport sys\nopen(sys.argv[sys.argv.index('-o')+1], 'wb').write(b'FAKE')\n")
        fake.chmod(0o755)
        self.invoke("compile", "--source", "a.c", "--format", "host", "--output", "noobj.o",
                    "--compiler", str(fake), "--approve-mutations", ok=False)


if __name__ == "__main__":
    unittest.main()

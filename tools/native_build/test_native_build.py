#!/usr/bin/env python3
"""Real compiler/link/run smoke tests. No model or IDE GUI required."""
import pathlib
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[2]
driver = root / "tools/native_build/rawrxd_native_build.cpp"
compiler = sys.argv[1] if len(sys.argv) > 1 else ("cl" if sys.platform == "win32" else "g++")
with tempfile.TemporaryDirectory(prefix="rawrxd-build-") as tmp:
    base = pathlib.Path(tmp)
    exe = base / ("native_build.exe" if sys.platform == "win32" else "native_build")
    if sys.platform == "win32":
        command = [compiler, "/nologo", "/std:c++17", "/EHsc", str(driver), "/Fe:" + str(exe)]
        toolchain = "cl"
    else:
        command = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", str(driver), "-o", str(exe)]
        toolchain = compiler
    subprocess.run(command, check=True)
    source = base / "main.cpp"
    binary = base / ("hello.exe" if sys.platform == "win32" else "hello")
    source.write_text("int main(){return 0;}\n")
    def check(label, expected, args):
        result = subprocess.run([str(exe), *args], check=False)
        print(f"{label}: expected={expected} actual={result.returncode}", flush=True)
        if result.returncode != expected:
            raise AssertionError(label)
    object_file = base / ("main.obj" if sys.platform == "win32" else "main.o")
    check("source-to-object", 0, [toolchain, str(source), str(object_file), "object"])
    if not object_file.is_file():
        raise AssertionError("missing object file")
    check("object-to-executable", 0, [toolchain, str(object_file), str(binary), "link"])
    if not binary.is_file():
        raise AssertionError("missing executable from object link")
    check("linked executable", 0, [str(binary)])
    check("compile-link", 0, [toolchain, str(source), str(binary), "build"])
    if not binary.is_file():
        raise AssertionError("missing binary after build")
    check("compile-link-run", 0, [toolchain, str(source), str(binary), "run"])
    source.write_text("int main(){return 7;}\n")
    check("program exit propagated", 7, [toolchain, str(source), str(binary), "run"])
    source.write_text("int main( { broken\n")
    check("compiler failure propagated", 2 if sys.platform == "win32" else 1, [toolchain, str(source), str(binary), "build"])
    check("missing source rejected", 3, [toolchain, str(base/"missing.cpp"), str(binary), "build"])
    check("missing compiler rejected", 127, ["rawrxd_nonexistent_compiler", str(source), str(binary), "build"])
    check("invalid mode rejected", 2, [toolchain, str(source), str(binary), "invalid"])
    print("NATIVE_BUILD_GATE PASS: 10 checks")

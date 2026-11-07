"""Deterministic, model-free native C++ compile/link acceptance gate.

This tests the host toolchain, not the full RawrXD IDE. No shell invocation or
network dependency. Intended for Windows MSVC and Linux/macOS C++ compilers.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SOURCE = r"""
#include <cstdint>
extern "C" std::uint32_t rawrxd_build_fixture(std::uint32_t x) {
    return x * 7u + 3u;
}
"""
MAIN = r"""
#include <cstdint>
extern "C" std::uint32_t rawrxd_build_fixture(std::uint32_t);
int main() { return rawrxd_build_fixture(11u) == 80u ? 0 : 7; }
"""
BAD = "extern int missing_rawrxd_symbol(); int main() { return missing_rawrxd_symbol(); }\n"

def run(argv, cwd, expect_success=True):
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=120)
    if (proc.returncode == 0) != expect_success:
        raise RuntimeError(
            f"Unexpected exit={proc.returncode} for {argv!r}\n"
            f"stdout: {proc.stdout[-3000:]}\nstderr: {proc.stderr[-3000:]}"
        )
    return proc

def toolchain(explicit):
    if explicit:
        path = shutil.which(explicit)
        if not path:
            raise RuntimeError(f"Compiler not found: {explicit}")
        return path
    for name in (("cl", "clang-cl") if os.name == "nt" else ("c++", "clang++", "g++")):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("No C++ compiler on PATH")

def acceptance(compiler):
    msvc = Path(compiler).name.lower() in ("cl.exe", "cl", "clang-cl.exe", "clang-cl")
    with tempfile.TemporaryDirectory(prefix="rawrxd-build-gate-") as tmp:
        root = Path(tmp)
        (root / "lib.cpp").write_text(SOURCE, encoding="utf-8")
        (root / "main.cpp").write_text(MAIN, encoding="utf-8")
        (root / "bad.cpp").write_text(BAD, encoding="utf-8")
        obj = root / ("lib.obj" if msvc else "lib.o")
        exe = root / ("fixture.exe" if os.name == "nt" else "fixture")
        badexe = root / ("bad.exe" if os.name == "nt" else "bad")
        if msvc:
            run([compiler, "/nologo", "/std:c++17", "/c", "lib.cpp", "/Fo" + str(obj)], root)
            run([compiler, "/nologo", "/std:c++17", "main.cpp", str(obj), "/Fe:" + str(exe)], root)
            run([compiler, "/nologo", "/std:c++17", "bad.cpp", "/Fe:" + str(badexe)], root, False)
        else:
            run([compiler, "-std=c++17", "-c", "lib.cpp", "-o", str(obj)], root)
            run([compiler, "-std=c++17", "main.cpp", str(obj), "-o", str(exe)], root)
            run([compiler, "-std=c++17", "bad.cpp", "-o", str(badexe)], root, False)
        if not obj.is_file() or not exe.is_file() or badexe.exists():
            raise RuntimeError("Object/executable artifact contract violated")
        run([str(exe)], root)
    print("PASS: object compile, link, executable run, missing-symbol rejection")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", help="Compiler executable on PATH")
    args = parser.parse_args()
    try:
        acceptance(toolchain(args.compiler))
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())

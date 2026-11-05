#!/usr/bin/env python3
"""Fail-closed contract smoke test for the production JS extension bridge.

Runs against the actual C++ source, not a Python mock. This is deliberately
NOT a JavaScript-runtime certification: the bridge currently has no engine.
"""
from pathlib import Path
import ctypes
import shutil
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1] / "src/core/js_extension_host_production.cpp"


def main():
    if not SOURCE.is_file():
        raise SystemExit(f"BLOCKED: source missing: {SOURCE}")
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        raise SystemExit("BLOCKED: no C++ compiler available")
    with tempfile.TemporaryDirectory(prefix="rawrxd-jsext-") as tmp:
        libpath = Path(tmp) / ("bridge.dll" if sys.platform == "win32" else "bridge.so")
        command = [compiler, "-std=c++17", "-shared", "-fPIC", str(SOURCE), "-o", str(libpath)]
        if sys.platform == "win32":
            raise SystemExit("BLOCKED: Windows toolchain needs its own shared-library build lane")
        subprocess.run(command, check=True, capture_output=True, text=True)
        lib = ctypes.CDLL(str(libpath))
        for name in ("RawrXD_JSExt_Initialize", "RawrXD_JSExt_IsInitialized"):
            getattr(lib, name).restype = ctypes.c_bool
        for name in ("RawrXD_JSExt_ExecuteScript", "RawrXD_JSExt_LoadExtension"):
            fn = getattr(lib, name)
            fn.argtypes = [ctypes.c_char_p]
            fn.restype = ctypes.c_bool
        lib.RawrXD_JSExt_Shutdown.restype = None
        if lib.RawrXD_JSExt_IsInitialized():
            raise RuntimeError("FAIL: starts initialized without an engine")
        if lib.RawrXD_JSExt_Initialize():
            raise RuntimeError("FAIL: false-positive runtime initialization")
        if lib.RawrXD_JSExt_ExecuteScript(b"throw Error('must not execute')"):
            raise RuntimeError("FAIL: false-positive script execution")
        if lib.RawrXD_JSExt_LoadExtension(b"/nonexistent/extension.vsix"):
            raise RuntimeError("FAIL: false-positive extension load")
        lib.RawrXD_JSExt_Shutdown()
        if lib.RawrXD_JSExt_IsInitialized():
            raise RuntimeError("FAIL: shutdown did not clear state")
        print("PASS: native bridge fail-closed contract (5 assertions)")
        print("BLOCKED: real JavaScript execution / VSIX activation (no engine in this bridge)")


if __name__ == "__main__":
    main()

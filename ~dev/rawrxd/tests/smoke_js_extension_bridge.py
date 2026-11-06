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
    host_source = SOURCE.with_name("js_extension_host.cpp")
    if not host_source.is_file():
        raise SystemExit(f"BLOCKED: extension host source missing: {host_source}")
    host_text = host_source.read_text(encoding="utf-8")
    required_fragments = {
        "deactivation script exact length": "sizeof(deactivateScript) - 1",
        "stable command binding storage": "std::deque<JSCommandBinding> s_jsCommands",
        "queued result status": "msg.completionCallback(execution.success, callbackResult, msg.completionCtx)",
        "queued error detail fallback": "execution.detail.c_str()",
        "invalid queued request callback": 'msg.completionCallback(false, "Empty extension ID or script", msg.completionCtx)',
        "event JSON parse": "JS_ParseJSON(extCtx, eventData.c_str(),",
        "event direct callback": "JS_Call(extCtx, handler, handlers, 1, &payload)",
        "event payload cleanup": "JS_FreeValue(extCtx, payload);",
        "event name validation": "const bool validEventName = !eventName.empty()",
        "unsafe event rejection": "if (!validEventName)",
        "no QuickJS fail closed": 'return PatchResult::error("QuickJS unavailable: JavaScript extension host disabled")',
    }
    for label, fragment in required_fragments.items():
        if fragment not in host_text:
            raise RuntimeError(f"FAIL: {label} invariant missing")
    event_section = host_text.split("case JSMessage::Type::FireEvent:", 1)[-1].split("case JSMessage::Type::TimerFire:", 1)[0]
    if "JS_Eval(" in event_section:
        raise RuntimeError("FAIL: event dispatch must not eval generated JavaScript")
    print("PASS: queued callback and event-dispatch source invariants (not runtime PASS)")

    windows = sys.platform == "win32"
    compiler = (shutil.which("cl") if windows else None) or shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if not compiler:
        raise SystemExit("BLOCKED: no C++ compiler available")
    with tempfile.TemporaryDirectory(prefix="rawrxd-jsext-") as tmp:
        libpath = Path(tmp) / ("bridge.dll" if sys.platform == "win32" else "bridge.so")
        if windows and Path(compiler).stem.lower() == "cl":
            command = [compiler, "/nologo", "/std:c++17", "/EHsc", "/LD", str(SOURCE), "/link", "/OUT:" + str(libpath)]
        elif windows:
            command = [compiler, "-std=c++17", "-shared", str(SOURCE), "-o", str(libpath)]
        else:
            command = [compiler, "-std=c++17", "-shared", "-fPIC", str(SOURCE), "-o", str(libpath)]
        subprocess.run(command, check=True, capture_output=True, text=True, cwd=tmp)
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
        if lib.RawrXD_JSExt_ExecuteScript(None):
            raise RuntimeError("FAIL: null script accepted")
        if lib.RawrXD_JSExt_LoadExtension(None):
            raise RuntimeError("FAIL: null extension path accepted")
        if lib.RawrXD_JSExt_ExecuteScript(b""):
            raise RuntimeError("FAIL: empty script accepted")
        if lib.RawrXD_JSExt_LoadExtension(b""):
            raise RuntimeError("FAIL: empty extension path accepted")
        if lib.RawrXD_JSExt_Initialize():
            raise RuntimeError("FAIL: repeated initialization returned success without an engine")
        lib.RawrXD_JSExt_Shutdown()
        if lib.RawrXD_JSExt_IsInitialized():
            raise RuntimeError("FAIL: shutdown did not clear state")
        lib.RawrXD_JSExt_Shutdown()
        if lib.RawrXD_JSExt_IsInitialized():
            raise RuntimeError("FAIL: repeated shutdown changed initialization state")
        print("PASS: native bridge fail-closed contract (11 assertions)")
        print("BLOCKED: real JavaScript execution / VSIX activation (no engine in this bridge)")


if __name__ == "__main__":
    main()

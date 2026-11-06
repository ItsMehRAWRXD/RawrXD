#!/usr/bin/env python3
"""Source-level safety gates only. These do NOT certify extension execution."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
FULL = ROOT / "~dev/rawrxd/src/core/js_extension_host.cpp"
HEADLESS = ROOT / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"
BRIDGE = ROOT / "~dev/rawrxd/src/core/js_extension_host_production.cpp"

def function_body(source, signature):
    """Return the brace-balanced body of a C++ method or None if absent."""
    match = re.search(signature + r"\s*\{", source)
    if not match:
        return None
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    return None


def rejects(source, signature):
    body = function_body(source, signature)
    return body is not None and bool(re.search(r"return\s+(?:PatchResult::error\s*\(|false\s*;)", body))


def check(label, condition):
    print(("PASS_STATIC" if condition else "FAIL_STATIC") + ": " + label)
    return bool(condition)

def main():
    full = FULL.read_text(encoding="utf-8")
    headless = HEADLESS.read_text(encoding="utf-8")
    bridge = BRIDGE.read_text(encoding="utf-8")
    tests = [
        ("full host has QuickJS feature detection", "#define RAWRXD_HAS_QUICKJS 1" in full and "#define RAWRXD_HAS_QUICKJS 0" in full),
        ("full host exposes runtime implementation", "JSExtensionHost::" in full),
        ("full host rejects missing QuickJS during initialize", (lambda body: body is not None and bool(re.search(r"#if\s+!RAWRXD_HAS_QUICKJS[\s\S]*?return\s+PatchResult::error\(", body)))(function_body(full, r"PatchResult\s+JSExtensionHost::initialize\(\)"))),
        ("headless host explicitly refuses initialization", rejects(headless, r"PatchResult\s+JSExtensionHost::initialize\(\)")),
        ("headless host explicitly refuses VSIX", rejects(headless, r"PatchResult\s+JSExtensionHost::loadVSIX\([^)]*\)")),
        ("headless host explicitly refuses script execution", rejects(headless, r"PatchResult\s+JSExtensionHost::executeScript\([^)]*\)")),
        ("compatibility bridge refuses initialization", rejects(bridge, r"bool\s+Initialize\(\)")),
        ("compatibility bridge refuses script execution", rejects(bridge, r"bool\s+ExecuteScript\([^)]*\)")),
        ("compatibility bridge refuses extension load", rejects(bridge, r"bool\s+LoadExtension\([^)]*\)")),
    ]
    passed = sum(check(label, result) for label, result in tests)
    print(f"STATIC_SOURCE_GATES: {passed}/{len(tests)}; runtime certification NOT implied")
    return 0 if passed == len(tests) else 1

if __name__ == "__main__":
    sys.exit(main())

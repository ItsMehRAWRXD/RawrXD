#!/usr/bin/env python3
"""Source-level safety gates only. These do NOT certify extension execution."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
FULL = ROOT / "~dev/rawrxd/src/core/js_extension_host.cpp"
HEADLESS = ROOT / "~dev/rawrxd/src/core/js_extension_host_headless_impl.cpp"
BRIDGE = ROOT / "~dev/rawrxd/src/core/js_extension_host_production.cpp"

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
        ("headless host explicitly refuses initialization", bool(re.search(r"PatchResult JSExtensionHost::initialize\(\).*?return PatchResult::error", headless, re.S))),
        ("headless host explicitly refuses VSIX", bool(re.search(r"PatchResult JSExtensionHost::loadVSIX\(.*?return PatchResult::error", headless, re.S))),
        ("headless host explicitly refuses script execution", bool(re.search(r"PatchResult JSExtensionHost::executeScript\(.*?return PatchResult::error", headless, re.S))),
        ("compatibility bridge refuses initialization", bool(re.search(r"bool Initialize\(\).*?return false;", bridge, re.S))),
        ("compatibility bridge refuses script execution", bool(re.search(r"bool ExecuteScript\(.*?return false;", bridge, re.S))),
        ("compatibility bridge refuses extension load", bool(re.search(r"bool LoadExtension\(.*?return false;", bridge, re.S))),
    ]
    passed = sum(check(label, result) for label, result in tests)
    print(f"STATIC_SOURCE_GATES: {passed}/{len(tests)}; runtime certification NOT implied")
    return 0 if passed == len(tests) else 1

if __name__ == "__main__":
    sys.exit(main())

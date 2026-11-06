#!/usr/bin/env python3
"""Fail-closed static regression gate for Win32IDE extension sidebar.
This is NOT runtime certification. Run: python3 tests/extension_sidebar_gate.py
"""
from pathlib import Path
import re
import sys

SOURCE = Path("src/win32app/Win32IDE_Sidebar.cpp")
METHODS = ("searchExtensions", "installExtension", "uninstallExtension",
           "updateExtension", "showExtensionDetails", "loadInstalledExtensions",
           "enableExtension", "disableExtension")

def method_body(source, name):
    match = re.search(r"void\s+Win32IDE::" + re.escape(name) + r"\s*\([^)]*\)\s*\{", source)
    if not match:
        return None
    depth = 1
    for index in range(match.end(), len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.end():index]
    return None

def inspect(source):
    failures = []
    for name in METHODS:
        body = method_body(source, name)
        if body is None:
            failures.append(f"{name}: missing implementation")
        elif re.search(r"\bPlaceholder\b|\bTODO\b|\bFIXME\b", body, re.I):
            failures.append(f"{name}: placeholder marker")
        elif name == "loadInstalledExtensions" and re.search(r"m_extensions\s*=\s*\{", body):
            failures.append(f"{name}: hardcoded extension inventory")
        elif name in ("enableExtension", "disableExtension") and "ext.enabled =" in body and not re.search(r"persist|save|activate|deactivate|host", body, re.I):
            failures.append(f"{name}: in-memory toggle without visible runtime/persistence integration")
    return failures

def main():
    if not SOURCE.is_file():
        print(f"FAIL: source missing: {SOURCE}")
        return 2
    failures = inspect(SOURCE.read_text(encoding="utf-8", errors="replace"))
    for failure in failures:
        print("FAIL:", failure)
    if failures:
        print(f"FAIL: {len(failures)} static extension-sidebar blockers; runtime unverified")
        return 1
    print("PASS: static sidebar placeholder checks only; runtime unverified")
    return 0

if __name__ == "__main__":
    sys.exit(main())

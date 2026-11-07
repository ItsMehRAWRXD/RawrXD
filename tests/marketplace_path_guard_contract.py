#!/usr/bin/env python3
"""Source-contract regression gate; does not replace a Windows C++ build/runtime test."""
from pathlib import Path
import re
p = Path("~dev/rawrxd/src/core/vscode_marketplace.cpp")
s = p.read_text(encoding="utf-8")
checks = {
    "component validator exists": "bool isSafeMarketplaceComponent(" in s,
    "install validates ID and version before async dispatch": bool(re.search(r"installExtension\([^)]*\)\s*\{\s*if\s*\(!isSafeMarketplaceComponent\(extensionId\)", s)),
    "update validates ID before async dispatch": bool(re.search(r"updateExtension\([^)]*\)\s*\{\s*if\s*\(!isSafeMarketplaceComponent\(extensionId\)", s)),
    "uninstall validates ID before async dispatch": bool(re.search(r"uninstallExtension\([^)]*\)\s*\{\s*if\s*\(!isSafeMarketplaceComponent\(extensionId\)", s)),
    "install directory rejects invalid IDs": bool(re.search(r"getExtensionInstallDirectory\([^)]*\)\s*\{\s*if\s*\(!isSafeMarketplaceComponent\(extensionId\)\)\s*return\s*\{\}", s)),
    "uninstall rejects empty guarded path": 'if (extensionDir.empty()) throw std::runtime_error("Unsafe extension installation path");' in s,
}
for name, ok in checks.items():
    print(("PASS" if ok else "FAIL") + ": " + name)
raise SystemExit(0 if all(checks.values()) else 1)

#!/usr/bin/env python3
"""Function-scoped model-discovery instrumentation for Win32IDE.cpp.

Fail-closed: every anchor must match exactly once (under one of the file's
newline styles) or the script aborts without writing. This prevents another
misplaced insertion on this mixed/double-CR file.

Patches (all inside model-discovery code paths):
  A) populateModelSelector      sync CB_ADDSTRING loop  -> [MODEL_ADD] per row
  B) populateModelSelector      sync final selection    -> [MODEL_SETCURSEL]
  C) onModelDiscoveryComplete   async CB_ADDSTRING loop  -> [MODEL_ADD] per row
  D) onModelDiscoveryComplete   async final selection    -> [MODEL_SETCURSEL]
"""
import sys

PATH = r"F:\rawrxd\src\win32app\Win32IDE.cpp"
NEWLINES = ["\r\r\n", "\r\n", "\n"]  # try most-specific first

with open(PATH, "rb") as fh:
    text = fh.read().decode("utf-8")  # BOM preserved as leading \ufeff

# Each patch: (name, [find lines...], [replacement lines...])
patches = []

patches.append((
    "A sync-add",
    ["        if (item != CB_ERR && item != CB_ERRSPACE) {"],
    [
        "        std::fprintf(stderr,",
        '            "[MODEL_ADD] stage=sync index=%zu result=%lld label=\'%s\'\\n",',
        "            i, static_cast<long long>(item),",
        "            m_availableModels[i].breadcrumb.c_str());",
        "        std::fflush(stderr);",
        "        if (item != CB_ERR && item != CB_ERRSPACE) {",
    ],
))

patches.append((
    "B sync-select",
    [
        "    SendMessage(m_hwndModelSelector, CB_SETCURSEL,",
        "            static_cast<WPARAM>(initialRow), 0);",
    ],
    [
        "    const LRESULT syncSelResult = SendMessage(m_hwndModelSelector, CB_SETCURSEL,",
        "            static_cast<WPARAM>(initialRow), 0);",
        "    const LRESULT syncCurSel = SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);",
        "    const LRESULT syncCount = SendMessage(m_hwndModelSelector, CB_GETCOUNT, 0, 0);",
        "    std::fprintf(stderr,",
        '        "[MODEL_SETCURSEL] stage=sync row=%d setResult=%lld curSel=%lld count=%lld\\n",',
        "        initialRow, static_cast<long long>(syncSelResult),",
        "        static_cast<long long>(syncCurSel),",
        "        static_cast<long long>(syncCount));",
        "    std::fflush(stderr);",
    ],
))

patches.append((
    "C async-add",
    [
        "        const LRESULT row = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,",
        "            reinterpret_cast<LPARAM>(entry.breadcrumb.c_str()));",
    ],
    [
        "        const LRESULT row = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,",
        "            reinterpret_cast<LPARAM>(entry.breadcrumb.c_str()));",
        "        std::fprintf(stderr,",
        '            "[MODEL_ADD] stage=async index=%zu result=%lld label=\'%s\'\\n",',
        "            i, static_cast<long long>(row), entry.breadcrumb.c_str());",
        "        std::fflush(stderr);",
    ],
))

patches.append((
    "D async-select",
    [
        "    if (selectedRow >= 0) {",
        "        SendMessage(m_hwndModelSelector, CB_SETCURSEL,",
        "            static_cast<WPARAM>(selectedRow), 0);",
    ],
    [
        "    if (selectedRow >= 0) {",
        "        const LRESULT selResult = SendMessage(m_hwndModelSelector, CB_SETCURSEL,",
        "            static_cast<WPARAM>(selectedRow), 0);",
        "        const LRESULT curSelAfter = SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);",
        "        const LRESULT countAfter = SendMessage(m_hwndModelSelector, CB_GETCOUNT, 0, 0);",
        "        std::fprintf(stderr,",
        '            "[MODEL_SETCURSEL] stage=async row=%d setResult=%lld curSel=%lld count=%lld\\n",',
        "            selectedRow, static_cast<long long>(selResult),",
        "            static_cast<long long>(curSelAfter),",
        "            static_cast<long long>(countAfter));",
        "        std::fflush(stderr);",
    ],
))

# Resolve each patch to a concrete (find, repl) using a newline style that
# matches exactly once. Abort if any patch is not uniquely resolvable.
resolved = []
all_ok = True
for name, find_lines, repl_lines in patches:
    chosen = None
    for nl in NEWLINES:
        find = nl.join(find_lines)
        c = text.count(find)
        if c == 1:
            chosen = (nl, find, nl.join(repl_lines))
            break
        if c > 1:
            print(f"[anchor] {name}: ambiguous count={c} with nl={nl!r}")
            all_ok = False
            break
    if chosen is None:
        if all_ok:
            print(f"[anchor] {name}: NOT FOUND under any newline style")
        all_ok = False
        continue
    nl, find, repl = chosen
    print(f"[anchor] {name}: OK count=1 nl={nl!r}")
    resolved.append((name, find, repl))

if not all_ok or len(resolved) != len(patches):
    print("ABORT: one or more anchors did not resolve uniquely; no write performed.")
    sys.exit(2)

for name, find, repl in resolved:
    text = text.replace(find, repl, 1)
    print(f"[applied] {name}")

with open(PATH, "wb") as fh:
    fh.write(text.encode("utf-8"))
print("WROTE", PATH)
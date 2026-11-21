#!/usr/bin/env python3
"""Sprint 2: eliminate transient blank selection in populateModelSelector.

When no concrete route resolves synchronously, select the sentinel row 0
(itemData -1) instead of CB_SETCURSEL(-1). The sentinel is a visible
placeholder only; onModelSelectionChanged clears the active model for
itemData < 0, so no inference route is authorized.

Fail-closed: the single anchor must match exactly once (any newline style).
"""
import sys

PATH = r"F:\rawrxd\src\win32app\Win32IDE.cpp"
NEWLINES = ["\r\r\n", "\r\n", "\n"]

with open(PATH, "rb") as fh:
    text = fh.read().decode("utf-8")

find_lines = [
    "    const int initialRow = forceRouteRow >= 0 ? forceRouteRow : defaultRouteRow;",
]
repl_lines = [
    "    int initialRow = forceRouteRow >= 0 ? forceRouteRow : defaultRouteRow;",
    "    // Sprint 2: when no concrete route resolves synchronously, select the",
    "    // sentinel row (itemData -1) so the combo shows a visible placeholder",
    "    // instead of a blank selection. The sentinel never authorizes inference:",
    "    // onModelSelectionChanged() clears the active model for itemData < 0.",
    "    const LRESULT preSelectCount = SendMessage(m_hwndModelSelector, CB_GETCOUNT, 0, 0);",
    "    if (initialRow < 0 && preSelectCount > 0) {",
    "        initialRow = 0;",
    "    }",
]

chosen = None
for nl in NEWLINES:
    find = nl.join(find_lines)
    c = text.count(find)
    if c == 1:
        chosen = (nl, find, nl.join(repl_lines))
        break
    if c > 1:
        print(f"AMBIGUOUS count={c} nl={nl!r}")
        sys.exit(2)

if chosen is None:
    print("ABORT: anchor not found; no write")
    sys.exit(2)

nl, find, repl = chosen
text = text.replace(find, repl, 1)
with open(PATH, "wb") as fh:
    fh.write(text.encode("utf-8"))
print(f"applied Sprint 2 (nl={nl!r})")
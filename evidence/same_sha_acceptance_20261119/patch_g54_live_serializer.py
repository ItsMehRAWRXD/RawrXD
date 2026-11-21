#!/usr/bin/env python3
"""G54 in the ACTIVE serializer (Win32IDE_FileOps.cpp).

saveIdeSession(): persist root["window"] = {x,y,width,height,maximized} using
  GetWindowPlacement().rcNormalPosition (workspace coords for top-level windows).
loadIdeSession(): restore via SetWindowPlacement() (handles workspace coords,
  DPI and maximized state); backward compatible when "window" is absent.

Fail-closed: each anchor must match exactly once. Newline style auto-detected.
"""
import sys

PATH = r"F:\rawrxd\src\win32app\Win32IDE_FileOps.cpp"
with open(PATH, "rb") as fh:
    raw = fh.read()
if raw[:2] == b"\xff\xfe":
    bom = b"\xff\xfe"; text = raw.decode("utf-16-le")
elif raw[:3] == b"\xef\xbb\xbf":
    bom = raw[:3]; text = raw[3:].decode("utf-8")
else:
    bom = b""; text = raw.decode("utf-8")
NL = "\r\r\n" if "\r\r\n" in text else ("\r\n" if "\r\n" in text else "\n")

# --- Patch A: save geometry ---
a_find = NL.join([
    "    std::string serialized;",
    "    try {",
    "        serialized = root.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);",
])
a_repl = NL.join([
    "    // G54: persist the normal window rectangle + maximized state. rcNormalPosition",
    "    // uses workspace coordinates for top-level windows; restore via SetWindowPlacement.",
    "    if (m_hwndMain && IsWindow(m_hwndMain)) {",
    "        WINDOWPLACEMENT wp{};",
    "        wp.length = sizeof(WINDOWPLACEMENT);",
    "        if (GetWindowPlacement(m_hwndMain, &wp)) {",
    "            const RECT& rc = wp.rcNormalPosition;",
    "            root[\"window\"] = {",
    "                {\"x\", rc.left}, {\"y\", rc.top},",
    "                {\"width\", rc.right - rc.left}, {\"height\", rc.bottom - rc.top},",
    "                {\"maximized\", wp.showCmd == SW_SHOWMAXIMIZED}",
    "            };",
    "        }",
    "    }",
    "    std::string serialized;",
    "    try {",
    "        serialized = root.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);",
])

# --- Patch B: restore geometry ---
b_find = "        const auto modelFromJson = [](const nlohmann::json& value) {"
b_repl = NL.join([
    "        // G54: restore window geometry via SetWindowPlacement (workspace coords,",
    "        // DPI-aware, handles maximized state). Backward compatible: absent key = no-op.",
    "        if (root.contains(\"window\") && root[\"window\"].is_object()) {",
    "            const auto& w = root[\"window\"];",
    "            if (w.contains(\"width\") && w.contains(\"height\") &&",
    "                m_hwndMain && IsWindow(m_hwndMain)) {",
    "                WINDOWPLACEMENT wp{};",
    "                wp.length = sizeof(WINDOWPLACEMENT);",
    "                if (GetWindowPlacement(m_hwndMain, &wp)) {",
    "                    const int x = w.value(\"x\", wp.rcNormalPosition.left);",
    "                    const int y = w.value(\"y\", wp.rcNormalPosition.top);",
    "                    const int width = w.value(\"width\", wp.rcNormalPosition.right - wp.rcNormalPosition.left);",
    "                    const int height = w.value(\"height\", wp.rcNormalPosition.bottom - wp.rcNormalPosition.top);",
    "                    wp.rcNormalPosition = {x, y, x + width, y + height};",
    "                    wp.showCmd = w.value(\"maximized\", false) ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;",
    "                    SetWindowPlacement(m_hwndMain, &wp);",
    "                }",
    "            }",
    "        }",
    "        const auto modelFromJson = [](const nlohmann::json& value) {",
])

patches = [("A save", a_find, a_repl), ("B restore", b_find, b_repl)]
ok = True
for name, find, _ in patches:
    c = text.count(find)
    print(f"[anchor] {name}: count={c}")
    if c != 1:
        ok = False
if not ok:
    print("ABORT: anchor not unique; no write"); sys.exit(2)

for name, find, repl in patches:
    text = text.replace(find, repl, 1)
    print(f"[applied] {name}")

with open(PATH, "wb") as fh:
    fh.write(bom + text.encode("utf-8"))
print("WROTE", PATH)
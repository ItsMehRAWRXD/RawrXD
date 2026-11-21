#!/usr/bin/env python3
"""G54 fix: persist + restore window geometry in the ACTIVE session file.

Win32IDE_Session.cpp is UTF-16LE. saveSession() omits window geometry, and
restoreSession() (deferred, runs after the window is shown) never reapplies it.
This patch:
  A) saveSession(): write session["window"] = {x,y,width,height,maximized}.
  B) restoreSession(): read it, set m_window*, and re-apply to m_hwndMain via
     SetWindowPos (restoreSession runs after createWindow's initial positioning).

Fail-closed: each anchor must match exactly once (in the UTF-16LE text).
"""
import sys

PATH = r"F:\rawrxd\src\win32app\Win32IDE_Session.cpp"

with open(PATH, "rb") as fh:
    raw = fh.read()
if raw[:2] != b"\xff\xfe":
    print("ABORT: expected UTF-16LE BOM"); sys.exit(2)
text = raw.decode("utf-16-le")

NL = "\r\n"

# --- Patch A: save window geometry after saveSessionTheme(session); ---
a_find = "        saveSessionTheme(session);"
a_repl = NL.join([
    "        saveSessionTheme(session);",
    "",
    "        // G54: persist window geometry so position/size restore across restarts",
    "        if (m_hwndMain) {",
    "            RECT rc{};",
    "            if (GetWindowRect(m_hwndMain, &rc)) {",
    '                session["window"]["x"] = (int)rc.left;',
    '                session["window"]["y"] = (int)rc.top;',
    '                session["window"]["width"] = (int)(rc.right - rc.left);',
    '                session["window"]["height"] = (int)(rc.bottom - rc.top);',
        '                session["window"]["maximized"] =',
        "                    ((GetWindowLongPtr(m_hwndMain, GWL_STYLE) & WS_MAXIMIZE) != 0);",
    "            }",
    "        }",
])

# --- Patch B: restore window geometry after restoreSessionTheme(session); ---
b_find = "        restoreSessionTheme(session);"
b_repl = NL.join([
    "        restoreSessionTheme(session);",
    "",
    "        // G54: restore window geometry (restoreSession runs after createWindow,",
    "        // so also re-apply directly to the shown window).",
    '        if (session.contains("window")) {',
    '            const auto& w = session["window"];',
    '            if (w.contains("width") && w.contains("height")) {',
    '                m_windowX = w.value("x", m_windowX);',
        '                m_windowY = w.value("y", m_windowY);',
        '                m_windowWidth = w.value("width", m_windowWidth);',
        '                m_windowHeight = w.value("height", m_windowHeight);',
        '                m_windowMaximized = w.value("maximized", m_windowMaximized);',
        '                if (m_hwndMain && IsWindow(m_hwndMain)) {',
        "                    SetWindowPos(m_hwndMain, HWND_TOP, m_windowX, m_windowY,",
        "                        m_windowWidth, m_windowHeight, SWP_SHOWWINDOW);",
        "                    if (m_windowMaximized) ShowWindow(m_hwndMain, SW_MAXIMIZE);",
        "                }",
        '                LOG_INFO("Session: window geometry restored");',
    "            }",
    "        }",
])

patches = [("A save-window", a_find, a_repl), ("B restore-window", b_find, b_repl)]

ok = True
for name, find, _ in patches:
    c = text.count(find)
    print(f"[anchor] {name}: count={c}")
    if c != 1:
        ok = False
if not ok:
    print("ABORT: anchor not unique; no write")
    sys.exit(2)

for name, find, repl in patches:
    text = text.replace(find, repl, 1)
    print(f"[applied] {name}")

with open(PATH, "wb") as fh:
    fh.write(b"\xff\xfe" + text.encode("utf-16-le"))
print("WROTE", PATH)
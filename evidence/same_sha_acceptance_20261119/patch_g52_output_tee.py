#!/usr/bin/env python3
"""G52: tee build output into the Output pane via a thread-safe main-window post.

1) Win32IDE.h: add TerminalUiUpdate::Kind::OutputToPane.
2) Win32IDE_lifecycle.cpp: handle OutputToPane -> appendToOutput on the UI thread.
3) Win32IDE_Commands.cpp: chain terminal onOutput/onError to post OutputToPane.

Fail-closed: each anchor must match exactly once; newline style auto-detected.
"""
import sys

def patch(path, pairs, enc_hint=True):
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:2] == b"\xff\xfe":
        bom = b"\xff\xfe"; text = raw.decode("utf-16-le")
    elif raw[:3] == b"\xef\xbb\xbf":
        bom = raw[:3]; text = raw[3:].decode("utf-8")
    else:
        bom = b""; text = raw.decode("utf-8")
    nl = "\r\r\n" if "\r\r\n" in text else ("\r\n" if "\r\n" in text else "\n")
    resolved = []
    for old, new in pairs:
        c = text.count(old)
        print(f"  {path.split(chr(92))[-1]}: count={c} :: {old.splitlines()[0][:55]}")
        if c != 1:
            print("  ABORT: anchor not unique"); return False
        resolved.append((old, new))
    for old, new in resolved:
        text = text.replace(old, new, 1)
    with open(path, "wb") as fh:
        fh.write(bom + text.encode("utf-8" if bom == b"\xef\xbb\xbf" else ("utf-16-le" if bom else "utf-8")))
    return True

def j(*lines, nl="\n"):
    return nl.join(lines)

# 1) enum
p1 = r"F:\rawrxd\src\win32app\Win32IDE.h"
ok = patch(p1, [(
    "    enum class Kind { Output, Error, Finished };",
    "    enum class Kind { Output, Error, Finished, OutputToPane };",
)])
if not ok: sys.exit(2)

# 2) handler
p2 = r"F:\rawrxd\src\win32app\Win32IDE_lifecycle.cpp"
with open(p2, "rb") as fh: raw = fh.read()
enc = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-8"
bom = b"\xff\xfe" if raw[:2] == b"\xff\xfe" else b""
t = raw.decode(enc, "replace")
nl = "\r\r\n" if "\r\r\n" in t else ("\r\n" if "\r\n" in t else "\n")
old = j('                } else {',
        '                    ExecTrace("UI_FINISHED pane=%d exit=%d",', nl=nl)
new = j('                } else if (update->kind == TerminalUiUpdate::Kind::OutputToPane) {',
        '                    ide->appendToOutput(update->text, "Output", OutputSeverity::Info);',
        '                } else {',
        '                    ExecTrace("UI_FINISHED pane=%d exit=%d",', nl=nl)
c = t.count(old); print(f"  lifecycle handler: count={c}")
if c != 1: print("  ABORT lifecycle"); sys.exit(2)
t = t.replace(old, new, 1)
with open(p2, "wb") as fh: fh.write(bom + t.encode(enc))

# 3) chain callbacks
p3 = r"F:\rawrxd\src\win32app\Win32IDE_Commands.cpp"
with open(p3, "rb") as fh: raw = fh.read()
enc = "utf-16-le" if raw[:2] == b"\xff\xfe" else "utf-8"
bom = b"\xff\xfe" if raw[:2] == b"\xff\xfe" else b""
t = raw.decode(enc, "replace")
nl = "\r\r\n" if "\r\r\n" in t else ("\r\n" if "\r\n" in t else "\n")
old = '        buildTrace("BUILD_LAUNCH_STARTED pid=" + std::to_string(pane->manager->pid()));'
new = j('        buildTrace("BUILD_LAUNCH_STARTED pid=" + std::to_string(pane->manager->pid()));',
        '        // G52: tee build stdout/stderr into the Output pane (thread-safe post).',
        '        {',
        '            auto prevOut = pane->manager->onOutput;',
        '            pane->manager->onOutput = [this, prevOut](const std::string& s) {',
        '                if (prevOut) prevOut(s);',
        '                auto* u = new TerminalUiUpdate{TerminalUiUpdate::Kind::OutputToPane, -1, s, 0};',
        '                if (!m_hwndMain || !PostMessageA(m_hwndMain, kRawrxdTerminalUiUpdate, 0, (LPARAM)u)) delete u;',
        '            };',
        '            auto prevErr = pane->manager->onError;',
        '            pane->manager->onError = [this, prevErr](const std::string& s) {',
        '                if (prevErr) prevErr(s);',
        '                auto* u = new TerminalUiUpdate{TerminalUiUpdate::Kind::OutputToPane, -1, s, 0};',
        '                if (!m_hwndMain || !PostMessageA(m_hwndMain, kRawrxdTerminalUiUpdate, 0, (LPARAM)u)) delete u;',
        '            };',
        '        }', nl=nl)
c = t.count(old); print(f"  commands chain: count={c}")
if c != 1: print("  ABORT commands"); sys.exit(2)
t = t.replace(old, new, 1)
with open(p3, "wb") as fh: fh.write(bom + t.encode(enc))
print("patched G52 output tee")
#!/usr/bin/env python3
"""Sprint 6: wire the shared backend_preferences.h into CLI + IDE.

Replaces three duplicated/hardcoded backend-preference sites:
  A) rawr_cli.cpp : backendPrefPath/normalize/load/save -> shared; resolveRunBackend
     honours RAWRXD_BACKEND precedence with an invalid-value diagnostic.
  B) Win32IDE.cpp : the hardcoded cli_backend_pref.txt read -> shared loadPersisted.
  C) Win32IDE_AgentCommands.cpp : the hardcoded fopen write -> shared savePersisted.

Line-range replacement (lossless for CRLF/CR-CR-LF). Fail-closed: every anchor
must resolve to exactly one line range, else abort with no write.
"""
import sys

def load(p):
    with open(p, "rb") as fh:
        return fh.read().decode("utf-8")

def save(p, t):
    with open(p, "wb") as fh:
        fh.write(t.encode("utf-8"))

def find_line(lines, pred, start=0):
    for i in range(start, len(lines)):
        if pred(lines[i].rstrip("\r")):
            return i
    return -1

def newline_of(s):
    if s.endswith("\r\r"):
        return "\r\r\n"
    if s.endswith("\r"):
        return "\r\n"
    return "\n"

def replace_range(text, start, end, new_lines):
    lines = text.split("\n")
    nl = newline_of(lines[start])
    old = "\n".join(lines[start:end + 1])
    new = nl.join(new_lines)
    return text.replace(old, new, 1)

def brace_match_end(lines, open_line_idx):
    # find first '{' on/after open_line_idx, then match braces; ignore a leading
    # '}' that closes a previous block on the same line (e.g. "} else if (..) {").
    depth = 0
    started = False
    for i in range(open_line_idx, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}" and started:
                depth -= 1
                if depth == 0:
                    return i
    return -1

# ---------------- A) rawr_cli.cpp ----------------
P = r"F:\rawrxd\src\rawr_cli.cpp"
t = load(P)

# include after rawr_core.hpp
anchor_inc = '#include "rawr_core.hpp"'
if t.count(anchor_inc) != 1:
    print("ABORT rawr_cli include anchor"); sys.exit(2)
if "backend_preferences.h" not in t:
    t = t.replace(anchor_inc, anchor_inc + "\n#include \"backend_preferences.h\"", 1)

lines = t.split("\n")
# functions block: backendPrefPath .. before defaultDeep2ModelRel
start = find_line(lines, lambda s: s == "static std::string backendPrefPath() {")
end = find_line(lines, lambda s: s.startswith("static std::string defaultDeep2ModelRel() {"))
if start < 0 or end < 0 or end <= start:
    print(f"ABORT rawr_cli func block start={start} end={end}"); sys.exit(2)
end -= 1  # line before defaultDeep2ModelRel
new_funcs = [
    "static std::string backendPrefPath() { return rawrxd::prefs::prefPath().string(); }",
    "static std::string normalizeBackendPref(std::string s) { return rawrxd::prefs::normalize(std::move(s)); }",
    "static std::string loadBackendPref() { return rawrxd::prefs::loadPersisted(); }",
    "static bool saveBackendPref(const std::string& pref) { return rawrxd::prefs::savePersisted(pref); }",
]
t = replace_range(t, start, end, new_funcs)

# resolveRunBackend env precedence
lines = t.split("\n")
r = find_line(lines, lambda s: s == "    std::string sel = flagOrEmpty.empty() ? loadBackendPref() : normalizeBackendPref(flagOrEmpty);")
if r < 0:
    print("ABORT resolveRunBackend sel line"); sys.exit(2)
r2 = find_line(lines, lambda s: s == '    if (sel.empty()) sel = "auto";', r)
if r2 < 0:
    print("ABORT resolveRunBackend auto line"); sys.exit(2)
new_resolve = [
    "    std::string sel;",
    "    if (!flagOrEmpty.empty()) {",
    "        sel = normalizeBackendPref(flagOrEmpty);",
    "    } else if (const char* env = std::getenv(\"RAWRXD_BACKEND\")) {",
    "        sel = normalizeBackendPref(env);",
    "        if (sel.empty()) {",
    "            std::fprintf(stderr,",
    "                \"warning: RAWRXD_BACKEND='%s' is not one of deep2|strata|ollama|auto; \"",
    "                \"using persisted preference instead\\n\", env);",
    "            sel = loadBackendPref();",
    "        }",
    "    } else {",
    "        sel = loadBackendPref();",
    "    }",
    '    if (sel.empty()) sel = "auto";',
]
t = replace_range(t, r, r2, new_resolve)
save(P, t)
print("patched rawr_cli.cpp")

# ---------------- B) Win32IDE.cpp pref block ----------------
P = r"F:\rawrxd\src\win32app\Win32IDE.cpp"
t = load(P)
lines = t.split("\n")
s = find_line(lines, lambda x: x == "        } else if (std::FILE* pf = nullptr) {")
if s < 0:
    print("ABORT Win32IDE else-if anchor"); sys.exit(2)
e = brace_match_end(lines, s)
if e < 0:
    print("ABORT Win32IDE brace match"); sys.exit(2)
new_block = [
    "        } else {",
    "            std::string persisted = rawrxd::prefs::loadPersisted();",
    "            if (persisted == \"native\") persisted = \"deep2\";",
    "            if (persisted == \"deep2\" || persisted == \"strata\" || persisted == \"ollama\") pref = persisted;",
    "        }",
]
t = replace_range(t, s, e, new_block)
# add include after Win32IDE.h
if "backend_preferences.h" not in t:
    inc = '#include "Win32IDE.h"'
    t = t.replace(inc, inc + "\n#include \"backend_preferences.h\"", 1)
save(P, t)
print("patched Win32IDE.cpp")

# ---------------- C) Win32IDE_AgentCommands.cpp ----------------
P = r"F:\rawrxd\src\win32app\Win32IDE_AgentCommands.cpp"
t = load(P)
if "backend_preferences.h" not in t:
    inc = '#include "Win32IDE.h"'
    if t.count(inc) != 1:
        print("ABORT AgentCommands include anchor"); sys.exit(2)
    t = t.replace(inc, inc + "\n#include \"backend_preferences.h\"", 1)
lines = t.split("\n")
s = find_line(lines, lambda x: x == "    // Persist exactly like `rawr backend select` so both frontends agree.")
if s < 0:
    print("ABORT AgentCommands comment anchor"); sys.exit(2)
e = brace_match_end(lines, s + 1)  # the 'if (std::FILE* f = nullptr) {' line
if e < 0:
    print("ABORT AgentCommands brace match"); sys.exit(2)
new_save = [
    "    // Persist through the shared resolver so both frontends agree and the",
    "    // preference lands in the portable application-state directory.",
    "    rawrxd::prefs::savePersisted(pref);",
]
t = replace_range(t, s, e, new_save)
save(P, t)
print("patched Win32IDE_AgentCommands.cpp")
print("DONE")
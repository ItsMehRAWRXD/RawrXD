#!/usr/bin/env python3
"""Sprint 8: fix WorkspaceToolHost::RunProcess acceptance capture.

Defects fixed:
  P0  stderrText never populated (x_popen merged 2>&1) -> use NativeProcess
      for INDEPENDENT stdout/stderr capture.
  P1  launch status inferred from exit_code != -1 -> use NativeProcessResult
      (launched/timeout/error).
  P1  acceptance now sees both channels + real status.
Fail-closed: anchors must match exactly once.
"""
import sys

PATH = r"F:\rawrxd\src\agentic\WorkspaceToolHost.cpp"
with open(PATH, "rb") as fh:
    raw = fh.read()
if raw[:2] == b"\xff\xfe":
    bom = b"\xff\xfe"; text = raw.decode("utf-16-le")
elif raw[:3] == b"\xef\xbb\xbf":
    bom = raw[:3]; text = raw[3:].decode("utf-8")
else:
    bom = b""; text = raw.decode("utf-8")
nl = "\r\r\n" if "\r\r\n" in text else ("\r\n" if "\r\n" in text else "\n")

old1 = nl.join([
    "    exit_code = -1;",
    "    std::string full = cmd;",
    "    // Capture stdout+stderr on both shells.",
    "#ifdef _WIN32",
    '    full += " 2>&1";',
    "#else",
    '    full += " 2>&1";',
    "#endif",
    '',
    '    FILE* pipe = x_popen(full.c_str(), "r");',
    '    if (!pipe) return "failed to start process";',
    '',
    "    std::string out;",
    "    char buf[4096];",
    "    size_t cap = 8 * 1024 * 1024;   // bounded output",
    "    while (fgets(buf, sizeof(buf), pipe)) {",
    "        out += buf;",
    '        if (out.size() > cap) { out.append("\\n...[output truncated]\\n"); break; }',
    "    }",
    "    exit_code = x_pclose(pipe);",
])
new1 = nl.join([
    "    exit_code = -1;",
    "    // G: use the native runner for INDEPENDENT stdout/stderr capture and",
    "    // accurate launch/timeout status (x_popen merges stderr into stdout).",
    "    const int timeoutMs = (timeout_minutes > 0 ? timeout_minutes : 1) * 60 * 1000;",
    '    const NativeProcessResult pr =',
    '        NativeProcess::execute("cmd.exe", {"/c", cmd}, "", timeoutMs);',
    "    exit_code = pr.exitCode;",
    "    std::string out = pr.stdoutOutput + pr.stderrOutput;",
    "    if (out.size() > 8 * 1024 * 1024) {",
    '        out.resize(8 * 1024 * 1024);',
    '        out.append("\\n...[output truncated]\\n");',
    "    }",
])

old2 = nl.join([
    "        rawrxd::ProcessOutcome outcome;",
    "        outcome.launched   = (exit_code != -1);",
    "        outcome.exitCode   = exit_code;",
    "        outcome.stdoutText = out;",
])
new2 = nl.join([
    "        rawrxd::ProcessOutcome outcome;",
    "        outcome.launched   = (pr.exitCode != -1) && pr.error.empty();",
    "        outcome.exitCode   = pr.exitCode;",
    "        outcome.timedOut   = pr.timedOut;",
    "        outcome.error      = pr.error;",
    "        outcome.stdoutText = pr.stdoutOutput;",
    "        outcome.stderrText = pr.stderrOutput;",
])

patches = [("runprocess", old1, new1), ("outcome", old2, new2)]
ok = True
for name, old, _ in patches:
    c = text.count(old)
    print(f"[anchor] {name}: count={c}")
    if c != 1:
        ok = False
if not ok:
    print("ABORT: anchor not unique; no write"); sys.exit(2)
for name, old, new in patches:
    text = text.replace(old, new, 1)
    print(f"[applied] {name}")
with open(PATH, "wb") as fh:
    fh.write(bom + text.encode("utf-8"))
print("WROTE", PATH)
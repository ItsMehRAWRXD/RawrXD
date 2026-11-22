#!/usr/bin/env python3
"""Sprint 8.2/8.3: explicit acceptance state in rawrxd::tools::Result and
enforcement in runInTerminal.

- Result gains: enum Acceptance {NotEvaluated,Accepted,Rejected,NotApplicable},
  acceptance (default NotApplicable), firstFailure.
- runInTerminal evaluates acceptance and returns failure when Rejected.
Fail-closed: anchors must match exactly once.
"""
import sys

PATH = r"F:\rawrxd\src\agentic\tool_core.hpp"
with open(PATH, "rb") as fh:
    raw = fh.read()
if raw[:2] == b"\xff\xfe":
    bom = b"\xff\xfe"; text = raw.decode("utf-16-le")
elif raw[:3] == b"\xef\xbb\xbf":
    bom = raw[:3]; text = raw[3:].decode("utf-8")
else:
    bom = b""; text = raw.decode("utf-8")
nl = "\r\r\n" if "\r\r\n" in text else ("\r\n" if "\r\n" in text else "\n")

old1 = "struct Result { bool ok=false; std::string output; std::string error; };"
new1 = nl.join([
    "struct Result {",
    "    bool ok=false; std::string output; std::string error;",
    "    enum class Acceptance { NotEvaluated, Accepted, Rejected, NotApplicable };",
    "    Acceptance acceptance = Acceptance::NotApplicable;",
    "    std::string firstFailure;",
    "};",
])

old2 = nl.join([
    "    if (ec != 0) return {false, out, \"exit=\" + std::to_string(ec)};",
    "    return {true, out, \"\"};",
    "#else",
])
new2 = nl.join([
    "    // G: evaluate acceptance on the captured outcome (merged pipe).",
    "    {",
    "        rawrxd::AcceptanceCriteria crit;",
    "        crit.expectedExit = 0;",
    "        if (const char* m = std::getenv(\"RAWRXD_ACCEPTANCE_MARKER\"); m && *m)",
    "            crit.stderrMustContain = m;",
    "        rawrxd::ProcessOutcome po;",
    "        po.launched = true;",
    "        po.exitCode = static_cast<int>(ec);",
    "        po.stdoutText = out;",
    "        po.stderrText = out;",
    "        const auto verdict = rawrxd::EvaluateAcceptance(po, crit);",
    "        if (ec != 0) return {false, out, \"exit=\" + std::to_string(ec)};",
    "        if (!verdict.passed) return {false, out, verdict.firstFailure};",
    "        return {true, out, \"\"};",
    "    }",
    "#else",
])

patches = [("result", old1, new1), ("runinterminal", old2, new2)]
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
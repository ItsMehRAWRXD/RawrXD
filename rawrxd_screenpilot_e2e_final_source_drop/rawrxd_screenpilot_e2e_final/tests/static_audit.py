#!/usr/bin/env python3
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "web" / "ide_chatbot_screenpilot_final.html"
JS = ROOT / "web" / "screenpilot_authority.js"
CPP = ROOT / "src" / "rawrxd_screenpilot_agent_v2.cpp"
HDR = ROOT / "include" / "rawrxd_screenpilot_agent_v2.h"
POLICY = ROOT / "include" / "screenpilot_tool_policy_v2.h"

errors = []
warnings = []

def require(name, condition, detail=""):
    if condition:
        print(f"{name}=PASS")
    else:
        print(f"{name}=FAIL" + (f" :: {detail}" if detail else ""))
        errors.append(name)

html = HTML.read_text(encoding="utf-8", errors="replace")
js = JS.read_text(encoding="utf-8", errors="replace")
cpp = CPP.read_text(encoding="utf-8", errors="replace")
hdr = HDR.read_text(encoding="utf-8", errors="replace")
policy = POLICY.read_text(encoding="utf-8", errors="replace")

m = re.search(
    r'<meta http-equiv="Content-Security-Policy"\s+content="([^"]*)">',
    html,
    re.S | re.I,
)
csp = m.group(1) if m else ""

require("SCREENPILOT_CSP_PRESENT", bool(csp))
require("SCREENPILOT_CSP_NO_UNSAFE_EVAL", "'unsafe-eval'" not in csp)
require("SCREENPILOT_CSP_CONNECT_SELF_ONLY", "connect-src 'self'" in csp and "localhost:*" not in csp)
require("SCREENPILOT_NO_CDN", "cdnjs.cloudflare.com" not in html and "fonts.googleapis.com" not in html)
require("SCREENPILOT_NO_EXEC_EVAL", "new Function(" not in html and "eval(" not in js)
require("SCREENPILOT_TEST_BRIDGE_DISABLED",
        "PostMessage bridge initialized" not in html and "TestAPI" not in html)
require("SCREENPILOT_AUTHORITY_CLIENT_MOUNTED",
        '/screenpilot/screenpilot_authority.js' in html)

for mode in ("ask", "plan", "build", "agent"):
    require(f"SCREENPILOT_MODE_{mode.upper()}_CLIENT",
            f"'{mode}'" in js or f'"{mode}"' in js)

require("SCREENPILOT_AGENT_RUN_CLIENT", "/agent/run" in js)
require("SCREENPILOT_CANCEL_CLIENT", "/agent/cancel" in js)
require("SCREENPILOT_APPROVAL_CLIENT", "/agent/approve" in js)
require("SCREENPILOT_FAIL_CLOSED_CLIENT", "legacyFallback: false" in js)
require("SCREENPILOT_FILE_PROTOCOL_REJECTED",
        "must be served from the localhost LocalServer, not file://" in js)
require("SCREENPILOT_NO_11437_FINAL_CLIENT", "11437" not in js)
require("SCREENPILOT_SESSION_HEADER_CLIENT", "X-RawrXD-Session" in js)
require("SCREENPILOT_WORKSPACE_CLIENT", "screenpilotWorkspace" in js)
require("SCREENPILOT_MWM_BUILD_CANONICAL",
        "canonical BUILD requested" in js and "MWM.compileAction" in js)
require("SCREENPILOT_MWM_RE_CANONICAL",
        "canonical analysis requested" in js and "MWM.reAction" in js)
require("SCREENPILOT_MWM_FALLBACK_NOT_NATIVE",
        "browser-fallback" in js and "kernel.native = false" in js)

for forbidden in (
    "CreateProcessW(",
    "CreateProcessA(",
    "ShellExecuteW(",
    "ShellExecuteA(",
    "WinExec(",
    "system(",
    "_popen(",
    "popen(",
):
    require(
        "SCREENPILOT_ADAPTER_NO_DIRECT_EXEC_" + re.sub(r"\W+", "_", forbidden).strip("_").upper(),
        forbidden not in cpp,
        forbidden,
    )

require("SCREENPILOT_SERVER_DERIVED_PERMISSIONS",
        "mode_permissions(*mode)" in cpp and "permission_mask" in hdr)
require("SCREENPILOT_SERVER_MODE_ASK_PLAN_READONLY",
        'mode == "ask" || mode == "plan"' in cpp)
require("SCREENPILOT_SERVER_MODE_BUILD_WRITE",
        'mode == "build"' in cpp and "RAWRXD_SP_PERM_WORKSPACE_WRITE" in cpp)
require("SCREENPILOT_SERVER_MODE_AGENT_APPROVAL",
        "RAWRXD_SP_PERM_GIT_REMOTE" in cpp and
        "RAWRXD_SP_PERM_NETWORK" in cpp and
        "RAWRXD_SP_PERM_HOST_DESTRUCTIVE" in cpp and
        "approval_required_mask" in hdr)
require("SCREENPILOT_SERVER_APPROVE_ROUTE", "/agent/approve" in cpp)
require("SCREENPILOT_SERVER_CANCEL_ROUTE", "/agent/cancel" in cpp)
require("SCREENPILOT_SERVER_BODY_LIMIT", "max_body_bytes" in cpp)
require("SCREENPILOT_SERVER_PROMPT_LIMIT", "max_prompt_bytes" in cpp)
require("SCREENPILOT_SERVER_CONSTANT_TIME_TOKEN", "constant_time_equal" in cpp)
require("SCREENPILOT_SERVER_WORKSPACE_ADMISSION", "validate_workspace" in cpp)
require("SCREENPILOT_TOOL_POLICY_FAIL_CLOSED", "ToolClass::Unknown" in policy)
require("SCREENPILOT_TOOL_POLICY_PER_CALL_PATH", "PathUnderWorkspace" in policy)
require("SCREENPILOT_TOOL_POLICY_PROCESS_WARNING", "ProcessGeneral" in policy)

# JS syntax validation when Node is present.
try:
    r = subprocess.run(["node", "--check", str(JS)], capture_output=True, text=True)
    require("SCREENPILOT_AUTHORITY_JS_SYNTAX", r.returncode == 0, r.stderr.strip())
except FileNotFoundError:
    warnings.append("node not installed: external JS syntax check skipped")
    print("SCREENPILOT_AUTHORITY_JS_SYNTAX=SKIP")

scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.S | re.I)
node_ok = True
node_err = ""
try:
    with tempfile.TemporaryDirectory() as td:
        for i, body in enumerate(scripts):
            p = Path(td) / f"inline_{i}.js"
            p.write_text(body, encoding="utf-8")
            r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
            if r.returncode:
                node_ok = False
                node_err = f"inline script {i}: {r.stderr.strip()}"
                break
    require("SCREENPILOT_INLINE_JS_SYNTAX", node_ok, node_err)
except FileNotFoundError:
    warnings.append("node not installed: inline JS syntax check skipped")
    print("SCREENPILOT_INLINE_JS_SYNTAX=SKIP")

if warnings:
    for w in warnings:
        print("WARN:", w)

if errors:
    print(f"SCREENPILOT_STATIC_AUDIT=FAIL ({len(errors)} failures)")
    sys.exit(1)

print("SCREENPILOT_STATIC_AUDIT=PASS")

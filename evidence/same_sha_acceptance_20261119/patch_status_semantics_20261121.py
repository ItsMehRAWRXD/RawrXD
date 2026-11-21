#!/usr/bin/env python3
"""Sprint 7B: correct backend status semantics (CRLF-aware).

Strata is not routable on this path; status must not report the configured
Ollama service as active. Adds an explicit strata branch (active=none,
routable=false, route_error=STRATA_NOT_ROUTABLE) and surfaces routable /
route_error in text and JSON.
"""
import sys

PATH = r"F:\rawrxd\src\rawr_cli.cpp"
NL = "\r\n"
with open(PATH, "rb") as fh:
    text = fh.read().decode("utf-8")

def j(*lines):
    return NL.join(lines)

reps = []
reps.append((
    "    std::string activeLabel;",
    j("    std::string activeLabel;",
      "    bool routable = true;",
      "    std::string routeError;"),
))
reps.append((
    j('        endpoint = "in-process://Deep2Engine";',
      "        port = 0;",
      "    } else {",
      "        InferenceClient probe;",
      "        probe.setEndpoint(11434);"),
    j('        endpoint = "in-process://Deep2Engine";',
      "        port = 0;",
      '    } else if (route == "strata") {',
      "        // Strata is not routable on this path: report none as active and",
      "        // never probe/substitute Ollama for inference.",
      '        activeLabel = "none";',
      '        active = "none";',
      '        endpoint = "none";',
      "        port = 0;",
      "        live = false;",
      "        routable = false;",
      '        routeError = "STRATA_NOT_ROUTABLE";',
      "    } else {",
      "        InferenceClient probe;",
      "        probe.setEndpoint(11434);"),
))
reps.append((
    j('                 {"active", activeLabel},',
      '                 {"active_detail", active},'),
    j('                 {"active", activeLabel},',
      '                 {"active_detail", active},',
      '                 {"routable", routable},',
      '                 {"route_error", routeError},'),
))
reps.append((
    j('    out("  active      : " + active);',
      '    out("  endpoint    : " + endpoint);',
      '    out("  reachable   : " + std::string(live ? "yes" : "NO"));'),
    j('    out("  routable    : " + std::string(routable ? "yes" : "no"));',
      '    out("  active      : " + active);',
      '    out("  endpoint    : " + endpoint);',
      '    out("  reachable   : " + std::string(live ? "yes" : "NO"));',
      '    if (!routeError.empty()) out("  route_error : " + routeError);'),
))

ok = True
for old, _ in reps:
    c = text.count(old)
    print(f"[anchor] count={c}: {old.splitlines()[0][:60]}")
    if c != 1:
        ok = False
if not ok:
    print("ABORT: non-unique anchor; no write")
    sys.exit(2)

for old, new in reps:
    text = text.replace(old, new, 1)
with open(PATH, "wb") as fh:
    fh.write(text.encode("utf-8"))
print("patched rawr_cli.cpp status semantics")
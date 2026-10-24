#!/usr/bin/env python3
"""Read-only dependency and end-to-end gap audit. Python standard library only."""
from pathlib import Path
import json, re, sys
root=Path(__file__).resolve().parents[1]
cmake=(root/"CMakeLists.txt").read_text(encoding="utf-8",errors="replace")
checks={}
def add(name,passed,evidence):
    checks[name]={"pass":bool(passed),"evidence":evidence}
add("native_ide_target","add_executable(RawrXD-Win32IDE-Native" in cmake,
    "Native IDE executable declared in root CMake")
add("native_cli_target","add_executable(RawrXD-CLI-V2" in cmake,
    "Native CLI executable declared in root CMake")
add("qt_not_required_by_default",bool(re.search(r"option\s*\(\s*RAWRXD_REQUIRE_QT[^\n]*\bOFF\s*\)",cmake,re.I)),
    "Root CMake RAWRXD_REQUIRE_QT option defaults OFF")
add("cli_no_external_json_link","nlohmann_json::nlohmann_json" not in cmake,
    "Root CMake references nlohmann_json::nlohmann_json; this is a no-deps closure gate")
for name,path in {
 "lsp_native_framing":"src/win32app/native/NativeLspFraming.hpp",
 "lsp_legacy_qt":"src/lsp_client.cpp",
 "ghosttext_native":"src/win32app/Win32IDE_GhostText.cpp",
 "powershell_native":"src/win32app/Win32IDE_PowerShell.cpp",
 "deep2_engine":"src/deep2/Deep2Engine.cpp",
 "reap_projection":"src/deep2/reap/ReapProjectionBridge.hpp",
 "snapshot":"src/snapshot/SnapshotEngine.cpp",
}.items():
    p=root/path
    add("source_"+name,p.is_file(),path)
report={
 "schema":"rawrxd.no_deps_audit.v1",
 "checks":checks,
 "passed":sum(x["pass"] for x in checks.values()),
 "total":len(checks),
 "warning":"Static source audit only. PASS does not prove linked dependency closure, UI functionality or GPU parity."
}
dest=root/"evidence"/"rawrxd_no_deps_audit.json"
dest.parent.mkdir(parents=True,exist_ok=True)
dest.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({"passed":report["passed"],"total":report["total"],
                  "failed":[k for k,v in checks.items() if not v["pass"]]}))

if "--strict" in sys.argv and report["passed"] != report["total"]:
    sys.exit(1)

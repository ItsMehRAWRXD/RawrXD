#!/usr/bin/env python3
"""Evidence-first source inventory. Python stdlib only; no code execution."""
import json, pathlib, re, sys
root=pathlib.Path(__file__).resolve().parents[1]
targets={
 "native_ghosttext":"src/win32app/Win32IDE_GhostText.cpp",
 "qt_ghosttext":"src/qtapp/widgets/OverlayWidget.cpp",
 "qt_lsp":"src/lsp_client.cpp",
 "native_lsp_framing":"src/win32app/native/NativeLspFraming.hpp",
 "native_powershell":"src/win32app/Win32IDE_PowerShell.cpp",
 "native_powershell_panel":"src/win32app/Win32IDE_PowerShellPanel.cpp",
 "snapshot":"src/snapshot/SnapshotEngine.cpp",
 "deep2_engine":"src/deep2/Deep2Engine.cpp",
 "rom_projection":"src/deep2/reap/ReapProjectionBridge.hpp",
 "route_mask":"src/deep2/reap/ReapRouteMask.hpp",
 "ci":".github/workflows/reap-rom-parity-ci.yml",
}
report={"schema":"rawrxd.e2e.source-audit.v1","checks":{},"summary":{}}
for name,path in targets.items():
    p=root/path
    if not p.is_file():
        report["checks"][name]={"path":path,"status":"missing"}
        continue
    data=p.read_text(encoding="utf-8",errors="replace")
    report["checks"][name]={
      "path":path,"status":"source_present_unverified",
      "qt_includes":len(re.findall(r'^\s*#\s*include\s*[<"]Q[A-Za-z]',data,re.M)),
      "bytes":len(data.encode("utf-8"))
    }
report["summary"]={
 "source_present":sum(x["status"]=="source_present_unverified" for x in report["checks"].values()),
 "missing":sum(x["status"]=="missing" for x in report["checks"].values()),
 "certified":0,
 "note":"Source presence is not functional parity, build success, or runtime certification."
}
out=root/"evidence"/"rawrxd_e2e_source_audit.json"
out.parent.mkdir(parents=True,exist_ok=True)
out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps(report["summary"],sort_keys=True))
if "--strict" in sys.argv and report["summary"]["missing"]: sys.exit(1)

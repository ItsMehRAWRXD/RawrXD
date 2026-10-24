#!/usr/bin/env python3
"""Deterministic read-only per-file inventory for RawrXD production closure.

Enumerates tracked source via git (not build artifacts), records SHA-256 and
line counts, and classifies source-level Qt and third-party references.
Static indicators are NOT proof of dependency or runtime correctness.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".inl",
       ".asm", ".s", ".rc", ".cmake", ".py", ".ps1", ".js", ".ts"}
QT_INCLUDE = re.compile(rb'^\s*#\s*include\s*[<"](?:Qt[A-Za-z0-9_/]*|Q[A-Z][A-Za-z0-9_]*)', re.M)
QT_CMAKE = re.compile(rb'\b(?:find_package\s*\(\s*Qt[56]|Qt[56]::|QT_WIDGETS_LIBRARIES)\b', re.I)
EXTERNAL = {
    "nlohmann_json": re.compile(rb'\b(?:nlohmann_json|nlohmann/json\.hpp)\b'),
    "qt": QT_INCLUDE,
    "curl": re.compile(rb'#\s*include\s*[<"]curl/'),
    "boost": re.compile(rb'#\s*include\s*[<"]boost/'),
}
def tracked():
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                            stdout=subprocess.PIPE)
    return sorted(p.decode("utf-8", "surrogateescape") for p in
                  result.stdout.split(b"\0") if p)

def inspect(rel):
    path = ROOT / rel
    if not path.is_file():
        return {"path": rel, "state": "tracked_missing"}
    data = path.read_bytes()
    is_source = path.suffix.lower() in EXT or path.name == "CMakeLists.txt"
    return {
        "path": rel,
        "state": "present",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "lines": data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0),
        "source": is_source,
        "qt_include_count": len(QT_INCLUDE.findall(data)) if is_source else 0,
        "qt_cmake_count": len(QT_CMAKE.findall(data)) if is_source else 0,
        "external_indicators": sorted(k for k, pat in EXTERNAL.items()
                                      if is_source and pat.search(data)),
    }

def main():
    records = [inspect(p) for p in tracked()]
    src = [r for r in records if r.get("source")]
    flagged = [r["path"] for r in src if r["qt_include_count"] or
               r["qt_cmake_count"] or r["external_indicators"]]
    report = {
        "schema": "rawrxd.per-file-source-audit.v1",
        "tracked_files": len(records),
        "source_files": len(src),
        "missing_tracked_files": sum(r["state"] != "present" for r in records),
        "files_with_dependency_indicators": len(flagged),
        "flagged_paths": flagged,
        "files": records,
        "limitations": "Static per-file audit only; no compiler, runtime, "
                       "GPU, vulnerability, or product-parity certification."
    }
    dest = ROOT / "evidence" / "rawrxd_per_file_source_audit.json"
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n",
                    encoding="utf-8")
    print(json.dumps({k: report[k] for k in
          ("tracked_files", "source_files", "missing_tracked_files",
           "files_with_dependency_indicators")}, sort_keys=True))
    return 1 if "--strict-missing" in sys.argv and report["missing_tracked_files"] else 0

if __name__ == "__main__":
    sys.exit(main())

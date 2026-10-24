#!/usr/bin/env python3
"""Read-only CMake target source admission report; standard library only.

Handles literal source paths inside add_executable/add_library calls, ignores
generator expressions and variable-expanded sources (reported as unresolved).
Does not attempt to evaluate CMake conditionals; flagged paths may be inside
disabled optional targets. Run CMake configure for authoritative results.
"""
import json
import pathlib
import re
import sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
CMAKE=ROOT/"CMakeLists.txt"
TEXT=CMAKE.read_text(encoding="utf-8",errors="replace")
TOKENS=re.compile(r'"[^"]*"|\$<[^>]*>|\$\{[^}]*\}|[^\s]+')
START=re.compile(r'\b(add_executable|add_library)\s*\(',re.I)
SOURCE_SUFFIX={".c",".cc",".cpp",".cxx",".h",".hpp",".hh",".inl",".rc",".asm",".s"}
entries=[]
for match in START.finditer(TEXT):
    depth=1
    pos=match.end()
    quote=False
    while pos<len(TEXT) and depth:
        ch=TEXT[pos]
        if ch=='"' and (pos==0 or TEXT[pos-1]!="\\"):
            quote=not quote
        if not quote:
            if ch=="(": depth+=1
            elif ch==")": depth-=1
        pos+=1
    if depth: continue
    args=TEXT[match.end():pos-1]
    args=re.sub(r'#[^\n]*','',args)
    tokens=[t.strip('"') for t in TOKENS.findall(args)]
    if not tokens: continue
    name=tokens[0]
    missing=[]
    unresolved=[]
    existing=0
    for token in tokens[1:]:
        if token.startswith("$") or "$" in token or ";" in token:
            unresolved.append(token)
            continue
        if pathlib.PurePosixPath(token.replace("\\","/")).suffix.lower() not in SOURCE_SUFFIX:
            continue
        candidate=ROOT/token
        if candidate.is_file(): existing+=1
        else: missing.append(token)
    entries.append({"target":name,"kind":match.group(1).lower(),
                    "line":TEXT.count("\n",0,match.start())+1,
                    "existing_literal_sources":existing,
                    "missing_literal_sources":missing,
                    "unresolved_expressions":unresolved})
report={"schema":"rawrxd.cmake-source-admission.v1",
        "cmake":"CMakeLists.txt","target_declarations":len(entries),
        "targets_with_missing_literal_sources":sum(bool(x["missing_literal_sources"]) for x in entries),
        "missing_literal_source_references":sum(len(x["missing_literal_sources"]) for x in entries),
        "targets":entries,
        "limitations":"Static approximation; CMake conditions and variables not evaluated. "
                      "Missing files in disabled targets do not necessarily break configure."}
out=ROOT/"evidence"/"rawrxd_cmake_source_admission.json"
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
print(json.dumps({k:report[k] for k in ("target_declarations","targets_with_missing_literal_sources","missing_literal_source_references")}))
if "--strict" in sys.argv and report["missing_literal_source_references"]:
    sys.exit(1)

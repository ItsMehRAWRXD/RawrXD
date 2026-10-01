"""Measure the CMake surface of the remaining stubs before touching anything.

Two questions, both answered empirically rather than by guessing list owners:
  1. how many active CMake lines name each remaining stub?
  2. would commenting them change any generated target, or would leaving them
     (and quarantining the file) merely add a missing-source warning?

A line counts as "naming" a stub only when the stub's file name appears in it.
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
CM = ROOT / "CMakeLists.txt"

rows = list(csv.DictReader((EV / "stub_manifest.csv").open(encoding="utf-8")))
done = {r["PATH"] for r in rows if r["SHIPPING_TARGET"]}
todo = [r for r in rows if r["PATH"] not in done]
print(f"ALREADY_DONE={len(done)}  REMAINING={len(todo)}")

# already-quarantined (moved out of the tree)
gone = {p.relative_to(ROOT).as_posix()
        for p in (EV / "stub-quarantine" / "payload").rglob("*")
        if p.is_file()} if (EV / "stub-quarantine" / "payload").exists() else set()
print(f"ALREADY_QUARANTINED={len(gone)}")

lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
leaves = {r["PATH"].rsplit("/", 1)[-1]: r["PATH"] for r in todo}

active_hits, commented_hits = [], []
for i, line in enumerate(lines, start=1):
    s = line.strip()
    for leaf, full in leaves.items():
        if leaf in line:
            (commented_hits if s.startswith("#") else active_hits).append(
                (i, leaf, full))
            break

print(f"ACTIVE_CMAKE_LINES_NAMING_REMAINING_STUBS={len(active_hits)}")
print(f"COMMENTED_CMAKE_LINES_NAMING_REMAINING_STUBS={len(commented_hits)}")
distinct = Counter(h[2] for h in active_hits)
print(f"STUBS_WITH_AT_LEAST_ONE_ACTIVE_CMAKE_LINE={len(distinct)}")
print(f"STUBS_WITH_NO_CMAKE_MENTION={len(todo) - len(distinct)}")

by_class = Counter(r["CLASSIFICATION"] for r in todo)
print("REMAINING_BY_CLASS=" + str(dict(by_class)))

# Which of the active hits are NOT in a currently generated target?
import xml.etree.ElementTree as ET
built = set()
for proj in (ROOT / "build_w1").rglob("*.vcxproj"):
    try:
        tree = ET.parse(proj)
    except ET.ParseError:
        continue
    for n in tree.getroot().iter():
        if n.tag.endswith("}ClCompile") and n.get("Include"):
            built.add(Path(n.get("Include").replace("\\", "/")).as_posix().lower())

not_built = [(i, leaf, full) for (i, leaf, full) in active_hits
             if (ROOT / full).as_posix().replace("\\", "/").lower() not in built]
print(f"ACTIVE_CMAKE_LINES_FOR_UNBUILT_STUBS={len(not_built)}")
for i, leaf, full in not_built[:12]:
    print(f"    {i:>6}  {full}")

with (EV / "BATCH_4" ).mkdir(parents=True, exist_ok=True) if False else (EV / "BATCH_4").mkdir(parents=True, exist_ok=True) as _:
    pass
with (EV / "BATCH_4" / "remaining_active_lines.txt").open("w", encoding="utf-8") as fh:
    for i, leaf, full in active_hits:
        fh.write(f"{i}\t{full}\t{full.lower() in built}\n")
print("WROTE=" + str(EV / "BATCH_4" / "remaining_active_lines.txt"))

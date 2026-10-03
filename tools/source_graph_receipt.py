#!/usr/bin/env python3
"""
RAWRXD_BUILD_GRAPH_DIAGNOSTIC_RECEIPT

Emits the declared source-graph metrics for rawrxd/CMakeLists.txt.

Why this exists
---------------
Two prior attempts to read this graph disagree with each other:

  * a per-list warning said  WIN32IDE_SOURCES: DROPPED 225 nonexistent source(s)
  * the global accumulator said RAWRXD_DROPPED_SOURCE_TOTAL=0 / VERDICT=PASS
    in the same configuration, with -DRAWRXD_STRICT_SOURCES=ON

A receipt that can contradict itself is not a receipt. So this script computes every
number from the filesystem at the moment it is asked, and prints them in a form CMake
can relay verbatim. It asserts nothing it has not measured.

Classification
--------------
  PRESENT             path exists on disk
  ACTIVE_MISSING      bare path on a code line, file absent  -> DEFECT (CMake's
                      rawrxd_filter_missing_sources drops these silently, so the target
                      builds with less code than its source list implies)
  COMMENTED_MISSING   path appears only inside a `#` comment -> DEFECT (the reference
                      was hidden rather than resolved)
  COMMENTED_PRESENT   path in a comment whose file does exist -> retired reference,
                      file left behind

Path detection is anchored: a candidate must contain a `/` or a known source directory
prefix, which is what keeps prose in comments from being counted as a declaration.
"""

import os
import re
import sys
from collections import defaultdict

ROOT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else r"F:\~dev\rawrxd"
CML = os.path.join(ROOT, "CMakeLists.txt")

SRC_EXT = (".cpp", ".cc", ".cxx", ".hpp", ".h", ".asm", ".inc", ".m", ".mm")
# A path must look like a path: forward slash, or a known top-level source dir.
PATH_HINT = re.compile(r"(^|/)(src|Ship|tests|B014|certs|3rdparty|rguf_source|cmake|"
                       r"include|assets|masm|asm|validation|production)/")
EXT_RE = re.compile(r"[A-Za-z0-9_./\\@$(){}-]+\.(?:cpp|cc|cxx|hpp|h|asm|inc|m|mm)\b")
QUOTE_RE = re.compile(r'"([^"\n]+)"')

# Source-list keywords that introduce declarations worth counting.
LIST_KW = re.compile(
    r"\b(set|list)\s*\(\s*(APPEND|REMOVE_ITEM)?\s*([A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<body>.*)$", re.IGNORECASE | re.DOTALL)
ADD_EXE = re.compile(r"\badd_(?:executable|library)\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)


def strip_comment(line: str):
    """Return (code_part, comment_part) respecting double-quoted strings."""
    in_q = False
    for i, ch in enumerate(line):
        if ch == '"':
            in_q = not in_q
        elif ch == "#" and not in_q:
            return line[:i], line[i:]
    return line, ""


def norm(p: str) -> str:
    p = p.strip().strip('"').replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def looks_like_path(p: str) -> bool:
    if not p.lower().endswith(SRC_EXT):
        return False
    if PATH_HINT.search(p):
        return True
    # bare filenames inside a directory-style block, e.g. "B014/build/x.cpp"
    return "/" in p and " " not in p


def main():
    if not os.path.isfile(CML):
        print("RAWRXD_GRAPH_CML_MISSING=1")
        return 1

    with open(CML, "r", encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.read().splitlines()

    present = set()
    active_missing = {}      # path -> line
    commented_missing = {}   # path -> line
    commented_present = {}   # path -> line

    for lineno, raw in enumerate(raw_lines, 1):
        code, comment = strip_comment(raw)

        # ---- code (active) declarations -------------------------------
        for m in QUOTE_RE.finditer(code):
            p = norm(m.group(1))
            if not looks_like_path(p):
                continue
            if os.path.exists(os.path.join(ROOT, p)):
                present.add(p)
            elif p not in active_missing:
                active_missing[p] = lineno
            else:
                present.add(p)

        # ---- comment declarations --------------------------------------
        if not comment:
            continue
        for m in QUOTE_RE.finditer(comment):
            p = norm(m.group(1))
            if not looks_like_path(p):
                continue
            if os.path.exists(os.path.join(ROOT, p)):
                if p not in present and p not in commented_missing:
                    commented_present[p] = lineno
            elif p not in commented_missing and p not in active_missing:
                commented_missing[p] = lineno

    referenced = len(present) + len(active_missing)
    absent = len(active_missing) + len(commented_missing)

    by_area = defaultdict(lambda: [0, 0, 0])   # active, cmt_missing, cmt_present
    def area_of(p):
        parts = p.split("/")
        return parts[1] if len(parts) > 1 else (parts[0] if parts else "?")
    for p in active_missing:
        by_area[area_of(p)][0] += 1
    for p in commented_missing:
        by_area[area_of(p)][1] += 1
    for p in commented_present:
        by_area[area_of(p)][2] += 1

    absent_cpp = sum(1 for p in list(active_missing) + list(commented_missing)
                     if p.lower().endswith(".cpp"))

    print("=== RAWRXD BUILD GRAPH DIAGNOSTIC RECEIPT ===")
    print("RAWRXD_GRAPH_SOURCES_REFERENCED=%d" % referenced)
    print("RAWRXD_GRAPH_SOURCES_PRESENT=%d" % len(present))
    print("RAWRXD_GRAPH_SOURCES_ABSENT=%d" % absent)
    print("RAWRXD_GRAPH_ABSENT_CPP=%d" % absent_cpp)
    print("RAWRXD_GRAPH_COMMENTED_OUT_REFS=%d" % (len(commented_missing) + len(commented_present)))
    print("RAWRXD_GRAPH_ACTIVE_MISSING=%d" % len(active_missing))
    print("RAWRXD_GRAPH_COMMENTED_MISSING=%d" % len(commented_missing))
    print("RAWRXD_GRAPH_COMMENTED_PRESENT=%d" % len(commented_present))
    print("RAWRXD_GRAPH_ABSENT_BY_AREA=%s" % ",".join(
        "%s:%d" % (a, v[0] + v[1]) for a, v in
        sorted(by_area.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))))

    print("--- absent by area (active / commented-missing / commented-present) ---")
    for a, v in sorted(by_area.items(), key=lambda kv: -(kv[1][0] + kv[1][1])):
        print("  %-24s %5d %5d %5d" % (a, v[0], v[1], v[2]))

    ok = (absent == 0 and len(commented_missing) == 0 and len(commented_present) == 0)
    print("RAWRXD_SOURCE_GRAPH_001=%s" % ("PASS" if ok else "FAIL"))
    print("RAWRXD_SOURCE_GRAPH_001_SCOPE=graph existence and reference visibility only;")
    print("RAWRXD_SOURCE_GRAPH_001_NOT_A_FUNCTIONAL_PASS=1")
    return 0 if ok else 0   # diagnostic by default; never fails configure here


if __name__ == "__main__":
    sys.exit(main())
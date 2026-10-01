"""Rebuild every de-listed CMake line with correct paren balance.

Each line this reconciliation commented has the form:
    <indent># AUTO-REMOVED: stub file  ...: <CLASS>, 0 callers, 0 declared API. was: <ORIGINAL>

The original is a stub path from the manifest, optionally followed by ')' when
the source line doubled as the closing paren of its command. That trailing ')'
has to survive as LIVE text: anything after '#' is ignored by CMake, which is
why appending it to the comment left the file unparseable.

Rebuilding from the manifest is deterministic, unlike trying to strip characters
off a line whose provenance text legitimately ends in ')'.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
CM = ROOT / "CMakeLists.txt"
MARK = "RAWRXD_STUB_RECONCILIATION_001"
HEADER = "# AUTO-REMOVED: stub file  RAWRXD_STUB_RECONCILIATION_001"

rows = list(csv.DictReader((EV / "stub_manifest.csv").open(encoding="utf-8")))
cls = {r["PATH"]: r["CLASSIFICATION"] for r in rows}
# Longest path first so a path that is a prefix of another cannot win.
by_len = sorted(cls.keys(), key=len, reverse=True)


def main():
    dry = "--dry" in sys.argv
    lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
    rebuilt, unmatched = 0, []

    for i, line in enumerate(lines):
        if MARK not in line or not line.strip().startswith("#"):
            continue
        was = line.split("was:", 1)
        if len(was) != 2:
            continue
        tail = was[1]
        hit = None
        for p in by_len:
            if p in tail:
                hit = p
                break
        if hit is None:
            unmatched.append((i + 1, tail[:60]))
            continue
        after = tail.split(hit, 1)[1]
        # Live parens that were prepended by an earlier repair attempt.
        prefix = re.match(r"^(\s*)([\)\(]*)\s*", line)
        indent = prefix.group(1)
        already = prefix.group(2)
        carries_close = after.lstrip().startswith(")")
        live = ")" if (carries_close and ")" not in already) else ""
        new = (f"{indent}{live}  {HEADER}: {cls[hit]}, 0 callers, "
               f"0 declared API. was: {hit}{')' if carries_close else ''}")
        if new != line:
            lines[i] = new
            rebuilt += 1

    print(f"LINES_REBUILT={rebuilt}")
    print(f"UNMATCHED={len(unmatched)}")
    for ln, t in unmatched[:10]:
        print(f"   {ln}: {t}")

    # Verify the whole file balances before writing.
    depth = 0
    for i, line in enumerate(lines, start=1):
        body = line.split("#", 1)[0]
        depth += body.count("(") - body.count(")")
        if depth < 0:
            print(f"NEGATIVE_DEPTH_AT={i}")
            return 1
    print(f"FINAL_PAREN_DEPTH={depth}")
    if depth != 0:
        print("REFUSING_TO_WRITE: file would not balance")
        return 1
    if not dry and rebuilt:
        CM.write_text("\n".join(lines), encoding="utf-8", newline="")
        print("WROTE=1")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""BATCH_3 (re-apply) - de-list the 25 shipping placeholders by FULL PATH.

The first attempt matched leaf names as substrings and therefore commented out
real sources: stub sampler.cpp matched src/rawrxd_sampler.cpp, and stub
src/inference/Deep2Engine.cpp matched src/deep2/Deep2Engine.cpp. This version
requires the complete manifest path to appear in the line, so a shared basename
can no longer produce a false match.

A source line may also carry the closing paren of its command:
    src/deep2/foo.cpp)
The paren is emitted as live text BEFORE the comment marker, because everything
after '#' is invisible to CMake.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
CM = ROOT / "CMakeLists.txt"
MARK = "# AUTO-REMOVED: stub file  RAWRXD_STUB_RECONCILIATION_001"


def main():
    dry = "--dry" in sys.argv
    rows = list(csv.DictReader((EV / "stub_manifest.csv").open(encoding="utf-8")))
    ship = {r["PATH"]: r for r in rows if r["SHIPPING_TARGET"]}
    paths = sorted(ship.keys(), key=len, reverse=True)   # longest first

    lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
    hits = []
    for i, line in enumerate(lines, start=1):
        if line.strip().startswith("#"):
            continue
        for p in paths:
            if p in line:
                hits.append((i, p, line))
                break

    print(f"SHIPPING_STUBS={len(ship)}")
    print(f"FULL_PATH_MATCHES={len(hits)}")
    matched_paths = {p for _, p, _ in hits}
    missing = sorted(set(ship) - matched_paths)
    print(f"STUBS_WITH_NO_ACTIVE_FULL_PATH_LINE={len(missing)}")
    for p in missing:
        print("   no active line:", p)
    for i, p, line in hits:
        print(f"   {i:>6}  {p}")

    if dry or not hits:
        print("DRY_RUN=1" if dry else "NOTHING_TO_DO=1")
        return 0

    for i, p, line in hits:
        indent = re.match(r"^(\s*)", line).group(1)
        rest = line[line.index(p) + len(p):]
        carries_close = rest.lstrip().startswith(")")
        live = ")" if carries_close else ""
        lines[i - 1] = (f"{indent}{live}  {MARK}: E_SHIPPING_STUB, 0 callers, "
                        f"0 declared API, link-neutral. was: {p}"
                        f"{')' if carries_close else ''}")
    CM.write_text("\n".join(lines), encoding="utf-8", newline="")
    print(f"LINES_COMMENTED={len(hits)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

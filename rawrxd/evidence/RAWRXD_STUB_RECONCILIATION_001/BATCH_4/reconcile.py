"""BATCH_4/5 - de-list every active CMake line naming a remaining stub, then
quarantine the file.

Order matters: the lines are commented first so that removing the files cannot
create a "cannot find source file" configure error. A line is only commented
when the stub's file name appears in it, and the replacement keeps the original
text so the change is auditable by reading the diff.
"""
import csv
import re
import shutil
import subprocess
import sys
import hashlib
import json
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
CM = ROOT / "CMakeLists.txt"
PAYLOAD = EV / "stub-quarantine" / "payload"
MARKER = "# AUTO-REMOVED: stub file"


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for c in iter(lambda: fh.read(65536), b""):
            h.update(c)
    return h.hexdigest()


def main():
    phase = sys.argv[1] if len(sys.argv) > 1 else "delist"
    dry = "--dry" in sys.argv

    rows = list(csv.DictReader((EV / "stub_manifest.csv").open(encoding="utf-8")))
    done = {r["PATH"] for r in rows if r["SHIPPING_TARGET"]}
    todo = [r for r in rows if r["PATH"] not in done]

    if phase == "delist":
        leaves = {r["PATH"].rsplit("/", 1)[-1]: r for r in todo}
        lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
        hits = []
        for i, line in enumerate(lines, start=1):
            s = line.strip()
            if s.startswith("#"):
                continue
            for leaf, r in leaves.items():
                if leaf in line:
                    hits.append((i, leaf, r))
                    break
        print(f"ACTIVE_LINES={len(hits)}  DISTINCT_STUBS={len({h[2]['PATH'] for h in hits})}")
        if dry:
            for i, leaf, r in hits[:8]:
                print(f"   {i:>6}  {r['PATH']}")
            return 0
        for i, leaf, r in hits:
            indent = re.match(r"^(\s*)", lines[i - 1]).group(1)
            lines[i - 1] = (f"{indent}{MARKER}  RAWRXD_STUB_RECONCILIATION_001: "
                            f"{r['CLASSIFICATION']}, 0 callers, 0 declared API. "
                            f"was: {lines[i-1].strip()}")
        CM.write_text("\n".join(lines), encoding="utf-8", newline="")
        print(f"LINES_COMMENTED={len(hits)}")
        (EV / "BATCH_4" / "delisted_lines.json").write_text(
            json.dumps([{"line": i, "path": r["PATH"],
                         "class": r["CLASSIFICATION"]} for i, _, r in hits], indent=1),
            encoding="utf-8")
        return 0

    if phase == "quarantine":
        tracked = set(subprocess.run(["git", "-C", str(ROOT.parent), "ls-files"],
                                     capture_output=True, text=True).stdout.split("\n"))
        moved, skipped = 0, 0
        rec = EV / "stub-quarantine" / "removed.jsonl"
        with rec.open("a", encoding="utf-8") as fh:
            for r in todo:
                src = ROOT / r["PATH"]
                if not src.exists():
                    skipped += 1
                    continue
                if not dry:
                    dst = PAYLOAD / r["PATH"]
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dst))
                moved += 1
                if dry:
                    continue
                fh.write(json.dumps({
                    "ORIGINAL_PATH": r["PATH"],
                    "ORIGINAL_SHA256": r["SHA256"],
                    "CLASSIFICATION": r["CLASSIFICATION"],
                    "OWNING_TARGETS": r["TARGETS"],
                    "CALLSITE_COUNT": r["CALLSITE_COUNT"],
                    "DECLARED_API": r["DECLARED_API"],
                    "GIT_TRACKED": r["PATH"] in tracked,
                    "QUARANTINE_PAYLOAD": f"stub-quarantine/payload/{r['PATH']}",
                    "REMOVED_AT_COMMIT": "pending",
                    "RESTORE_COMMAND": (
                        f"git -C F:/~dev checkout HEAD -- \"{r['PATH']}\""
                        if r["PATH"] in tracked else
                        "Move stub-quarantine/payload/" + r["PATH"] +
                        " back to rawrxd/" + r["PATH"]),
                }) + "\n")
        print(f"MOVED={moved}  ALREADY_ABSENT={skipped}")
        return 0

    print("usage: reconcile.py delist|quarantine [--dry]")
    return 2


if __name__ == "__main__":
    sys.exit(main())

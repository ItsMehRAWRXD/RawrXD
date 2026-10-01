"""Quarantine a list of stub paths, preserving content and provenance.

Two facts drive the design:

  1. Many of these files are untracked in git. `git rm` cannot remove them and
     the spec's assumption that "git history remains the authoritative copy" is
     simply false for them. Content is therefore moved into the quarantine
     payload tree, not deleted.
  2. Nothing may be deleted merely because it looks obsolete, so every moved
     file keeps its original relative path under the payload root.

Usage: quarantine.py <csv-with-PATH-column> [--action ACTION] [--dry]
"""
import csv
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
PAYLOAD = EV / "stub-quarantine" / "payload"


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT.parent), *args],
                          capture_output=True, text=True).stdout


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    csv_path = Path(sys.argv[1])
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    action = "unspecified"
    if "--action" in sys.argv:
        action = sys.argv[sys.argv.index("--action") + 1]
    dry = "--dry" in sys.argv

    tracked_all = set(git("ls-files").split("\n"))
    moved, skipped = [], []
    for r in rows:
        rel = r["PATH"]
        src = ROOT / rel
        if not src.exists():
            skipped.append((rel, "already_absent"))
            continue
        if dry:
            moved.append(rel)
            continue
        dst = PAYLOAD / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        moved.append(rel)

    if dry:
        print(f"DRY_WOULD_MOVE={len(moved)}")
        for m in moved[:10]:
            print("   ", m)
        return 0

    # Provenance record for everything moved in this run.
    rec = EV / "stub-quarantine" / "removed.jsonl"
    with rec.open("a", encoding="utf-8") as fh:
        for r in rows:
            rel = r["PATH"]
            if rel not in moved:
                continue
            tracked = rel in tracked_all
            fh.write(json.dumps({
                "ORIGINAL_PATH": rel,
                "ORIGINAL_SHA256": r["SHA256"],
                "CLASSIFICATION": r["CLASSIFICATION"],
                "ACTION": r.get("ACTION") or action,
                "OWNING_TARGETS": r["TARGETS"],
                "CALLSITE_COUNT": r["CALLSITE_COUNT"],
                "DECLARED_API": r["DECLARED_API"],
                "GIT_TRACKED": tracked,
                "QUARANTINE_PAYLOAD": f"stub-quarantine/payload/{rel}",
                "REMOVED_AT_COMMIT": ("pending" if not tracked
                                      else "recorded in the commit that stages this"),
                "RESTORE_COMMAND": (f"git -C F:/~dev checkout HEAD -- \"{rel}\""
                                    if tracked else
                                    f"Move evidence/RAWRXD_STUB_RECONCILIATION_001/"
                                    f"stub-quarantine/payload/{rel} back to "
                                    f"rawrxd/{rel}"),
                "REMOVED_AT_UTC": subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')"],
                    capture_output=True, text=True).stdout.strip(),
            }) + "\n")

    print(f"MOVED={len(moved)}")
    print(f"SKIPPED={len(skipped)}")
    for s in skipped[:5]:
        print("   skip:", s)
    return 0


if __name__ == "__main__":
    sys.exit(main())

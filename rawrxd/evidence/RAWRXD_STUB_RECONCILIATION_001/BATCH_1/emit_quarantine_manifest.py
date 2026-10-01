"""BATCH_1 - emit the quarantine manifest (spec section 3) and the batch receipt.

Quarantine manifest records provenance for every classified stub. Nothing is
removed here; REMOVED_AT_COMMIT stays "pending" until a later batch actually
removes the path, so the manifest cannot claim a removal that did not happen.
"""
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path

OUT = Path(r"F:\~dev\rawrxd\evidence\RAWRXD_STUB_RECONCILIATION_001")
ROOT = Path(r"F:\~dev\rawrxd")

WHY = {
    "A_ORPHAN": ("not compiled by any CMake target; no caller; no declared API. "
                 "Dead source, not a partially built feature."),
    "B_BUILD_METADATA_GHOST": ("listed in CMake and compiled as an empty translation "
                               "unit; supplies no symbol; no caller references it."),
    "D_STUB_ONLY_TARGET": ("the CMake target that exists to build it has no other "
                           "meaningful source and cannot supply main()."),
    "E_SHIPPING_STUB": ("compiled into RawrXD-Win32IDE as an empty translation unit; "
                        "supplies no symbol; must be proven link-neutral to remove."),
}

ACTION_TO_BATCH = {
    "QUARANTINE_FROM_ACTIVE_TREE": "BATCH_5",
    "REMOVE_FROM_CMAKE_AND_QUARANTINE": "BATCH_4",
    "REMOVE_TARGET_FROM_ACTIVE_BUILD_AND_QUARANTINE": "BATCH_2",
    "CANDIDATE_PROVEN_DEAD_REMOVED_FROM_TARGET": "BATCH_3",
    "IMPLEMENT_REAL_TEST_OR_PROGRAM": "BATCH_2",
    "IMPLEMENT_FOR_REAL": "BATCH_3",
    "BLOCKED_SPEC_REQUIRED": "BLOCKED",
}


def git(*args):
    try:
        return subprocess.run(["git", "-C", str(ROOT.parent), *args],
                              capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception:
        return ""


def main():
    with (OUT / "stub_manifest.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    head = git("rev-parse", "HEAD")
    quarantine = OUT / "stub-quarantine"
    quarantine.mkdir(parents=True, exist_ok=True)

    lines = []
    for r in rows:
        lines.append("\n".join([
            "---",
            f"ORIGINAL_PATH={r['PATH']}",
            f"ORIGINAL_SHA256={r['SHA256']}",
            f"LINE_COUNT={r['LINE_COUNT']}",
            f"CLASSIFICATION={r['CLASSIFICATION']}",
            f"ACTION={r['ACTION']}",
            f"BATCH={ACTION_TO_BATCH.get(r['ACTION'], 'UNASSIGNED')}",
            f"OWNING_TARGETS={r['TARGETS'] or '(none)'}",
            f"SHIPPING_TARGET={r['SHIPPING_TARGET'] or '(none)'}",
            f"ONLY_SOURCE_OF_TARGET={r['ONLY_SOURCE_OF_TARGET'] or '(none)'}",
            f"CALLSITE_COUNT={r['CALLSITE_COUNT']}",
            f"HEADER_EXISTS={r['HEADER_EXISTS'] or '(none)'}",
            f"DECLARED_API={r['DECLARED_API']}",
            f"DECLARED_API_PROBE={r['DECLARED_API_PROBE']}",
            f"CMAKE_REFERENCED={r['CMAKE_REFERENCED']}",
            f"CURRENT_BUILD_FAILURE={r['CURRENT_BUILD_FAILURE'] or '(none)'}",
            f"WHY_REMOVED={WHY.get(r['CLASSIFICATION'], '')}",
            f"REASON_DETAIL={r['REASON']}",
            f"REMOVED_AT_COMMIT=pending",
            f"RESTORE_COMMAND=git -C F:/~dev checkout {head} -- \"{r['PATH']}\"",
        ]))
    header = "\n".join([
        "# RAWRXD_STUB_RECONCILIATION_001 - quarantine manifest",
        f"HEAD_AT_INVENTORY={head}",
        f"ENTRIES={len(rows)}",
        "REMOVED_AT_COMMIT=pending means the path is still present. This file is",
        "written by BATCH_1 (inventory only); later batches fill REMOVED_AT_COMMIT",
        "with the commit that actually removed the path.",
        "",
    ])
    (quarantine / "manifest.txt").write_text(header + "\n".join(lines) + "\n",
                                             encoding="utf-8")

    by_class = Counter(r["CLASSIFICATION"] for r in rows)
    by_action = Counter(r["ACTION"] for r in rows)
    by_batch = Counter(ACTION_TO_BATCH.get(r["ACTION"], "UNASSIGNED") for r in rows)

    md = ["# Stub reconciliation inventory (BATCH_1)", "",
          f"HEAD_AT_INVENTORY: `{head}`", "",
          "| Metric | Measured | Expected | Match |", "|---|---|---|---|"]

    def m(name, meas, exp):
        md.append(f"| {name} | {meas} | {exp} | {'yes' if meas == exp else 'NO'} |")

    m("TOTAL_STUBS", len(rows), 446)
    m("CMAKE_COMPILED", sum(1 for r in rows if r["COMPILED_BY_TARGET"] == "1"), 68)
    m("NEVER_COMPILED", sum(1 for r in rows if r["COMPILED_BY_TARGET"] == "0"), 378)
    m("SHIPPING_IDE", sum(1 for r in rows if r["SHIPPING_TARGET"]), 25)
    m("STUB_ONLY_TARGETS",
      len({t for r in rows for t in r["ONLY_SOURCE_OF_TARGET"].split(";") if t}), 17)
    m("LNK2019_MAIN_FAILURES",
      sum(1 for r in rows if "LNK2019" in r["CURRENT_BUILD_FAILURE"]
          and "unresolved external symbol main" in r["CURRENT_BUILD_FAILURE"]), 5)
    md += ["", "## Classification", "", "| Class | Count |", "|---|---|"]
    for k, v in sorted(by_class.items()):
        md.append(f"| {k} | {v} |")
    md += ["", "## Action", "", "| Action | Count | Batch |", "|---|---|---|"]
    for k, v in sorted(by_action.items()):
        md.append(f"| {k} | {v} | {ACTION_TO_BATCH.get(k, '?')} |")
    md += ["", "## Batch load", "", "| Batch | Entries |", "|---|---|"]
    for k, v in sorted(by_batch.items()):
        md.append(f"| {k} | {v} |")
    (OUT / "stub-quarantine" / "manifest.md").write_text("\n".join(md) + "\n",
                                                         encoding="utf-8")

    print("QUARANTINE_ENTRIES=" + str(len(rows)))
    print("QUARANTINE_MANIFEST_COMPLETE=1" if len(lines) == len(rows) else "INCOMPLETE")
    for k, v in sorted(by_class.items()):
        print(f"CLASS_{k}={v}")
    for k, v in sorted(by_action.items()):
        print(f"ACTION_{k}={v}")
    for k, v in sorted(by_batch.items()):
        print(f"BATCH_{k}={v}")


if __name__ == "__main__":
    main()

"""Snapshot / diff every generated target's compile list.

Used to prove a CMake edit changed exactly one target and nothing else. A
hand-wave about which list a line belongs to is not evidence; this is.
"""
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

BUILD = Path(r"F:\~dev\rawrxd\build_w1")


def snapshot():
    out = {}
    if not BUILD.exists():
        return out
    for proj in BUILD.rglob("*.vcxproj"):
        try:
            tree = ET.parse(proj)
        except ET.ParseError:
            continue
        srcs = []
        for node in tree.getroot().iter():
            if node.tag.endswith("}ClCompile"):
                inc = node.get("Include")
                if inc:
                    srcs.append(inc.replace("\\", "/").lower())
        out[proj.stem] = sorted(set(srcs))
    return out


def main():
    mode = sys.argv[1]
    path = Path(sys.argv[2])
    if mode == "save":
        path.write_text(json.dumps(snapshot(), indent=1, sort_keys=True), encoding="utf-8")
        print(f"SNAPSHOT_TARGETS={len(snapshot())}")
        return
    before = json.loads(path.read_text(encoding="utf-8"))
    after = snapshot()
    changed_targets = []
    for t in sorted(set(before) | set(after)):
        b, a = set(before.get(t, [])), set(after.get(t, []))
        if b != a:
            changed_targets.append(t)
            print(f"TARGET_CHANGED={t}  removed={len(b - a)}  added={len(a - b)}")
            for s in sorted(b - a):
                print(f"    - {s}")
            for s in sorted(a - b):
                print(f"    + {s}")
    print(f"TARGETS_CHANGED={len(changed_targets)}")
    print("TARGETS_TOTAL=" + str(len(after)))


if __name__ == "__main__":
    main()

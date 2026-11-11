#!/usr/bin/env python3
"""Extend optional-source guards past the follow-up target_* calls.

The first pass wrapped `add_executable` (+ a trailing set_target_properties) in
`if(EXISTS ...)`. Several targets then have `target_include_directories`,
`target_link_libraries`, `if(WIN32) ... endif()` and `message(STATUS ...)`
AFTER the block, which CMake still evaluates when the target was skipped -
producing "Target ... links to ... but is not a target" style configure errors.

This pass moves the `else()/message/endif()` tail of each guard to just after
the last line that references the guarded target, so the whole target's
configuration is inside the guard.
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(r"F:\rawrxd\.kilo\worktrees\thorn-measure")
CMAKE = ROOT / "CMakeLists.txt"

MARKER = 'message(STATUS "optional source absent, target skipped:'


def main() -> int:
    lines = CMAKE.read_text(encoding="utf-8").split("\n")
    moved = 0

    i = 0
    while i < len(lines):
        if lines[i].strip().startswith(MARKER):
            guard_src = lines[i].split(MARKER, 1)[1].rstrip('")').strip()
            # The endif() closing this guard is the next one.
            endif = None
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == "endif()":
                    endif = j
                    break
            if endif is None:
                i += 1
                continue

            # Recover the target name from the guarded add_executable above.
            target = None
            for j in range(i - 1, -1, -1):
                m = re.match(r"\s*add_executable\(\s*(\S+)", lines[j])
                if m:
                    target = m.group(1)
                    break
                if lines[j].strip().startswith("if(EXISTS"):
                    break
            if not target:
                print(f"WARN: no target for guard at line {i+1}", file=sys.stderr)
                i += 1
                continue

            # Find the last following line that mentions this target.
            last = endif
            for j in range(endif + 1, len(lines)):
                if re.search(r"\b" + re.escape(target) + r"\b", lines[j]):
                    # Stop extending once we hit the next guard banner.
                    if lines[j].strip().startswith("if(EXISTS"):
                        break
                    last = j
            if last == endif:
                i += 1
                continue

            tail = lines[endif + 1 : last + 1]
            guard = lines[i:endif + 1]      # else()  message  endif()

            # Rebuild: [.. endif() position] now holds the tail, then the guard.
            new = lines[:endif] + tail + guard + lines[last + 1 :]
            lines = new
            moved += 1
            i = endif + len(tail) + len(guard)
            continue
        i += 1

    CMAKE.write_text("\n".join(lines), encoding="utf-8")
    print(f"extended {moved} guards")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

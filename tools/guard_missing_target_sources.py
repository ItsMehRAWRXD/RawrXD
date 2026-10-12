#!/usr/bin/env python3
"""Guard every target whose source is absent from the checkout.

Scans every CMakeLists.txt in the worktree (root and subdirectories), finds
`add_executable(...)` blocks that reference a source file which does not exist,
and wraps the whole target block in `if(EXISTS "<missing>") ... else()
message(STATUS "optional source absent, target skipped: ...") endif()`.

The block taken verbatim - from the `add_executable(` line to the last line that
mentions the target name - and indented as a unit. The range computation stops
at any section banner or at another `add_executable`/`add_target`, and never
splits an open parenthesis. Taking it verbatim (rather than re-emitting the
inner statements) is what preserves nested `if(MSVC) ... else() ... endif()`
control flow, which is where a rewriting approach produces "flow control
statements are not properly nested".

This does not invent any file. Every skip is reported as a STATUS line.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(r"F:\rawrxd\.kilo\worktrees\thorn-measure")

TARGET_START = re.compile(r"^\s*add_executable\s*\(")
BOUNDARY = re.compile(r"^\s*add_executable\s*\(|^\s*add_library\s*\(|^\s*#\s*=+\s*$")
CALL_OPEN = re.compile(r"^\s*[a-zA-Z_][\w\-]*\s*\(")


def balanced_end(lines, start):
    depth = 0
    for j in range(start, len(lines)):
        depth += lines[j].count("(") - lines[j].count(")")
        if depth <= 0 and j >= start:
            return j
    return len(lines) - 1


def exists(path, base):
    p = (base / path if not pathlib.Path(path).is_absolute() else pathlib.Path(path))
    return p.exists()


def guard_file(path):
    original = path.read_text(encoding="utf-8")
    lines = original.split("\n")
    base = path.parent
    out = []
    i = 0
    n_guarded = 0

    while i < len(lines):
        if not TARGET_START.match(lines[i]):
            out.append(lines[i])
            i += 1
            continue

        # Collect the add_executable's own source arguments.
        end = balanced_end(lines, i)
        head = "\n".join(lines[i:end + 1])
        m = re.match(r"\s*add_executable\(\s*(\S+)", lines[i])
        if not m:
            out.extend(lines[i:end + 1])
            i = end + 1
            continue
        target = m.group(1)

        # Source files: tokens that are not variables/aliases/keywords.
        args = re.findall(r"[^\s()]+", head[len("add_executable("):])
        skip_words = {"WIN32", "MACOSX_BUNDLE", "EXCLUDE_FROM_ALL", "EXCLUDE_FROM_ALL"}
        srcs = [a for a in args
                if a not in skip_words and not a.startswith("$")
                and a not in {target} and a.upper() not in skip_words
                and not a.isupper()]

        missing = [s for s in srcs
                   if not exists(s, base) and not exists("${CMAKE_CURRENT_SOURCE_DIR}/" + s, base)]

        if not missing or not srcs:
            out.extend(lines[i:end + 1])
            i = end + 1
            continue

        # Extend forward over every line that mentions the target, stopping at
        # the first boundary, and never splitting an open call.
        last = end
        j = end + 1
        tgt_re = re.compile(r"\b" + re.escape(target) + r"\b")
        while j < len(lines):
            if BOUNDARY.match(lines[j]):
                break
            if tgt_re.search(lines[j]):
                if CALL_OPEN.match(lines[j]):
                    j = balanced_end(lines, j) + 1
                else:
                    j += 1
                last = j - 1
                continue
            if re.match(r"\s*if\s*\(", lines[j]):
                j = balanced_end_control(lines, j, target)
                last = j - 1
                continue
            break

        block = lines[i:last + 1]
        indent = re.match(r"\s*", lines[i]).group(0)
        missing_top = missing[0]
        rel = f"{path.parent.relative_to(ROOT).as_posix()}/{missing_top}" \
            if path.parent != ROOT else missing_top
        out.append(f'{indent}if(EXISTS "${{CMAKE_CURRENT_SOURCE_DIR}}/{missing_top}")')
        for b in block:
            out.append((indent + "    " + b) if b.strip() else b)
        out.append(f"{indent}else()")
        out.append(f'{indent}    message(STATUS "optional source absent, target skipped: {rel}")')
        out.append(f"{indent}endif()")
        n_guarded += 1
        i = last + 1

    if n_guarded:
        path.write_text("\n".join(out), encoding="utf-8")
    return n_guarded


def balanced_end_control(lines, start, target):
    """Extend over an if/elseif/else/endif() that mentions `target`."""
    depth = 1
    j = start + 1
    tgt_re = re.compile(r"\b" + re.escape(target) + r"\b")
    while j < len(lines):
        if re.match(r"\s*(if|elseif)\s*\(", lines[j]):
            depth += 1
        elif re.match(r"\s*endif\s*\(", lines[j]):
            depth -= 1
            if depth == 0:
                return j + 1
        elif depth == 1 and not tgt_re.search(lines[j]) and CALL_OPEN.match(lines[j]):
            # A control block that never referenced the target: don't swallow.
            return j
        j += 1
    return j


def main():
    total = 0
    files = sorted(ROOT.rglob("CMakeLists.txt"))
    for f in files:
        n = guard_file(f)
        if n:
            rel = f.relative_to(ROOT).as_posix()
            print(f"  {rel}: guarded {n} target(s)")
            total += n
    print(f"total guarded: {total}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

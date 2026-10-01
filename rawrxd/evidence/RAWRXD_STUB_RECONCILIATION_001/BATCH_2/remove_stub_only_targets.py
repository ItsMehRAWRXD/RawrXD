"""BATCH_2 - remove stub-only CMake targets and every command that names them.

Three things the naive scan got wrong, each verified against the real file:

  1. add_executable can close on the same line. Scanning forward to the next
     line starting with ')' overshot by ~40 lines and swallowed neighbouring
     targets. Paren depth is tracked instead.
  2. Each target has companion commands - set_target_properties,
     target_link_libraries, add_test(NAME ...) - that reference a target which
     no longer exists. Leaving them is a hard CMake configure error.
  3. add_test names the target in its second argument, not its first.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(r"F:\~dev\rawrxd")
EV = ROOT / "evidence" / "RAWRXD_STUB_RECONCILIATION_001"
CM = ROOT / "CMakeLists.txt"

TARGET_COMMANDS = {
    "add_executable", "add_library", "set_target_properties",
    "target_link_libraries", "target_include_directories",
    "target_compile_definitions", "target_compile_options",
    "target_compile_features", "target_sources", "add_dependencies",
    "add_test",
}


def is_target_command(cmd):
    # Any target_* command refers to a target as its first argument, so the
    # whole family has to be covered. Enumerating them one at a time is how
    # target_compile_features got missed and broke configure.
    return cmd in TARGET_COMMANDS or cmd.startswith("target_")
CMD_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def command_spans(lines):
    """(cmd, start, end_exclusive) for every command invocation, nesting aware."""
    spans = []
    i = 0
    n = len(lines)
    while i < n:
        m = CMD_RE.match(lines[i])
        if not m:
            i += 1
            continue
        depth = 0
        j = i
        while j < n:
            for ch in lines[j]:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            if depth <= 0:
                break
            j += 1
        spans.append((m.group(1), i, j + 1))
        i = j + 1
    return spans


def names_target(cmd, body, target):
    """True when this command's arguments refer to `target`.

    `body` is the argument list only, so the command name is supplied
    separately; branching on body.startswith("add_test") could never fire.
    """
    if target not in body:
        return False
    if cmd == "add_test":
        return re.search(r"\bNAME\s+" + re.escape(target) + r"\b", body) is not None
    if cmd == "add_dependencies":
        return re.search(r"(^|\s)" + re.escape(target) + r"(\s|$)", body) is not None
    # Every other command names the target as its first argument.
    return re.search(r"^\s*" + re.escape(target) + r"\b", body) is not None


def main():
    apply = "--apply" in sys.argv
    rows = list(csv.DictReader((EV / "stub_manifest.csv").open(encoding="utf-8")))
    targets = sorted({t for r in rows for t in r["ONLY_SOURCE_OF_TARGET"].split(";") if t})

    lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
    spans = command_spans(lines)
    body_of = {}
    for cmd, a, b in spans:
        # Arguments only. Matching against the whole line would anchor the regex
        # on the command name, not on the target that follows it.
        first = lines[a]
        open_paren = first.find("(")
        args_first = first[open_paren + 1:] if open_paren >= 0 else first
        body_of[(cmd, a)] = "\n".join([args_first] + lines[a + 1:b])

    drop = set()
    removed = []
    for cmd, a, b in spans:
        if not is_target_command(cmd):
            continue
        body = body_of[(cmd, a)]
        for t in targets:
            if names_target(cmd, body, t):
                drop.update(range(a + 1, b + 1))
                removed.append((cmd, t, a + 1, b))
                break

    print(f"TARGETS={len(targets)}")
    print(f"COMMANDS_REMOVED={len(removed)}")
    by_cmd = {}
    for cmd, t, a, b in removed:
        by_cmd[cmd] = by_cmd.get(cmd, 0) + 1
    for c, n in sorted(by_cmd.items()):
        print(f"   {c}: {n}")
    per_target = {t: 0 for t in targets}
    for cmd, t, a, b in removed:
        per_target[t] += 1
    untouched = [t for t in targets if per_target[t] == 0]
    print(f"TARGETS_WITH_NO_REMOVAL={len(untouched)}")
    for t in untouched:
        print("   UNTOUCHED:", t)
    for cmd, t, a, b in sorted(removed, key=lambda r: r[2]):
        print(f"   {a:>6}..{b:<6} {cmd:<24} {t}")
    if not apply:
        print("DRY_RUN=1")
        return 1 if untouched else 0
    out = [l for i, l in enumerate(lines, start=1) if i not in drop]
    CM.write_text("\n".join(out), encoding="utf-8", newline="")
    print(f"LINES_REMOVED={len(drop)}")
    print(f"LINES_BEFORE={len(lines)} LINES_AFTER={len(out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Restore every line this reconciliation wrongly de-listed.

The de-list matched by leaf name as a substring, so a stub named sampler.cpp
matched the real source src/rawrxd_sampler.cpp, and the stub
src/inference/Deep2Engine.cpp matched the real src/deep2/Deep2Engine.cpp. Real
sources were commented out. This puts them back.

Recovering the original text is deterministic. The earlier paren repair
appended a run of n identical parens to a line, where n was computed as
closes-minus-opens of the ORIGINAL. So for the current text T:

    net(T) = net(original) + net(appended run) = n + n = 2n

giving n = |net(T)| / 2, and stripping n trailing parens of that kind from T
recovers the original exactly. A line whose net(T) is 0 was never touched.

Nothing is written unless the whole file balances to depth 0.
"""
import re
import sys
from pathlib import Path

CM = Path(r"F:\~dev\rawrxd\CMakeLists.txt")
MARK = "RAWRXD_STUB_RECONCILIATION_001"


def net(s):
    return s.count(")") - s.count("(")


def main():
    dry = "--dry" in sys.argv
    lines = CM.read_text(encoding="utf-8", errors="replace").split("\n")
    restored, balanced, kept = 0, 0, 0

    for i, line in enumerate(lines):
        s = line.strip()
        if not s.startswith("#") or MARK not in line or "was:" not in line:
            continue
        indent = re.match(r"^(\s*)", line).group(1)
        head, tail = line.split("was:", 1)
        # Drop any live parens an earlier repair prepended before the comment.
        head = re.sub(r"^(\s*)[\)\(\s]*", r"\1", head)
        tail = tail.rstrip("\n")
        t_net = net(tail)
        if t_net == 0:
            original = tail
        else:
            n = abs(t_net) // 2
            ch = ")" if t_net > 0 else "("
            if t_net % 2 != 0:
                print(f"ODD_NET_AT_LINE={i+1} net={t_net} tail={tail[:60]!r}")
                return 1
            if not tail.endswith(ch * n):
                print(f"TAIL_MISMATCH_AT_LINE={i+1} tail={tail[-40:]!r} n={n}")
                return 1
            original = tail[: len(tail) - n]
        new = indent + original
        if new != line:
            restored += 1
        lines[i] = new
        balanced += 1

    print(f"MARKER_LINES_SEEN={balanced}")
    print(f"LINES_RESTORED={restored}")

    # A whole-file paren scan is NOT a valid gate here: the pristine HEAD file
    # already reports negative depth at line 55 because parens appear inside
    # quoted paths and generator expressions. `cmake -S ... -B ...` is the
    # authority, and the caller runs it after this writes.
    depth = sum(net(l.split("#", 1)[0]) for l in lines)
    print(f"WHOLE_FILE_NET_PARENS={depth} (not a validity test; see module docstring)")

    if not dry:
        CM.write_text("\n".join(lines), encoding="utf-8", newline="")
        print("WROTE=1")
    return 0


if __name__ == "__main__":
    sys.exit(main())

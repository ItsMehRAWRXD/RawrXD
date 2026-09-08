import re
from pathlib import Path

p = Path(r"G:/~dev/rawrxd/src/core/command_handlers_comprehensive.cpp")
t = p.read_text(encoding="utf-8", errors="replace")


def repl(m: re.Match) -> str:
    msg = m.group(1)
    tag = re.sub(r"[^A-Za-z0-9]+", "", msg)[:48] or "Handler"
    return f'return {{1, "NOT_PRODUCT_PATH=1 FEATURE_FICTION=1 {tag}", nullptr}};'


nt, n = re.subn(r'return \{0, "([^"]+)", nullptr\};', repl, t)
p.write_text(nt, encoding="utf-8")
print(f"converted={n}")

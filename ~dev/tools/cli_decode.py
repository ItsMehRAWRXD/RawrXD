import re
import sys

raw = open(r"F:\rawrxd\evidence\PARITY_2026-10-13\cli_def.out", "rb").read()
txt = raw.decode("utf-8", "replace")
clean = re.sub(r"\x1b\[[0-9;]*m", "", txt)
out = []
out.append("total_bytes=%d" % len(raw))
out.append("raw_tail=%r" % raw[-48:])
out.append("clean_tail=%r" % clean[-120:])
i = clean.rfind("> ")
out.append("GEN_AFTER_PROMPT=%r" % clean[i:i + 60])
open(r"F:\rawrxd\evidence\PARITY_2026-10-13\cli_def.txt", "w",
     encoding="utf-8").write("\n".join(out))
print("\n".join(out))

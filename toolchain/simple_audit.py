import os
import re
from collections import Counter

asm_dir = r"d:\rawrxd\src\asm"

keywords = [
    "proc", "endp", "invoke", "macro", "endm", "if", "else", "endif",
    "struct", "ends", "extern", "public", "include", "equ", "assume",
    "local", "align", "db", "dw", "dd", "dq", "frame", "uses",
    "option", "code", "data", "const", "proto", "typedef",
    "union", "enum", "for", "while", "repeat", "break",
    "continue", "exitm", "goto", "label", "addr", "offset",
    "ptr", "sizeof", "lengthof", "dup", "this",
    "pushreg", "allocstack", "setframe", "endprolog",
    "stdcall", "cdecl", "fastcall", "flat"
]

results = Counter()
print("Scanning...")

for root, _, files in os.walk(asm_dir):
    for file in files:
        if file.endswith(".asm"):
            with open(os.path.join(root, file), 'r', errors='ignore') as f:
                content = f.read().lower()
                for kw in keywords:
                    if re.search(rf'\b{kw}\b', content):
                        results[kw] += 1

print("\n=== RESULTS ===")
for kw, count in results.most_common():
    tier = "T1" if count >= 200 else "T2" if count >= 50 else "T3"
    print(f"{kw:15} : {count:4d} [{tier}]")

print(f"\nTotal: {len(results)} features in {sum(1 for _ in os.walk(asm_dir))} dirs")

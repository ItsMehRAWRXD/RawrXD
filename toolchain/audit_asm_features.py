import os
import re
from collections import Counter

# Configuration
asm_dir = r"d:\rawrxd\src\asm"

# List of potential MASM/Assembly keywords to audit
keywords = [
    r"\.macro", r"macro", r"\.endm", r"endm",
    r"\.invoke", r"invoke",
    r"\.if", r"\.else", r"\.endif", r"if", r"else", r"endif",
    r"\.struct", r"\.ends", r"struct", r"ends",
    r"\.extern", r"extern", r"\.public", r"public",
    r"\.proc", r"\.endp", r"proc", r"endp",
    r"\.assume", r"assume",
    r"\.local", r"local",
    r"\.align", r"align",
    r"\.byte", r"\.word", r"\.dword", r"\.qword",
    r"db", r"dw", r"dd", r"dq",
    r"include", r"\.include",
    r"equ", r"\.equ",
    r"frame", r"\.frame",
    r"\.pushreg", r"\.allocstack", r"\.setframe", r"\.endprolog",
    r"uses", r"\.uses",
    r"option", r"\.option",
    r"\.code", r"\.data", r"\.const", r"\.bss",
    r"proto", r"\.proto",
    r"typedef", r"\.typedef",
    r"record", r"\.record",
    r"union", r"\.union",
    r"enum", r"\.enum",
    r"for", r"\.for", r"endfor", r"\.endfor",
    r"while", r"\.while", r"endw", r"\.endw",
    r"repeat", r"\.repeat", r"until", r"\.until",
    r"break", r"\.break",
    r"continue", r"\.continue",
    r"exitm", r"\.exitm",
    r"goto", r"\.goto",
    r"label", r"\.label",
    r"addr", r"\.addr",
    r"offset", r"\.offset",
    r"ptr", r"\.ptr",
    r"length", r"\.length",
    r"size", r"\.size",
    r"sizeof", r"\.sizeof",
    r"lengthof", r"\.lengthof",
    r"this", r"\.this",
    r"dup", r"\.dup",
    r"\?", r"\$",
    r"@@", r"@f", r"@b",
    r"@code", r"@data", r"@stack",
    r"@curseg",
    r"flat", r"\.flat",
    r"stdcall", r"\.stdcall",
    r"cdecl", r"\.cdecl",
    r"fastcall", r"\.fastcall",
    r"vectorcall", r"\.vectorcall",
    r"sysv", r"\.sysv",
]

results = Counter()
file_counts = {}

print(f"Auditing {asm_dir}...")
print(f"Checking {len(keywords)} keywords...\n")

asm_files = []
for root, _, files in os.walk(asm_dir):
    for file in files:
        if file.endswith(".asm"):
            asm_files.append(os.path.join(root, file))

print(f"Found {len(asm_files)} .asm files\n")

for filepath in asm_files:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
            for kw in keywords:
                pattern = re.compile(rf"\b{kw}\b")
                if pattern.search(content):
                    results[kw] += 1
                    if kw not in file_counts:
                        file_counts[kw] = []
                    file_counts[kw].append(os.path.basename(filepath))
    except Exception as e:
        print(f"Error reading {filepath}: {e}")

print("=" * 60)
print("FEATURE AUDIT RESULTS (Frequency across all files)")
print("=" * 60)
print(f"{'Keyword':<20} {'Files':>8} {'Tier':<15}")
print("-" * 60)

tier1_threshold = 200
tier2_threshold = 50

tier1 = []
tier2 = []
tier3 = []

for kw, count in results.most_common():
    if count >= tier1_threshold:
        tier = "TIER 1 (Core)"
        tier1.append((kw, count))
    elif count >= tier2_threshold:
        tier = "TIER 2 (Ctrl)"
        tier2.append((kw, count))
    else:
        tier = "TIER 3 (Adv)"
        tier3.append((kw, count))
    print(f"{kw:<20} {count:>8} {tier:<15}")

print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"Tier 1 (Core - >200 files):     {len(tier1)} features")
print(f"Tier 2 (Control - 50-200):      {len(tier2)} features")
print(f"Tier 3 (Advanced - <50):        {len(tier3)} features")
print(f"Total unique features found:    {len(results)}")

# Show sample files for Tier 1
print("\n" + "=" * 60)
print("TIER 1 FEATURES - Sample Files")
print("=" * 60)
for kw, count in tier1[:5]:
    print(f"\n{kw} ({count} files):")
    for f in file_counts[kw][:3]:
        print(f"  - {f}")

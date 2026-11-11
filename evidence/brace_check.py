import re

p = r"F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp"
lines = open(p, encoding="utf-8", errors="replace").read().split("\n")

def strip(code):
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r'"((?:\\.|[^"\\])*)"', '""', code)
    code = re.sub(r"'((?:\\.|[^'\\])*)'", "''", code)
    code = re.sub(r"//[^\n]*", "", code)
    return code

stripped = [strip(ln) for ln in lines]

# find class ModelExportRuntime open (line containing the keyword, brace may be next line)
open_line = None
for i, ln in enumerate(stripped, start=1):
    if re.search(r"\bclass\s+ModelExportRuntime\b", ln):
        open_line = i
        break

# the opening brace line: same line if '{' present, else next line
brace_line = open_line
if open_line and "{" not in stripped[open_line-1]:
    brace_line = open_line + 1

print("CLASS_KEYWORD_LINE =", open_line, "  OPEN_BRACE_LINE =", brace_line)

# balanced-brace walk starting at the class opening brace
b = 0
started = False
matched_close = None
for i in range(brace_line - 1, len(stripped)):
    delta = stripped[i].count("{") - stripped[i].count("}")
    if delta:
        b += delta
        if i+1 >= 750 and i+1 <= 1600:
            print("  %4d bal=%+d  %s" % (i+1, b, lines[i].rstrip()[:95]))
    if brace_line and i+1 >= brace_line and b <= 0 and (started or delta):
        started = True
    if started and b == 0:
        matched_close = i + 1
        break

print("CLASS_MATCHING_CLOSE_LINE =", matched_close)
if matched_close:
    lo = max(1, matched_close-3); hi = min(len(lines), matched_close+2)
    print("--- context around class close ---")
    for i in range(lo, hi+1):
        print("  %4d: %s" % (i, lines[i-1]))

# full-file final balance
tot = 0
for ln in stripped:
    tot += ln.count("{") - ln.count("}")
print("FULL_FILE_FINAL_BALANCE =", tot)

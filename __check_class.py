import re

log = open(r'd:\rawrxd\__build_log.txt').read()

# Find all unresolved external symbols with :: (class methods)
syms = set()
for line in log.split('\n'):
    if 'unresolved external symbol' in line:
        # Match the decorated name inside quotes
        m = re.search(r'unresolved external symbol\s+"([^"]+)"', line)
        if m:
            sym = m.group(1)
            if '::' in sym:
                syms.add(sym)

for s in sorted(syms):
    print(s)

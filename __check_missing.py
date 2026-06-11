import re

# Read current stub file
stub = open(r'd:\rawrxd\src\win32app\win32app_stubs.cpp').read()
stub_handlers = set(re.findall(r'STUB_HANDLER\((\w+)\)', stub))

# Read build log and extract unresolved handle* symbols
log = open(r'd:\rawrxd\__build_log.txt').read()

# Find all unresolved external symbols that start with 'handle'
unresolved = set()
class_unresolved = []
for line in log.split('\n'):
    if 'unresolved external symbol' in line:
        m = re.search(r'unresolved external symbol\s+([A-Za-z0-9_:]+)', line)
        if m:
            sym = m.group(1)
            if sym.startswith('handle'):
                unresolved.add(sym)
            if '::' in sym:
                class_unresolved.append(sym)

print('=== MISSING HANDLERS (in build log but not in stub file) ===')
missing = sorted(unresolved - stub_handlers)
for h in missing:
    print(h)

print()
print('=== CLASS METHOD UNRESOLVED ===')
for c in sorted(set(class_unresolved)):
    print(c)

print()
print('=== TOTAL MISSING HANDLERS ===')
print(len(missing))
print('=== TOTAL CLASS UNRESOLVED ===')
print(len(set(class_unresolved)))

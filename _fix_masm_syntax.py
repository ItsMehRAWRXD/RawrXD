import re

with open(r'd:\rawrxd-ci-bootstrap\SovereignOrchestrator_Hardened.asm', 'r') as f:
    content = f.read()

# Fix 1: Replace C-style hex 0xNNNN with MASM-style NNNNh
content = re.sub(r'0x([0-9A-Fa-f]+)(?![0-9A-Fa-f])', r'\1h', content)

# Fix 2: Replace @@ labels with .labels (MASM PROC-local syntax)
content = content.replace('@@', '.')

# Fix 3: Fix any double-h issues
content = re.sub(r'hh\b', 'h', content)
content = re.sub(r'hh$', 'h', content, flags=re.MULTILINE)

# Fix 4: Ensure hex values starting with letter have leading zero
content = re.sub(r'\b([A-Fa-f][0-9A-Fa-f]*)h\b', r'0\1h', content)

with open(r'd:\rawrxd-ci-bootstrap\SovereignOrchestrator_Hardened.asm', 'w') as f:
    f.write(content)

print('Fixed MASM syntax: 0x -> h suffix, @@ -> .labels')

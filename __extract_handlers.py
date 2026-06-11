import re

with open(r'd:\rawrxd\__build_log.txt', 'r') as f:
    text = f.read()

matches = re.findall(r'handle\w+', text)
handlers = sorted(set(m for m in matches if m.startswith('handle')))

print(f'Found {len(handlers)} unique handlers')
for h in handlers:
    print(f'STUB_HANDLER({h})')

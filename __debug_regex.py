import re

log = open(r'd:\rawrxd\__build_log.txt').read()
for line in log.split('\n')[:60]:
    if 'unresolved external symbol' in line:
        print('LINE:', repr(line[:200]))
        m = re.search(r'unresolved external symbol\s+\"([^\"]+)\"', line)
        if m:
            print('  MATCH:', m.group(1))
        else:
            print('  NO MATCH')

import json, re
# certified executor argmax from its log
cert = []
for line in open(r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\cert_exec.log', encoding='utf-8', errors='replace'):
    m = re.search(r'Predicted token: (\d+)', line)
    if m:
        cert.append(int(m.group(1)))
native = json.load(open(r'F:\rawrxd\evidence\RAWRXD_DEEP2_RUNTIME_PARITY_001\native.json'))['argmax']
n = min(len(cert), len(native))
match = sum(1 for i in range(n) if cert[i] == native[i])
print('certified executor argmax (%d): %s' % (len(cert), cert))
print('runtime graph    argmax (%d): %s' % (len(native), native))
print()
print('runtime vs certified match: %d/%d = %.1f%%' % (match, n, 100.0*match/max(n,1)))
for i in range(n):
    if cert[i] != native[i]:
        print('  first divergence at pos %d: ref=%d runtime=%d' % (i, cert[i], native[i]))
        break
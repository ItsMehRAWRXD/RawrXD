import re, struct

src = open(r'F:\rawrxd\src\deep2\modelgenie\TensorROM.generated.hpp', encoding='utf-16').read()
names = re.findall(r'"([^"]+)"', src)
names = [n for n in names if ('.' in n and ' ' not in n and len(n) > 6)]
expected = set(names)
print('quoted strings in TensorROM :', len(names), 'distinct:', len(expected))

p = r'F:\models\gguf\library__deepseek-coder-v2__16b.gguf'
f = open(p, 'rb')
assert f.read(4) == b'GGUF'
struct.unpack('<I', f.read(4))
tc = struct.unpack('<Q', f.read(8))[0]
kc = struct.unpack('<Q', f.read(8))[0]

def rs():
    n = struct.unpack('<Q', f.read(8))[0]
    return f.read(n).decode('utf8', 'replace')

def rv(t):
    m = {0:('<B',1),1:('<b',1),2:('<H',2),3:('<h',2),4:('<I',4),5:('<i',4),
         6:('<f',4),7:('<?',1),10:('<Q',8),11:('<q',8),12:('<d',8)}
    if t in m:
        fmt, sz = m[t]
        return struct.unpack(fmt, f.read(sz))[0]
    if t == 8: return rs()
    if t == 9:
        et = struct.unpack('<I', f.read(4))[0]
        c = struct.unpack('<Q', f.read(8))[0]
        return [rv(et) for _ in range(c)]
    raise ValueError()

for _ in range(kc):
    rs(); t = struct.unpack('<I', f.read(4))[0]; rv(t)

actual = set()
for _ in range(tc):
    n = rs(); nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    struct.unpack('<I', f.read(4)); struct.unpack('<Q', f.read(8))
    actual.add(n)

print('actual GGUF tensors        :', len(actual))
print()
direct = expected & actual
print('EXACT NAME MATCHES         :', len(direct), '/', len(expected))
notfound = sorted(expected - actual)
print('expected but missing in GGUF:', len(notfound))
for x in notfound[:15]: print('   MISSING:', x)
extra = sorted(actual - expected)
print('in GGUF but not expected   :', len(extra))
for x in extra[:15]: print('   EXTRA  :', x)
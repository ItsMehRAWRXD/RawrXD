import re, struct

src = open(r'F:\rawrxd\src\deep2\modelgenie\TensorROM.generated.hpp',
           encoding='utf-8', errors='replace').read()
names = re.findall(r'"([^"]+)"', src)
names = [n for n in names if ('.' in n and ' ' not in n and len(n) > 6)]
expected = set(names)
print('quoted strings in TensorROM :', len(names))
print('distinct                    :', len(expected))

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
    n = rs()
    nd = struct.unpack('<I', f.read(4))[0]
    d = [struct.unpack('<Q', f.read(8))[0] for _ in range(nd)]
    struct.unpack('<I', f.read(4))
    struct.unpack('<Q', f.read(8))
    actual.add(n)

print('actual GGUF tensors        :', len(actual))
print()
direct = expected & actual
print('exact name matches         :', len(direct))

def found(e):
    for a in actual:
        if e == a: return True
        if a.endswith('.' + e): return True
        if e.endswith('.' + a): return True
    return False

contained = [e for e in expected if found(e)]
notfound = sorted(set(expected) - set(contained))
print('quoted strings found in GGUF names :', len(contained))
print('quoted strings NOT found           :', len(notfound))
for x in notfound[:20]:
    print('   NOT FOUND:', x)

# also: GGUF tensors with no quoted counterpart
missing_rom = []
for a in sorted(actual):
    if not any(a.endswith('.' + e) or e.endswith('.' + a) or e == a for e in expected):
        missing_rom.append(a)
print()
print('GGUF tensors with no TensorROM entry :', len(missing_rom))
for x in missing_rom[:25]:
    print('   ', x)

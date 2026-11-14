import struct, mmap

EXE = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
f = open(EXE, "rb")
m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
e = struct.unpack_from("<I", m, 0x3C)[0]
ns = struct.unpack_from("<H", m, e + 6)[0]
so = struct.unpack_from("<H", m, e + 20)[0]
ib = struct.unpack_from("<Q", m, e + 24 + 24)[0]
sect_off = e + 24 + so
sects = []
for i in range(ns):
    o = sect_off + i * 40
    name = bytes(m[o : o + 8]).split(b"\0")[0].decode()
    vs, va, rs, rw = struct.unpack_from("<IIII", m, o + 8)
    sects.append((name, va, vs, rw, rs))


def va2off(va):
    rva = va - ib
    for n, va0, vs, rw, rs in sects:
        if va0 <= rva < va0 + max(vs, rs):
            return rw + (rva - va0)
    return None


def dump(va, n=160):
    off = va2off(va)
    b = bytes(m[off : off + n])
    for i in range(0, len(b), 16):
        h = " ".join(f"{x:02X}" for x in b[i : i + 16])
        print(f"{va + i:016X}  {h}")


print("RESTORE_FN 0x141aeefe0")
dump(0x141aeefe0, 160)
print("EVICT_TAIL after printf")
dump(0x141aed496, 48)
text = sects[0]
tr, tsz = text[3], text[4]
last = tr + tsz - 1
while last > tr and m[last] in (0, 0xCC):
    last -= 1
print("last_nonzero_off", hex(last), "slack", hex(tr + tsz - 1 - last))
# padding between Evict ret and next fn
print("bytes after Evict success ret:")
dump(0x141aed4b0, 32)
m.close()
f.close()

import struct, mmap
EXE = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
TARGETS = [0x1AEEFFE0, 0x1AEF054, 0x1AED3D0, 0x1AED3F3, 0x1AED4E0]

f = open(EXE, "rb"); m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
e = struct.unpack_from("<I", m, 0x3C)[0]
ns = struct.unpack_from("<H", m, e + 6)[0]
so = struct.unpack_from("<H", m, e + 20)[0]
ib = struct.unpack_from("<Q", m, e + 24 + 24)[0]
sect_off = e + 24 + so
text = None
for i in range(ns):
    o = sect_off + i * 40
    name = bytes(m[o : o + 8]).split(b"\0")[0].decode()
    vs, va, rs, rw = struct.unpack_from("<IIII", m, o + 8)
    if name == ".text":
        text = (va, rw, rs)

va, rw, rs = text
want = set(TARGETS)
hits = {t: [] for t in TARGETS}
j = rw
end = rw + rs - 5
while j < end:
    if m[j] == 0xE8:
        rel = struct.unpack_from("<i", m, j + 1)[0]
        cur = va + (j - rw)
        tgt = (cur + 5 + rel) & 0xFFFFFFFF
        if tgt in want:
            hits[tgt].append(ib + cur)
    j += 1
for t, hs in hits.items():
    print(hex(ib + t), "N", len(hs), [hex(h) for h in hs[:15]])
m.close(); f.close()

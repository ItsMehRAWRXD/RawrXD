# Find E8 callers of Restore pdata begin; also scan for larger enclosing fn.
import struct, mmap, sys

EXE = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
RESTORE = 0x1AEF054  # rva
EVICT = 0x1AED3F3

def main():
    f = open(EXE, "rb")
    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    e = struct.unpack_from("<I", m, 0x3C)[0]
    ns = struct.unpack_from("<H", m, e + 6)[0]
    so = struct.unpack_from("<H", m, e + 20)[0]
    ib = struct.unpack_from("<Q", m, e + 24 + 24)[0]
    sect_off = e + 24 + so
    text = None
    pdata = None
    for i in range(ns):
        o = sect_off + i * 40
        name = bytes(m[o : o + 8]).split(b"\0")[0].decode()
        vs, va, rs, rw = struct.unpack_from("<IIII", m, o + 8)
        if name == ".text":
            text = (va, vs, rw, rs)
        if name == ".pdata":
            pdata = (va, vs, rw, rs)

    def callers(target_rva):
        va, vs, rw, rs = text
        hits = []
        j = rw
        end = rw + rs - 5
        while j < end:
            if m[j] == 0xE8:
                rel = struct.unpack_from("<i", m, j + 1)[0]
                cur = va + (j - rw)
                tgt = cur + 5 + rel
                if tgt == target_rva:
                    hits.append(ib + cur)
            j += 1
        return hits

    for label, rva in [("RESTORE", RESTORE), ("EVICT", EVICT)]:
        cs = callers(rva)
        print(label, "callers", len(cs), [hex(c) for c in cs[:20]])

    # list pdata entries near Restore
    pva, pvs, prw, prs = pdata
    n = prs // 12
    near = []
    for i in range(n):
        o = prw + i * 12
        begin, end, unwind = struct.unpack_from("<III", m, o)
        if abs(begin - RESTORE) < 0x2000:
            near.append((begin, end, end - begin))
    near.sort()
    print("PDATA_NEAR_RESTORE")
    for b, e2, sz in near:
        print(" ", hex(ib + b), hex(ib + e2), "sz", sz)

    m.close()
    f.close()

if __name__ == "__main__":
    main()

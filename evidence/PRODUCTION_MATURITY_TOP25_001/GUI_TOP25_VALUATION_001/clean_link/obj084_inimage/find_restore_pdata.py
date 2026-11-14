# Find real VRAMManager::Restore entry via .pdata covering Restored-string xref.
import struct, mmap, sys

EXE = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"

def main():
    f = open(EXE, "rb")
    m = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    e = struct.unpack_from("<I", m, 0x3C)[0]
    ns = struct.unpack_from("<H", m, e + 6)[0]
    so = struct.unpack_from("<H", m, e + 20)[0]
    ib = struct.unpack_from("<Q", m, e + 24 + 24)[0]
    sect_off = e + 24 + so
    sects = {}
    for i in range(ns):
        o = sect_off + i * 40
        name = bytes(m[o : o + 8]).split(b"\0")[0].decode()
        vs, va, rs, rw = struct.unpack_from("<IIII", m, o + 8)
        sects[name] = (va, vs, rw, rs)

    def off2rva(off):
        for va, vs, rw, rs in sects.values():
            if rw <= off < rw + rs:
                return va + (off - rw)
        return None

    def va2off(va_abs):
        rva = va_abs - ib
        for va, vs, rw, rs in sects.values():
            if va <= rva < va + max(vs, rs):
                return rw + (rva - va)
        return None

    def lea_xrefs(rva):
        va, vs, rw, rs = sects[".text"]
        hits = []
        j = rw
        end = rw + rs - 7
        while j < end:
            if m[j] in (0x48, 0x4C) and m[j + 1] == 0x8D and (m[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", m, j + 3)[0]
                tgt = (va + (j + 7 - rw)) + disp
                if tgt == rva:
                    hits.append(ib + va + (j - rw))
            j += 1
        return hits

    rest_off = m.find(b"[VRAMManager] Restored '%s'")
    rest_rva = off2rva(rest_off)
    xref = lea_xrefs(rest_rva)[0]
    xref_rva = xref - ib
    print("REST_XREF", hex(xref), "rva", hex(xref_rva))

    # .pdata: array of RUNTIME_FUNCTION {BeginAddress, EndAddress, UnwindInfo} RVAs dword each
    pva, pvs, prw, prs = sects[".pdata"]
    n = prs // 12
    hit = None
    for i in range(n):
        o = prw + i * 12
        begin, end, unwind = struct.unpack_from("<III", m, o)
        if begin <= xref_rva < end:
            hit = (begin, end, unwind)
            print("PDATA", hex(begin), hex(end), hex(unwind))
            break
    if not hit:
        print("NO_PDATA")
        return 1
    begin, end, unwind = hit
    print("RESTORE_FN", hex(ib + begin), "END", hex(ib + end), "SIZE", end - begin)
    boff = va2off(ib + begin)
    print("PROLOG", bytes(m[boff : boff + 48]).hex())

    # Also Evict pdata for first Evicted xref
    ev_off = m.find(b"[VRAMManager] Evicted '%s'")
    ev_x = lea_xrefs(off2rva(ev_off))[0]
    ev_rva = ev_x - ib
    for i in range(n):
        o = prw + i * 12
        begin, end, unwind = struct.unpack_from("<III", m, o)
        if begin <= ev_rva < end:
            print("EVICT_FN", hex(ib + begin), "END", hex(ib + end), "SIZE", end - begin)
            eoff = va2off(ib + begin)
            print("EVICT_PROLOG", bytes(m[eoff : eoff + 48]).hex())
            break

    m.close()
    f.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())

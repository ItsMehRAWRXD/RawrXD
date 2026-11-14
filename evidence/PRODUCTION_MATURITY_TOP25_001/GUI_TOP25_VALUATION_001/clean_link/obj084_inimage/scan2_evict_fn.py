# Find Evict fn via format-string xref; measure padding; plan overlay cave.
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
    sects = []
    for i in range(ns):
        o = sect_off + i * 40
        name = bytes(m[o : o + 8]).split(b"\0")[0].decode()
        vs, va, rs, rw = struct.unpack_from("<IIII", m, o + 8)
        sects.append((name, va, vs, rw, rs, o))

    def off2rva(off):
        for n, va, vs, rw, rs, _ in sects:
            if rw <= off < rw + rs:
                return va + (off - rw)
        return None

    def va2off(va):
        rva = va - ib
        for n, va0, vs, rw, rs, _ in sects:
            if va0 <= rva < va0 + max(vs, rs):
                return rw + (rva - va0)
        return None

    def lea_xrefs(rva):
        text = next(s for s in sects if s[0] == ".text")
        tr, tv, tsz = text[3], text[1], text[4]
        hits = []
        j = tr
        end = tr + tsz - 7
        while j < end:
            if m[j] in (0x48, 0x4C) and m[j + 1] == 0x8D and (m[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", m, j + 3)[0]
                tgt = (tv + (j + 7 - tr)) + disp
                if tgt == rva:
                    hits.append(ib + tv + (j - tr))
            j += 1
        return hits

    # Evicted format (with VRAMManager prefix nearby)
    needle = b"[VRAMManager] Evicted '%s'"
    off = m.find(needle)
    if off < 0:
        needle = b"Evicted '%s' (%zu bytes) from GPU"
        off = m.find(needle)
    print("EVICT_STR", needle, hex(off), hex(off2rva(off)))
    xr = lea_xrefs(off2rva(off))
    print("EVICT_XREFS", [hex(x) for x in xr])

    for xva in xr[:3]:
        xoff = va2off(xva)
        print("EVICT_CTX", hex(xva), bytes(m[xoff - 64 : xoff + 32]).hex())
        # walk back for prologue patterns: 40 55 / 48 89 5c / 48 83 ec / 55 48
        for back in range(0, 0x600):
            o = xoff - back
            b = bytes(m[o : o + 4])
            if b[:2] == b"\x40\x55" or b[:3] == b"\x48\x89\x5c" or b[:3] == b"\x48\x83\xec" or b[:2] == b"\x55\x48":
                # require prior CC or ret-ish
                if m[o - 1] in (0xCC, 0xC3, 0x00) or back > 16:
                    print("  PROLOG_CAND", hex(ib + off2rva(o)), "gap", back, b.hex())
                    if back < 0x200:
                        break

    rest = m.find(b"[VRAMManager] Restored '%s'")
    print("REST_STR", hex(rest), hex(off2rva(rest)))
    rx = lea_xrefs(off2rva(rest))
    print("REST_XREFS", [hex(x) for x in rx])
    for xva in rx[:2]:
        xoff = va2off(xva)
        print("REST_CTX", hex(xva), bytes(m[xoff - 80 : xoff + 16]).hex())
        for back in range(0, 0x600):
            o = xoff - back
            b = bytes(m[o : o + 5])
            if (b[0] == 0x40 and b[1] == 0x55) or b[:3] == b"\x48\x89\x5c" or b[:3] == b"\x48\x83\xec":
                if m[o - 1] in (0xCC, 0xC3):
                    print("  REST_PROLOG", hex(ib + off2rva(o)), "gap", back, bytes(m[o : o + 16]).hex())
                    break

    # padding: 00 runs and 90 runs in .text
    text = next(s for s in sects if s[0] == ".text")
    tr, tv, tsz = text[3], text[1], text[4]
    for padb, label in [(0x00, "ZERO"), (0x90, "NOP"), (0xCC, "INT3")]:
        best = (0, 0)
        run = 0
        rs = 0
        for j in range(tr, tr + tsz):
            if m[j] == padb:
                if run == 0:
                    rs = j
                run += 1
            else:
                if run > best[0]:
                    best = (run, rs)
                run = 0
        print(label, "BEST", best[0], "va", hex(ib + tv + (best[1] - tr)) if best[0] else None)

    # section alignment slack: VirtualSize vs SizeOfRawData
    for n, va, vs, rw, rs, ho in sects:
        slack = rs - vs if rs > vs else 0
        print("SECT", n, "VA", hex(va), "VSZ", hex(vs), "RSZ", hex(rs), "SLACK", slack)

    # PE overlay / end of file beyond last section
    last = max(rw + rs for _, _, _, rw, rs, _ in sects)
    print("FILE_LEN", len(m), "LAST_SECT_END", last, "OVERLAY", len(m) - last)
    m.close()
    f.close()

if __name__ == "__main__":
    main()

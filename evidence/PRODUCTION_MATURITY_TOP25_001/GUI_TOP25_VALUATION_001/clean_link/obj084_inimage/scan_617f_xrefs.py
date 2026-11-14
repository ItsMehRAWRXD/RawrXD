# Fast mmap PE string-xref scan for LOCKED 617F784E. PROMOTE=0.
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
        sects.append((name, va, vs, rw, rs))

    def off2rva(off):
        for n, va, vs, rw, rs in sects:
            if rw <= off < rw + rs:
                return va + (off - rw)
        return None

    def va2off(va):
        rva = va - ib
        for n, va0, vs, rw, rs in sects:
            if va0 <= rva < va0 + max(vs, rs):
                return rw + (rva - va0)
        return None

    def find_leas(needle):
        i = m.find(needle)
        if i < 0:
            return None, None, []
        rva = off2rva(i)
        hits = []
        text = next(s for s in sects if s[0] == ".text")
        tr, tv, tsz = text[3], text[1], text[4]
        j = tr
        end = tr + tsz - 7
        while j < end:
            if m[j] in (0x48, 0x4C) and m[j + 1] == 0x8D and (m[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", m, j + 3)[0]
                tgt = (tv + (j + 7 - tr)) + disp
                if tgt == rva:
                    hits.append(ib + tv + (j - tr))
            j += 1
        return i, rva, hits

    needles = [
        b"GENERATE_STREAM_ENTER=",
        b"Evicted 'token_embd",
        b"Allocated 'token_embd",
        b"[VRAMManager] Restored",
        b"TOKEN_EMBD_STREAM_RESTORE",
        b"token_embd.weight",
        b"PRODUCT_OPEN",
    ]
    for n in needles:
        off, rva, hits = find_leas(n)
        print(
            n.decode(errors="replace"),
            "off",
            hex(off) if off is not None else None,
            "rva",
            hex(rva) if rva else None,
            "n",
            len(hits),
            "xrefs",
            [hex(h) for h in hits[:10]],
        )

    # generateStream near GENERATE_STREAM_ENTER first xref
    _, _, gs = find_leas(b"GENERATE_STREAM_ENTER=")
    if not gs:
        print("NO_GS_XREF")
        return 1
    gs_va = gs[0]
    print("GS_XREF", hex(gs_va))
    # walk back for INT3 padding then prologue
    off = va2off(gs_va)
    fn = None
    for back in range(0, 0x1000):
        o = off - back
        if m[o] == 0xCC and m[o + 1] != 0xCC:
            fn = ib + (off2rva(o + 1))
            print("FN_CAND", hex(fn), "gap", back)
            break
    if fn is None:
        print("NO_FN")
        return 2
    foff = va2off(fn)
    print("PROLOGUE", bytes(m[foff : foff + 24]).hex())
    calls = []
    for k in range(0, 0x280):
        if m[foff + k] == 0xE8:
            rel = struct.unpack_from("<i", m, foff + k + 1)[0]
            tgt = fn + k + 5 + rel
            calls.append((fn + k, tgt))
    print("CALLS_FIRST20")
    for a, t in calls[:20]:
        print(" ", hex(a), "->", hex(t))
    # dump 64B at Evict format xref if present
    _, _, ev = find_leas(b"Evicted 'token_embd")
    if ev:
        eoff = va2off(ev[0])
        print("EVICT_XREF0", hex(ev[0]))
        print("EVICT_BYTES", bytes(m[eoff - 32 : eoff + 48]).hex())
    _, _, rs = find_leas(b"[VRAMManager] Restored")
    if rs:
        print("RESTORE_XREF0", hex(rs[0]))
        roff = va2off(rs[0])
        # walk back for function start of Restore
        for back in range(0, 0x800):
            o = roff - back
            if m[o] == 0xCC and m[o + 1] != 0xCC:
                print("RESTORE_FN_CAND", hex(ib + off2rva(o + 1)), "gap", back)
                break
    m.close()
    f.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())

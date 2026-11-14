# Locate Evict/Restore sites in LOCKED 617F + frozen restore for in-image inject.
# PROMOTE=0. mmap only; no PowerShell PE scans.
import struct, mmap, sys

LOCKED = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
FROZEN = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_frozen617_restore.exe"

def pe_map(path):
    f = open(path, "rb")
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
    return f, m, ib, sects

def off2rva(sects, off):
    for n, va, vs, rw, rs in sects:
        if rw <= off < rw + rs:
            return va + (off - rw)
    return None

def va2off(sects, ib, va):
    rva = va - ib
    for n, va0, vs, rw, rs in sects:
        if va0 <= rva < va0 + max(vs, rs):
            return rw + (rva - va0)
    return None

def lea_xrefs(m, sects, ib, needle):
    i = m.find(needle)
    if i < 0:
        return None, None, []
    rva = off2rva(sects, i)
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
    return i, rva, hits

def fn_before(m, sects, ib, va, limit=0x1000):
    off = va2off(sects, ib, va)
    for back in range(0, limit):
        o = off - back
        if m[o] == 0xCC and m[o + 1] != 0xCC:
            return ib + off2rva(sects, o + 1), back
    return None, None

def dump_around(m, sects, ib, va, before=64, after=96):
    off = va2off(sects, ib, va)
    chunk = bytes(m[off - before : off + after])
    base = va - before
    for i in range(0, len(chunk), 16):
        addr = base + i
        h = " ".join(f"{b:02X}" for b in chunk[i : i + 16])
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk[i : i + 16])
        print(f"  {addr:016X}  {h:<48}  {a}")

def analyze(label, path):
    print("====", label, path)
    f, m, ib, sects = pe_map(path)
    for n in [
        b"[VRAMManager] Evicted",
        b"[VRAMManager] Restored",
        b"TOKEN_EMBD_STREAM_RESTORE",
        b"GENERATE_STREAM_ENTER=",
        b"token_embd.weight",
    ]:
        off, rva, hits = lea_xrefs(m, sects, ib, n)
        print(n.decode(), "n", len(hits), "xrefs", [hex(h) for h in hits[:6]])
        if hits:
            fn, gap = fn_before(m, sects, ib, hits[0])
            print("  fn_cand", hex(fn) if fn else None, "gap", gap)
            if n.startswith(b"[VRAMManager] Evicted") or n.startswith(b"TOKEN_EMBD"):
                print("  around xref0:")
                dump_around(m, sects, ib, hits[0], 48, 80)
            if n.startswith(b"TOKEN_EMBD") and hits:
                # dump larger window toward fn start for restore block
                if fn:
                    print("  restore-block window from fn:")
                    dump_around(m, sects, ib, fn, 0, 256)
    # code cave candidates: runs of 0xCC in .text >= 128
    text = next(s for s in sects if s[0] == ".text")
    tr, tv, tsz = text[3], text[1], text[4]
    caves = []
    j = tr
    while j < tr + tsz:
        if m[j] == 0xCC:
            k = j
            while k < tr + tsz and m[k] == 0xCC:
                k += 1
            if k - j >= 128:
                caves.append((ib + tv + (j - tr), k - j))
            j = k
        else:
            j += 1
    print("CAVES>=128", len(caves), "first5", [(hex(a), n) for a, n in caves[:5]])
    m.close()
    f.close()

def main():
    analyze("LOCKED617F", LOCKED)
    analyze("FROZEN_RESTORE", FROZEN)
    return 0

if __name__ == "__main__":
    sys.exit(main())

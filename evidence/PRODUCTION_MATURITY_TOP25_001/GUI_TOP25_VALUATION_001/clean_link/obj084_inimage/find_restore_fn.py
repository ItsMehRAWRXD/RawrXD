# Find true VRAMManager::Restore / Evict prologues on LOCKED 617F.
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

def lea_xrefs(needle):
    i = m.find(needle)
    rva = off2rva(i)
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

def find_fn(va, limit=0x400):
    """Walk back for MSVC x64 prologue after INT3 run."""
    off = va2off(va)
    cands = []
    for back in range(0, limit):
        o = off - back
        # int3 then typical prologue: 40 53 / 48 89 / 48 8B / 4C 89 / 55
        if m[o] == 0xCC and m[o + 1] != 0xCC:
            p = bytes(m[o + 1 : o + 1 + 16])
            if p[0] in (0x40, 0x41, 0x48, 0x4C, 0x55, 0x53, 0x56, 0x57):
                cands.append((ib + off2rva(o + 1), back, p.hex()))
    return cands

for label, needle in [
    ("EVICT", b"[VRAMManager] Evicted"),
    ("RESTORE", b"[VRAMManager] Restored"),
]:
    hits = lea_xrefs(needle)
    print(label, "xref", hex(hits[0]))
    cands = find_fn(hits[0], 0x600)
    print("  prologue cands", len(cands))
    for va, gap, hx in cands[:12]:
        print(f"  {hex(va)} gap={gap} {hx}")

# Evict success epilogue site detail
ev = lea_xrefs(b"[VRAMManager] Evicted")[0]
off = va2off(ev)
print("EVICT_XREF_BYTES")
print(bytes(m[off - 16 : off + 48]).hex())
# Show 2nd xref too
print("EVICT_XREF1", hex(lea_xrefs(b"[VRAMManager] Evicted")[1]))
off1 = va2off(lea_xrefs(b"[VRAMManager] Evicted")[1])
print(bytes(m[off1 - 16 : off1 + 48]).hex())

# Search for pdata / typical Restore signature: cmp state EVICTED (3) early
# pattern from frozen: 83 F8 03 75  after mov eax,[reg+48]
restore_xref = lea_xrefs(b"[VRAMManager] Restored")[0]
roff = va2off(restore_xref)
# scan back 0x200 for 'cmp eax,3' / 'cmp dword,3'
for back in range(0, 0x300):
    o = roff - back
    if m[o] == 0x83 and m[o + 1] == 0xF8 and m[o + 2] == 0x03:  # cmp eax,3
        print("cmp eax,3 at", hex(ib + off2rva(o)), "back", back)
    if m[o] == 0x83 and m[o + 1] == 0x7B and m[o + 2] == 0x48 and m[o + 3] == 0x03:
        print("cmp [rbx+48],3 at", hex(ib + off2rva(o)), "back", back)

m.close()
f.close()

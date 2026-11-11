import struct
from pathlib import Path
exe = Path(r"F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe")
data = exe.read_bytes()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
coff = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff + 2)[0]
opt_size = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
exception_rva, exception_size = struct.unpack_from("<II", data, opt + 112 + 3 * 8)
sec_off = opt + opt_size
sections = []
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o+8)
    sections.append((name, va, vsize, rawptr, rawsize))
def rva_to_off(rva):
    for name, va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va), name
    return None, None
ex_off,_ = rva_to_off(exception_rva)
pdata = data[ex_off:ex_off+exception_size]
entries=[]
for i in range(0,len(pdata),12):
    b,e,_=struct.unpack_from("<III",pdata,i)
    entries.append((b,e))
entries.sort()
rvas=[0x119EB0,0x127AEF,0x119DF0,0x1275BF,0x2920,0x6147,0x1865,0x1D5330]
out=[]
out.append("IMAGE_BASE=0x140000000 SHA=F41BAFB8")
for r in rvas:
    hit=None
    for b,e in entries:
        if b<=r<e:
            hit=(b,e); break
    off,sec=rva_to_off(r)
    if hit:
        out.append(f"RVA=0x{r:X} SEC={sec} FUNC=[0x{hit[0]:X}..0x{hit[1]:X}) SIZE={hit[1]-hit[0]} FILEOFF=0x{off:X}")
    else:
        out.append(f"RVA=0x{r:X} SEC={sec} FUNC=NOT_IN_PDATA FILEOFF={off}")
# Also search for GhostText prop string and nearby xref sense
needle=b"RawrXD.GhostText"
idx=data.find(needle)
out.append(f"GHOSTTEXT_PROP_STRING_OFF=0x{idx:X}" if idx>=0 else "GHOSTTEXT_PROP_STRING=MISSING")
Path(r"F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs\rva_pdata_map_35440.txt").write_text("\n".join(out)+"\n",encoding="utf-8")
print("\n".join(out))

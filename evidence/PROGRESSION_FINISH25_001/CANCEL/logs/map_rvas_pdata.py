import struct
from pathlib import Path

exe = Path(r"F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe")
data = exe.read_bytes()
assert data[:2] == b"MZ"
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
assert data[e_lfanew : e_lfanew + 4] == b"PE\0\0"
coff = e_lfanew + 4
num_sections = struct.unpack_from("<H", data, coff + 2)[0]
opt_size = struct.unpack_from("<H", data, coff + 16)[0]
opt = coff + 20
magic = struct.unpack_from("<H", data, opt)[0]
assert magic == 0x20B
exception_rva, exception_size = struct.unpack_from("<II", data, opt + 112 + 3 * 8)
sec_off = opt + opt_size
sections = []
for i in range(num_sections):
    o = sec_off + i * 40
    name = data[o : o + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
    sections.append((name, va, vsize, rawptr, rawsize))


def rva_to_off(rva):
    for name, va, vsize, rawptr, rawsize in sections:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + (rva - va), name
    return None, None


ex_off, _ = rva_to_off(exception_rva)
pdata = data[ex_off : ex_off + exception_size]
entries = []
for i in range(0, len(pdata), 12):
    begin, end, _unwind = struct.unpack_from("<III", pdata, i)
    entries.append((begin, end))
entries.sort()

rvas = [
    0x119DF0,
    0x1275BF,
    0x2920,
    0x6147,
    0x1865,
    0x1D5330,
    0x1D5828,
    0x1D58A8,
    0x1D58B0,
    0x2450F0,
    0x1DE2F8,
    0x1DE990,
    0x246400,
]
print("IMAGE_BASE=0x140000000")
for r in rvas:
    hit = None
    for b, e in entries:
        if b <= r < e:
            hit = (b, e)
            break
    off, sec = rva_to_off(r)
    if hit:
        print(
            f"RVA=0x{r:X} SEC={sec} FUNC=[0x{hit[0]:X}..0x{hit[1]:X}) "
            f"SIZE={hit[1]-hit[0]} FILEOFF=0x{off:X}"
        )
    else:
        print(f"RVA=0x{r:X} SEC={sec} FUNC=NOT_IN_PDATA FILEOFF={off}")

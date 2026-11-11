# deepen_4ed_exception_context.py — sealed dump only; no cdb
import struct
from pathlib import Path

OUT = Path(r"F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs")
dump = (OUT / "RawrXD-Win32IDE-Native.exe.3976.dmp").read_bytes()
ns = struct.unpack_from("<I", dump, 8)[0]
soff = struct.unpack_from("<I", dump, 12)[0]
streams = [struct.unpack_from("<III", dump, soff + i * 12) for i in range(ns)]

exc = next(s for s in streams if s[0] == 6)
base = exc[2]
tid = struct.unpack_from("<I", dump, base)[0]
er = base + 8
code, flags = struct.unpack_from("<II", dump, er)
addr = struct.unpack_from("<Q", dump, er + 16)[0]
nparam = struct.unpack_from("<I", dump, er + 24)[0]
infos = [struct.unpack_from("<Q", dump, er + 32 + i * 8)[0] for i in range(min(nparam, 15))]
ctx_size, ctx_rva = struct.unpack_from("<II", dump, er + 152)
ctx = dump[ctx_rva : ctx_rva + ctx_size]
names = [
    "Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
    "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "Rip",
]
regs = {n: struct.unpack_from("<Q", ctx, 0x78 + i * 8)[0] for i, n in enumerate(names)}
eflags = struct.unpack_from("<I", ctx, 0x44)[0]
mxcsr = struct.unpack_from("<I", ctx, 0x34)[0]

mem = next(s for s in streams if s[0] == 5)
nrange = struct.unpack_from("<I", dump, mem[2])[0]
ranges = []
p = mem[2] + 4
for _ in range(nrange):
    start = struct.unpack_from("<Q", dump, p)[0]
    dsz, rva = struct.unpack_from("<II", dump, p + 8)
    ranges.append((start, dsz, rva))
    p += 16


def read_va(va, n):
    for start, dsz, rva in ranges:
        if start <= va < start + dsz:
            off = rva + (va - start)
            end = min(n, start + dsz - va)
            return dump[off : off + end]
    return None


EXE = 0x7FF6C1ED0000
COMCTL_V5 = 0x7FFEE3770000
pump = read_va(EXE + 0x127820, 0xD8)
fault = read_va(COMCTL_V5 + 0xBCF0, 64)

lines = []
lines.append("DEEPEN_4ED_EXCEPTION_CONTEXT")
lines.append("DUMP=RawrXD-Win32IDE-Native.exe.3976.dmp")
lines.append("SHA_LOCKED=4ED342CE")
lines.append(f"TID={tid}")
lines.append(f"CODE=0x{code:X} FLAGS=0x{flags:X} ADDR=0x{addr:X}")
lines.append("INFO=" + ",".join(f"0x{x:X}" for x in infos))
lines.append(f"EFlags=0x{eflags:X} MxCsr=0x{mxcsr:X}")
for n in names:
    lines.append(f"{n}=0x{regs[n]:X}")

# WinSxS v5.82 known path only
sx_path = Path(
    r"C:\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_5.82.26100.8328_none_87eede957a2ccddd\comctl32.dll"
)
sx = sx_path.read_bytes()
e = struct.unpack_from("<I", sx, 0x3C)[0]
nsec = struct.unpack_from("<H", sx, e + 6)[0]
opt = struct.unpack_from("<H", sx, e + 20)[0]
sec = e + 24 + opt


def rva_off(buf, rva):
    ee = struct.unpack_from("<I", buf, 0x3C)[0]
    n = struct.unpack_from("<H", buf, ee + 6)[0]
    opsz = struct.unpack_from("<H", buf, ee + 20)[0]
    s = ee + 24 + opsz
    for i in range(n):
        o = s + i * 40
        va, vsz, rawsz, rawptr = struct.unpack_from("<IIII", buf, o + 8)
        if va <= rva < va + max(vsz, rawsz):
            return rawptr + (rva - va)
    return None


off = rva_off(sx, 0xBCF0)
v582 = sx[off : off + 64]
lines.append("COMCTL32_FAULT_MODULE_BASE=0x7FFEE3770000")
lines.append("COMCTL32_FAULT_MODULE_SIZE=0xB5000")
lines.append("COMCTL32_VARIANT=WinSxS common-controls 5.82.26100.8328 (size-match + WER F41)")
lines.append(f"COMCTL32_V582_FILE_SIZE=0x{len(sx):X}")
lines.append(f"COMCTL32_V582_BYTES_AT_BCF0={v582.hex()}")
if fault is not None:
    (OUT / "comctl32_v5_bd00_from_dump_3976.bin").write_bytes(fault)
    lines.append(f"COMCTL32_DUMP_BYTES_AT_BCF0={fault.hex()}")
    lines.append(f"COMCTL32_DUMP_MATCHES_V582={fault == v582[: len(fault)]}")
else:
    lines.append("COMCTL32_DUMP_BYTES_AT_BCF0=NOT_IN_MEMORY_LIST")

# Instruction window at BD02
at = sx[rva_off(sx, 0xBD02) : rva_off(sx, 0xBD02) + 24]
lines.append(f"FAULTING_BYTES_AT_BD02={at.hex()}")
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for insn in md.disasm(at, 0xBD02):
        lines.append(f"DISASM_V582+0x{insn.address:X}: {insn.mnemonic} {insn.op_str}")
        if insn.address >= 0xBD20:
            break
except Exception as ex:
    lines.append(f"CAPSTONE=UNAVAILABLE ({type(ex).__name__})")
    # manual first opcode
    lines.append(f"OPCODE0_AT_BD02=0x{at[0]:02X}")

if pump is not None:
    (OUT / "func_127820_from_dump_3976.bin").write_bytes(pump)
    lines.append(f"PUMP_FUNC_BYTES_LEN={len(pump)}")
    lines.append(f"PUMP_FUNC_HEX={pump.hex()}")
    i = 0
    while i + 6 <= len(pump):
        if pump[i] == 0xFF and pump[i + 1] == 0x15:
            disp = struct.unpack_from("<i", pump, i + 2)[0]
            rip = 0x127820 + i + 6
            lines.append(f"PUMP_IAT_CALL RVA=0x{0x127820 + i:X} SLOT=0x{rip + disp:X}")
        if pump[i] == 0xE8:
            disp = struct.unpack_from("<i", pump, i + 1)[0]
            rip = 0x127820 + i + 5
            lines.append(f"PUMP_REL_CALL RVA=0x{0x127820 + i:X} DEST=0x{rip + disp:X}")
        i += 1
else:
    lines.append("PUMP_FUNC_BYTES=NOT_IN_MEMORY_LIST")

# Resolve IAT slots against tip EXE only as cross-check (label SHA separately)
exe_path = Path(r"F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe")
exe = exe_path.read_bytes()
import hashlib

tip_sha = hashlib.sha256(exe).hexdigest().upper()
lines.append(f"TIP_EXE_SHA256={tip_sha}")
lines.append("TIP_EXE_SHA_NOTE=NOT_4ED342CE — tip binary drifted; IAT names are cross-check only")

text = "\n".join(lines) + "\n"
(OUT / "exception_context_4ED342CE_deepened.txt").write_text(text, encoding="utf-8")
print(text)

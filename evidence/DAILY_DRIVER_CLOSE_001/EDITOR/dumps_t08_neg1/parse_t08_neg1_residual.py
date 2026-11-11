# parse_t08_neg1_residual.py — residual minidump parser (no cdb)
# Same approach as CANCEL CRASH_STACK_4ED342CE stack_parse_*.txt
import struct, hashlib
from pathlib import Path
from datetime import datetime, timezone

DUMP = Path(r"F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\procdump_r4_26936.dmp")
OUT_TXT = Path(r"F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\stack_parse_t08_neg1.txt")
OUT_MD = Path(r"F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\T08_NEG1_DUMP_PARSE.md")
EXE = Path(r"F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe")
FREEZE_SHA = "9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8"

STREAM_NAMES = {3:"ThreadList",4:"ModuleList",5:"MemoryList",6:"Exception",7:"SystemInfo",8:"ThreadExList",9:"Memory64List",10:"CommentA",11:"CommentW",12:"HandleData",13:"FunctionTable",14:"UnloadedModuleList",15:"MiscInfo",16:"MemoryInfoList",17:"ThreadInfoList",18:"HandleOperationList",19:"Token",20:"JavaScriptData",21:"SystemMemoryInfo",22:"ProcessVmCounters",24:"ThreadNames"}

dump = DUMP.read_bytes()
sig, ver = struct.unpack_from("<II", dump, 0)
ns = struct.unpack_from("<I", dump, 8)[0]
soff = struct.unpack_from("<I", dump, 12)[0]
assert sig == 0x504D444D, f"bad signature 0x{sig:X}"
streams = [struct.unpack_from("<III", dump, soff + i * 12) for i in range(ns)]
stream_ids = sorted({s[0] for s in streams})

def get_stream(typ):
    for t, dsz, drva in streams:
        if t == typ: return dsz, drva
    return None, None

def read_md_string(rva):
    if rva == 0 or rva >= len(dump): return ""
    n = struct.unpack_from("<I", dump, rva)[0]
    if n <= 0 or rva + 4 + n > len(dump): return ""
    return dump[rva+4:rva+4+n].decode("utf-16-le", errors="replace").rstrip("\x00")

modules = []
mod_dsz, mod_rva = get_stream(4)
if mod_rva is not None:
    count = struct.unpack_from("<I", dump, mod_rva)[0]
    p = mod_rva + 4
    for _ in range(count):
        base = struct.unpack_from("<Q", dump, p)[0]
        size = struct.unpack_from("<I", dump, p + 8)[0]
        name_rva = struct.unpack_from("<I", dump, p + 20)[0]
        name = read_md_string(name_rva)
        short = Path(name).name if name else "?"
        modules.append((base, size, short, name))
        p += 108

def resolve(va):
    for base, size, short, _ in modules:
        if base <= va < base + size:
            return f"{short}+0x{va-base:X}", short, va - base
    return f"0x{va:X}", None, None

ranges = []
def load_memory_list():
    global ranges
    dsz, rva = get_stream(9)
    if rva is not None:
        n = struct.unpack_from("<Q", dump, rva)[0]
        base_rva = struct.unpack_from("<Q", dump, rva + 8)[0]
        p = rva + 16
        cur = base_rva
        for _ in range(n):
            start = struct.unpack_from("<Q", dump, p)[0]
            dlen = struct.unpack_from("<Q", dump, p + 8)[0]
            ranges.append((start, dlen, cur))
            cur += dlen
            p += 16
        return "Memory64List"
    dsz, rva = get_stream(5)
    if rva is not None:
        n = struct.unpack_from("<I", dump, rva)[0]
        p = rva + 4
        for _ in range(n):
            start = struct.unpack_from("<Q", dump, p)[0]
            msz, mrva = struct.unpack_from("<II", dump, p + 8)
            ranges.append((start, msz, mrva))
            p += 16
        return "MemoryList"
    return "NONE"
mem_kind = load_memory_list()

def read_va(va, n):
    for start, dsz, rva in ranges:
        if start <= va < start + dsz:
            off = rva + (va - start)
            end = min(n, start + dsz - (va - start))
            if off < 0 or off + end > len(dump): return None
            return dump[off:off+end]
    return None

exc_present = False
exc_tid = exc_code = exc_flags = exc_addr = None
exc_infos = []
exc_regs = {}
exc_dsz, exc_rva = get_stream(6)
if exc_rva is not None and exc_dsz and exc_dsz > 0:
    tid = struct.unpack_from("<I", dump, exc_rva)[0]
    er = exc_rva + 8
    code, flags = struct.unpack_from("<II", dump, er)
    addr = struct.unpack_from("<Q", dump, er + 16)[0]
    nparam = struct.unpack_from("<I", dump, er + 24)[0]
    if code != 0 or addr != 0 or tid != 0:
        exc_present = True
        exc_tid, exc_code, exc_flags, exc_addr = tid, code, flags, addr
        for i in range(min(nparam, 15)):
            exc_infos.append(struct.unpack_from("<Q", dump, er + 32 + i * 8)[0])
        ctx_size, ctx_rva = struct.unpack_from("<II", dump, er + 152)
        if ctx_rva and ctx_size >= 0x78 + 17 * 8:
            ctx = dump[ctx_rva:ctx_rva+ctx_size]
            names = ["Rax","Rcx","Rdx","Rbx","Rsp","Rbp","Rsi","Rdi","R8","R9","R10","R11","R12","R13","R14","R15","Rip"]
            exc_regs = {n: struct.unpack_from("<Q", ctx, 0x78 + i * 8)[0] for i, n in enumerate(names)}

threads = []
thr_dsz, thr_rva = get_stream(3)
if thr_rva is not None:
    tcount = struct.unpack_from("<I", dump, thr_rva)[0]
    p = thr_rva + 4
    for _ in range(tcount):
        tid = struct.unpack_from("<I", dump, p)[0]
        suspend = struct.unpack_from("<I", dump, p + 4)[0]
        teb = struct.unpack_from("<Q", dump, p + 16)[0]
        stack_start = struct.unpack_from("<Q", dump, p + 24)[0]
        stack_dsz, stack_rva = struct.unpack_from("<II", dump, p + 32)
        ctx_dsz, ctx_rva = struct.unpack_from("<II", dump, p + 40)
        rip = rsp = rbp = None
        regs = {}
        if ctx_rva and ctx_dsz >= 0x78 + 17 * 8:
            ctx = dump[ctx_rva:ctx_rva+ctx_dsz]
            rax = struct.unpack_from("<Q", ctx, 0x78)[0]
            rcx = struct.unpack_from("<Q", ctx, 0x80)[0]
            rdx = struct.unpack_from("<Q", ctx, 0x88)[0]
            rbx = struct.unpack_from("<Q", ctx, 0x90)[0]
            rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
            rbp = struct.unpack_from("<Q", ctx, 0xA0)[0]
            rip = struct.unpack_from("<Q", ctx, 0xF8)[0]
            regs = {"Rax":rax,"Rcx":rcx,"Rdx":rdx,"Rbx":rbx,"Rsp":rsp,"Rbp":rbp,"Rip":rip}
        threads.append({"tid":tid,"suspend":suspend,"teb":teb,"stack_start":stack_start,"stack_dsz":stack_dsz,"stack_rva":stack_rva,"rip":rip,"rsp":rsp,"rbp":rbp,"regs":regs})
        p += 48

def scan_stack(thr, max_frames=64):
    frames = []
    rip = thr["rip"]; rsp = thr["rsp"]
    if rip is not None:
        lab,_,_ = resolve(rip)
        frames.append(("RIP", lab, 0, rip))
    if rsp is None: return frames, "NO_RSP", False
    stack_bytes = read_va(rsp, 0x4000)
    rsp_in_mem = stack_bytes is not None
    mode = "RSP_DIRECT"
    if stack_bytes is None and thr["stack_rva"] and thr["stack_dsz"]:
        ss = thr["stack_start"]
        if ss <= rsp < ss + thr["stack_dsz"]:
            off = thr["stack_rva"] + (rsp - ss)
            n = min(0x4000, thr["stack_dsz"] - (rsp - ss))
            if off + n <= len(dump):
                stack_bytes = dump[off:off+n]
                rsp_in_mem = True
                mode = "THREAD_STACK_MEMORY"
    if stack_bytes is None: return frames, "STACK_UNMAPPED", False
    seen = set()
    for i in range(0, len(stack_bytes) - 7, 8):
        va = struct.unpack_from("<Q", stack_bytes, i)[0]
        lab, short, rva = resolve(va)
        if short is None or rva == 0: continue
        key = (va, i)
        if key in seen: continue
        seen.add(key)
        frames.append(("RET", lab, i, va))
        if len(frames) >= max_frames: break
    return frames, mode, rsp_in_mem

primary = None
if exc_present and exc_tid is not None:
    primary = next((t for t in threads if t["tid"] == exc_tid), None)
if primary is None:
    for t in threads:
        if t["rip"] is not None:
            _, short, _ = resolve(t["rip"])
            if short and "RawrXD" in short:
                primary = t; break
if primary is None and threads:
    primary = threads[0]

primary_frames = []; scan_mode = "N/A"; rsp_in = False
if primary:
    primary_frames, scan_mode, rsp_in = scan_stack(primary)
product_frames = [f for f in primary_frames if "RawrXD" in f[1]]
last_pc = last_pc_lab = None
if primary and primary["rip"] is not None:
    last_pc = primary["rip"]; last_pc_lab,_,_ = resolve(last_pc)
elif exc_present and exc_addr is not None:
    last_pc = exc_addr; last_pc_lab,_,_ = resolve(last_pc)

key_names = ("RawrXD","comctl32","user32","ntdll","kernel32","KERNELBASE","riched20","msctf","gdi32","ole32","imm32","win32u","msvcp","vcruntime")
key_mods = [(short,base,size) for base,size,short,full in modules if any(k.lower() in short.lower() for k in key_names)]
exe_sha = hashlib.sha256(EXE.read_bytes()).hexdigest().upper() if EXE.exists() else "MISSING"
sha_match = exe_sha == FREEZE_SHA
causality_proven = 0
tip_fix = "NOT_APPLIED"

lines = []
lines.append("T08_NEG1_NATIVE_STACK_RESIDUAL_PARSE")
lines.append(f"Dump={DUMP}")
lines.append(f"DumpSize={len(dump)}")
lines.append(f"Signature=0x{sig:X} Version=0x{ver:X}")
lines.append(f"Streams={','.join(str(x) for x in stream_ids)}")
lines.append(f"StreamNames={','.join(STREAM_NAMES.get(x,str(x)) for x in stream_ids)}")
lines.append(f"ThreadCount={len(threads)}")
lines.append(f"ModuleCount={len(modules)}")
lines.append(f"MemoryKind={mem_kind} MemoryRanges={len(ranges)}")
lines.append(f"FREEZE_SHA={FREEZE_SHA}")
lines.append(f"EXE_SHA256={exe_sha}")
lines.append(f"SHA_MATCH={sha_match}")
lines.append("MARKER_SHA_0F054F01_CONFLATED=0")
lines.append(f"ExceptionStreamPresent={int(exc_present)}")
if exc_present:
    lines.append(f"ExceptionThreadId={exc_tid}")
    lines.append(f"ExceptionCode=0x{exc_code:X}")
    lines.append(f"ExceptionFlags=0x{exc_flags:X}")
    elab,_,_ = resolve(exc_addr)
    lines.append(f"ExceptionAddress=0x{exc_addr:X} ({elab})")
    for i, info in enumerate(exc_infos):
        lines.append(f"ExceptionInformation[{i}]=0x{info:X}")
    for n,v in exc_regs.items():
        lines.append(f"Context.{n}=0x{v:X}")
else:
    lines.append("ExceptionStream=ABSENT_OR_EMPTY (procdump -t TERMINATE expected)")
lines.append("")
lines.append("=== Threads (tid, RIP, Rsp, module) ===")
for t in threads:
    rip = t["rip"]
    if rip is None:
        lines.append(f"  tid={t['tid']} RIP=NONE stack=0x{t['stack_start']:X}+0x{t['stack_dsz']:X}")
        continue
    lab, short, rva = resolve(rip)
    lines.append(f"  tid={t['tid']} RIP={lab} Rsp=0x{t['rsp']:X} Rbp=0x{t['rbp']:X} stack=0x{t['stack_start']:X}+0x{t['stack_dsz']:X} teb=0x{t['teb']:X}")
lines.append("")
lines.append("=== Key modules ===")
for short, base, size in sorted(key_mods, key=lambda x: x[0].lower()):
    lines.append(f"{short} base=0x{base:X} size=0x{size:X}")
if primary:
    lines.append("")
    lines.append(f"=== Primary thread tid={primary['tid']} ===")
    lines.append(f"LastPC=0x{last_pc:X} ({last_pc_lab})" if last_pc else "LastPC=NONE")
    lines.append(f"FaultingThread.StackStart=0x{primary['stack_start']:X} Size=0x{primary['stack_dsz']:X} FileRva=0x{primary['stack_rva']:X}")
    lines.append(f"RspInThreadStackMemory={rsp_in}")
    lines.append(f"StackScanMode={scan_mode}")
    lines.append("")
    lines.append("=== Stack (RIP + module-mapped RET candidates from RSP) ===")
    for i,(kind,lab,off,va) in enumerate(primary_frames):
        if kind == "RIP": lines.append(f"  [{i:2d}] RIP  {lab}")
        else: lines.append(f"  [{i:2d}] RET  {lab}  (rsp+0x{off:X})")
    lines.append("")
    lines.append("=== Product frames (RawrXD*) ===")
    if product_frames:
        for kind,lab,off,va in product_frames:
            lines.append(f"  {kind} {lab} rsp+0x{off:X}")
    else:
        lines.append("  NONE")
lines.append("")
lines.append("=== Disposition ===")
lines.append("DUMP_KIND=procdump_-t_TERMINATE")
lines.append(f"EXCEPTION_YES_NO={'yes' if exc_present else 'no'}")
lines.append(f"CAUSALITY_PROVEN={causality_proven}")
lines.append(f"TIP_FIX={tip_fix}")
lines.append("OWNERSHIP_LIFETIME_PROVEN=0")
lines.append("PROMOTE=0")
lines.append("STOP_SPECULATIVE_EDITOR_BATCH=1")
lines.append("CDB=NOT_USED AVOID_RECURSIVE_CDB_SEARCH=1")
text = "\n".join(lines) + "\n"
OUT_TXT.write_text(text, encoding="utf-8")
print(text)

asof = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
md = []
md.append("# T08_NEG1_DUMP_PARSE — residual terminate dump")
md.append("")
md.append(f"ASOF_UTC={asof}")
md.append(f"FREEZE_SHA={FREEZE_SHA}")
md.append(f"EXE_SHA256={exe_sha}")
md.append(f"SHA_MATCH={int(sha_match)}")
md.append("MARKER_SHA_0F054F01_CONFLATED=0")
md.append(f"DUMP={DUMP}")
md.append(f"DUMP_SIZE={len(dump)}")
md.append("DUMP_KIND=procdump_-t_TERMINATE")
md.append(f"PARSE_TXT={OUT_TXT}")
md.append("PARSER=residual_minidump (CANCEL CRASH_STACK_4ED342CE approach; no cdb)")
md.append("PROMOTE=0")
md.append("STOP_SPECULATIVE_EDITOR_BATCH=1")
md.append("")
md.append("## Streams")
md.append("")
md.append("```")
md.append(f"Streams={','.join(str(x) for x in stream_ids)}")
md.append(f"ThreadCount={len(threads)}")
md.append(f"ModuleCount={len(modules)}")
md.append(f"MemoryKind={mem_kind} Ranges={len(ranges)}")
md.append(f"ExceptionStreamPresent={int(exc_present)}")
md.append("```")
md.append("")
md.append("## Exception")
md.append("")
if exc_present:
    elab,_,_ = resolve(exc_addr)
    md.append("- EXCEPTION=**yes**")
    md.append(f"- ThreadId={exc_tid}")
    md.append(f"- Code=0x{exc_code:X}")
    md.append(f"- Address=0x{exc_addr:X} ({elab})")
else:
    md.append("- EXCEPTION=**no** (stream absent/empty; consistent with procdump `-t` TERMINATE)")
md.append("")
md.append("## Last PC / primary thread")
md.append("")
if primary:
    md.append(f"- PrimaryTid={primary['tid']}")
    md.append(f"- LastPC=`{last_pc_lab}` (0x{last_pc:X})" if last_pc else "- LastPC=NONE")
    md.append(f"- Rsp=0x{primary['rsp']:X}" if primary['rsp'] is not None else "- Rsp=NONE")
    md.append(f"- StackScanMode={scan_mode}")
    md.append(f"- RspInMappedMemory={rsp_in}")
else:
    md.append("- PrimaryThread=NONE")
md.append("")
md.append("## Product frames")
md.append("")
if product_frames:
    md.append("```")
    for kind,lab,off,va in product_frames[:32]:
        md.append(f"{kind} {lab} rsp+0x{off:X}")
    md.append("```")
else:
    md.append("NONE on primary residual stack scan.")
md.append("")
md.append("## Key modules (abbrev)")
md.append("")
md.append("```")
for short, base, size in sorted(key_mods, key=lambda x: x[0].lower())[:24]:
    md.append(f"{short} base=0x{base:X} size=0x{size:X}")
md.append("```")
md.append("")
md.append("## Threads summary")
md.append("")
md.append("| Tid | RIP | Module |")
md.append("|-----|-----|--------|")
for t in threads:
    if t["rip"] is None:
        md.append(f"| {t['tid']} | NONE | — |")
    else:
        lab, short, _ = resolve(t["rip"])
        md.append(f"| {t['tid']} | `{lab}` | {short or '?'} |")
md.append("")
md.append("## Disposition (fail-closed)")
md.append("")
md.append("```")
md.append(f"EXCEPTION_YES_NO={'yes' if exc_present else 'no'}")
md.append(f"CAUSALITY_PROVEN={causality_proven}")
md.append("OWNERSHIP_LIFETIME_PROVEN=0")
md.append(f"TIP_FIX={tip_fix}")
md.append("TIP_FIX_YES_NO=no")
md.append("PROMOTE=0")
md.append("WER_EXCEPTION_DUMP=NONE_THIS_CAPTURE")
md.append("NEXT_GATE=CATCH_EXCEPTION_DUMP_BEFORE_DEATH (-e -ma / LocalDumps re-stress)")
md.append("```")
md.append("")
md.append("Do not conflate MARKER_SHA 0F054F01. Do not invent PASS.")
OUT_MD.write_text("\n".join(md)+"\n", encoding="utf-8")
print(f"SEALED_MD={OUT_MD}")
print(f"SEALED_TXT={OUT_TXT}")

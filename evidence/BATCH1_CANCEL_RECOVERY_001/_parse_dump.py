import struct
import sys
from pathlib import Path

path = Path(r"C:\Users\Garrett\AppData\Local\RawrXD\crashes\rawrxd-20261103-004332.dmp")
data = path.read_bytes()
sig, ver, stream_count, stream_rva, checksum, timestamp, flags = struct.unpack_from(
    "<IIIIIII", data, 0
)
print(f"sig={sig:08X} ver={ver} streams={stream_count} stream_rva={stream_rva} flags={flags}")

ExceptionStream = 6
ThreadListStream = 3
ModuleListStream = 4
MemoryListStream = 5
SystemInfoStream = 7

for i in range(stream_count):
    off = stream_rva + i * 12
    stype, size, rva = struct.unpack_from("<III", data, off)
    name = {
        3: "ThreadList",
        4: "ModuleList",
        5: "MemoryList",
        6: "Exception",
        7: "SystemInfo",
        15: "Memory64List",
    }.get(stype, str(stype))
    print(f"stream[{i}] type={name} size={size} rva={rva}")
    if stype == ExceptionStream:
        # MINIDUMP_EXCEPTION_STREAM
        thread_id, _align, code, flags_e, record, address, nparams, _a2 = struct.unpack_from(
            "<IIIIQQII", data, rva
        )
        print(f"  thread_id={thread_id} code=0x{code:08X} flags=0x{flags_e:X} addr=0x{address:016X} nparams={nparams}")
        params = struct.unpack_from("<" + "Q" * min(nparams, 15), data, rva + 32) if nparams else ()
        print(f"  params={['0x%X' % p for p in params]}")
        # CONTEXT follows via ThreadContext Directory? Exception stream has ThreadContext MINIDUMP_LOCATION_DESCRIPTOR
        # After EXCEPTION_RECORD64 (152 bytes?) layout:
        # ULONG32 ThreadId; ULONG32 __alignment; MINIDUMP_EXCEPTION Exception; MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
        # MINIDUMP_EXCEPTION is 152 bytes on x64 (code+flags+record+addr+nparams+align+15*QWORD)
        ctx_size, ctx_rva = struct.unpack_from("<II", data, rva + 4 + 4 + 152)
        print(f"  context size={ctx_size} rva={ctx_rva}")
        if ctx_size >= 0x4D0 and ctx_rva + 0x4D0 <= len(data):
            # AMD64_CONTEXT: Rip at offset 0xF8
            rip = struct.unpack_from("<Q", data, ctx_rva + 0xF8)[0]
            rsp = struct.unpack_from("<Q", data, ctx_rva + 0x98)[0]
            rbp = struct.unpack_from("<Q", data, ctx_rva + 0xA0)[0]
            rax = struct.unpack_from("<Q", data, ctx_rva + 0x78)[0]
            rcx = struct.unpack_from("<Q", data, ctx_rva + 0x80)[0]
            rdx = struct.unpack_from("<Q", data, ctx_rva + 0x88)[0]
            print(f"  RIP=0x{rip:016X} RSP=0x{rsp:016X} RBP=0x{rbp:016X}")
            print(f"  RAX=0x{rax:016X} RCX=0x{rcx:016X} RDX=0x{rdx:016X}")
    if stype == ModuleListStream:
        nmod = struct.unpack_from("<I", data, rva)[0]
        print(f"  modules={nmod}")
        # print first few + find RawrXD
        base = rva + 4
        for m in range(min(nmod, 80)):
            # MINIDUMP_MODULE is 108 bytes
            mo = base + m * 108
            base_of_image, size_of_image = struct.unpack_from("<QI", data, mo)
            name_rva = struct.unpack_from("<I", data, mo + 24)[0]
            # MINIDUMP_STRING
            nchars = struct.unpack_from("<I", data, name_rva)[0]
            name_s = data[name_rva + 4 : name_rva + 4 + nchars * 2].decode("utf-16le", "replace")
            if "RawrXD" in name_s or "rawrxd" in name_s.lower() or m < 3:
                print(f"    [{m}] base=0x{base_of_image:016X} size=0x{size_of_image:X} {name_s}")

# Also dump readable strings mentioning Win32 / Ollama / crash
ascii = "".join(chr(b) if 32 <= b < 127 else "\n" for b in data)
for key in (
    "Win32IDE",
    "generateOllama",
    "HandleCopilot",
    "AgentStep",
    "access violation",
    "Access violation",
    "EXCEPTION_ACCESS",
    "std::",
    "abort",
):
    if key.lower() in ascii.lower():
        print("string-hit:", key)

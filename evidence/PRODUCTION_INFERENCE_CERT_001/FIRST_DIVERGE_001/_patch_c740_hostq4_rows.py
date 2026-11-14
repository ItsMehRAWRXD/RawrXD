# Patch C7402085 DispatchGEMVQuant: host Q4 when rows>cols under FORCE.
# PROMOTE=0 — produces pin/rawr_ffn_act2_hostq4.exe (gitignored *.exe).
import struct, hashlib, shutil, sys

SRC = r"G:\~dev\rawrxd\build_ninja\bin\rawr_gpufwd_C7402085.exe"
DST = r"G:\~dev\rawrxd\build_ninja\bin\rawr_gpufwd_ffn_act2_hostq4.exe"
PIN = (
    r"G:\~dev\rawrxd\evidence\PRODUCTION_INFERENCE_CERT_001"
    r"\FIRST_DIVERGE_001\pin\rawr_ffn_act2_hostq4.exe"
)
EXPECT_C740 = "C74020852AC324FC6827A896060E5508F74569C7F53EB7198B9CDB92DEAEB750"


def main():
    data = bytearray(open(SRC, "rb").read())
    h0 = hashlib.sha256(data).hexdigest().upper()
    if h0 != EXPECT_C740:
        print("C740_SHA_MISMATCH", h0)
        return 2
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    opt = coff + 20
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    sec_off = opt + size_opt
    _vsz, va, _rsz, raw = struct.unpack_from("<IIII", data, sec_off + 8)

    def rva2off(rva):
        return raw + (rva - va)

    seq = bytes.fromhex("4885c074098038310f84f3000000")
    force_off = data.find(seq)
    if force_off < 0:
        print("FORCE_SEQ_MISSING")
        return 3
    force_rva = va + (force_off - raw)
    host_ok = force_rva + 14
    skip_host = host_ok + 0xF3
    cave_rva = 0x465540
    cave_off = rva2off(cave_rva)
    tramp = bytearray()
    tramp += b"\x41\x3B\xEE"  # cmp r13d,r14d (rows,cols)
    tramp += b"\x7F\x0A"  # jg host
    tramp += b"\x48\x85\xC0"  # test force
    tramp += b"\x74\x05"  # jz host
    tramp += b"\x80\x38\x31"  # cmp [rax],'1'
    tramp += b"\x74\x05"  # je skip
    tramp += b"\xE9" + struct.pack("<i", host_ok - (cave_rva + 15 + 5))
    tramp += b"\xE9" + struct.pack("<i", skip_host - (cave_rva + 20 + 5))
    if not all(b in (0, 0xCC) for b in data[cave_off : cave_off + len(tramp)]):
        print("CAVE_DIRTY")
        return 4
    data[cave_off : cave_off + len(tramp)] = tramp
    rel = cave_rva - (force_rva + 5)
    patch = b"\xE9" + struct.pack("<i", rel) + b"\x90" * 9
    data[force_off : force_off + 14] = patch
    open(DST, "wb").write(data)
    shutil.copy2(DST, PIN)
    print("SHA256", hashlib.sha256(data).hexdigest().upper())
    print("PROMOTE=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())

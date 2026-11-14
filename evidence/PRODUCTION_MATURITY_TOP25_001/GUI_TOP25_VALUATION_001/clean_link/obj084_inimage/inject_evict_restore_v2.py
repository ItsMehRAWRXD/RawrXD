# v2: TELEMETR EXEC|READ (no WRITE). Modes: epilogue_only | restore_noprint | restore_full
import struct, hashlib, sys

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F_inimage_restore.exe"
EXPECT_SRC = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"
IB = 0x140000000
EVICT_TAIL_VA = 0x141AED496
RESTORE_VA = 0x141AEEFE0
TELEMETR_VA = 0x140AB0000
MODE = sys.argv[1] if len(sys.argv) > 1 else "restore_noprint"


def pe_sects(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e + 6)[0]
    so = struct.unpack_from("<H", data, e + 20)[0]
    sect_off = e + 24 + so
    sects = []
    for i in range(ns):
        o = sect_off + i * 40
        name = bytes(data[o : o + 8]).split(b"\0")[0].decode()
        vs, va, rs, rw = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        sects.append({"name": name, "va": va, "vs": vs, "rs": rs, "rw": rw, "ch": ch, "off": o})
    return sects


def va2off(sects, va):
    rva = va - IB
    for s in sects:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["rw"] + (rva - s["va"])
    raise ValueError(hex(va))


def main():
    raw = open(SRC, "rb").read()
    if hashlib.sha256(raw).hexdigest().upper() != EXPECT_SRC:
        raise SystemExit("SRC_HASH_MISMATCH")
    data = bytearray(raw)
    sects = pe_sects(data)
    tele = next(s for s in sects if s["name"].startswith("TELEMETR"))
    # CODE|EXEC|READ — no WRITE (W^X friendly)
    struct.pack_into("<I", data, tele["off"] + 36, 0x60000020)

    cave_va = TELEMETR_VA
    code = bytearray()
    if MODE == "epilogue_only":
        pass
    else:
        # name size == 17
        code += bytes.fromhex("48837B2011")
        jne0 = len(code)
        code += bytes.fromhex("7500")
        code += bytes.fromhex("488B4308")
        code += b"\x48\xB9" + b"token_em"
        code += bytes.fromhex("483908")
        jne1 = len(code)
        code += bytes.fromhex("7500")
        code += b"\x48\xB9" + b"bd.weigh"
        code += bytes.fromhex("48394808")
        jne2 = len(code)
        code += bytes.fromhex("7500")
        code += bytes.fromhex("80781074")
        jne3 = len(code)
        code += bytes.fromhex("7500")
        # Restore(this=rdi, lease=rbx, gpu=0)
        code += bytes.fromhex("488BCF488BD34533C0")
        call_at = len(code)
        code += b"\xE8\x00\x00\x00\x00"
        code += bytes.fromhex("C6434501")  # pinned=1
        if MODE == "restore_full":
            msg = b"TOKEN_EMBD_STREAM_RESTORE=1\n\0"
            msg_va = cave_va + 0x100
            data[va2off(sects, msg_va) : va2off(sects, msg_va) + len(msg)] = msg
            printf_rel = struct.unpack("<i", bytes.fromhex("3BCD62FE"))[0]
            printf_va = 0x141AED496 + printf_rel
            lea_at = len(code)
            code += b"\x48\x8D\x0D\x00\x00\x00\x00"
            callp = len(code)
            code += b"\xE8\x00\x00\x00\x00"
            skip = len(code)
            struct.pack_into("<i", code, lea_at + 3, msg_va - (cave_va + lea_at + 7))
            struct.pack_into("<i", code, callp + 1, printf_va - (cave_va + callp + 5))
        else:
            skip = len(code)
        for site in (jne0, jne1, jne2, jne3):
            code[site + 1] = (skip - (site + 2)) & 0xFF
        struct.pack_into("<i", code, call_at + 1, RESTORE_VA - (cave_va + call_at + 5))

    # epilogue
    code += bytes.fromhex("8B742438B001488B6C24304C8B742440488B5C24484883C4205FC3")
    cave_off = va2off(sects, cave_va)
    data[cave_off : cave_off + len(code)] = code

    tramp = bytearray(b"\xE9\x00\x00\x00\x00")
    struct.pack_into("<i", tramp, 1, cave_va - (EVICT_TAIL_VA + 5))
    tail_off = va2off(sects, EVICT_TAIL_VA)
    data[tail_off : tail_off + 5] = tramp
    for i in range(5, 27):
        data[tail_off + i] = 0xCC

    open(DST, "wb").write(data)
    h = hashlib.sha256(data).hexdigest().upper()
    print("MODE", MODE)
    print("DST_SHA256", h)
    print("CAVE_LEN", len(code))
    meta = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj084_inimage\INIMAGE_BUILD.txt"
    open(meta, "w", encoding="utf-8").write(
        f"MODE={MODE}\nDST_SHA256={h}\nCAVE_VA={cave_va:X}\nRESTORE_VA={RESTORE_VA:X}\nPROMOTE=0\n"
    )


if __name__ == "__main__":
    main()

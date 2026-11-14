# v3: fix epilogue mov rsi (REX.W). Restore+pin after token_embd Evict.
import struct, hashlib, sys

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F_inimage_restore.exe"
EXPECT_SRC = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"
IB = 0x140000000
EVICT_TAIL_VA = 0x141AED496
RESTORE_VA = 0x141AEEFE0
TELEMETR_VA = 0x140AB0000
MODE = sys.argv[1] if len(sys.argv) > 1 else "restore_full"
# Correct original epilogue (includes REX.W on mov rsi)
EPILOGUE = bytes.fromhex(
    "488B742438"  # mov rsi, [rsp+38h]
    "B001"  # mov al, 1
    "488B6C2430"  # mov rbp, [rsp+30h]
    "4C8B742440"  # mov r14, [rsp+40h]
    "488B5C2448"  # mov rbx, [rsp+48h]
    "4883C420"  # add rsp, 20h
    "5F"  # pop rdi
    "C3"  # ret
)


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
    struct.pack_into("<I", data, tele["off"] + 36, 0x60000020)

    cave_va = TELEMETR_VA
    code = bytearray()
    if MODE != "epilogue_only":
        # std::string at lease+8: size at +0x10 → lease+0x18; capacity at lease+0x20
        code += bytes.fromhex("48837B1811")  # cmp [rbx+18h], 11h (name.size==17)
        j0 = len(code)
        code += bytes.fromhex("7500")
        code += bytes.fromhex("488B4308")
        code += b"\x48\xB9" + b"token_em"
        code += bytes.fromhex("483908")
        j1 = len(code)
        code += bytes.fromhex("7500")
        code += b"\x48\xB9" + b"bd.weigh"
        code += bytes.fromhex("48394808")
        j2 = len(code)
        code += bytes.fromhex("7500")
        code += bytes.fromhex("80781074")
        j3 = len(code)
        code += bytes.fromhex("7500")
        code += bytes.fromhex("488BCF488BD34533C0")
        call_at = len(code)
        code += b"\xE8\x00\x00\x00\x00"
        code += bytes.fromhex("C6434501")
        if MODE == "restore_full":
            msg = b"TOKEN_EMBD_STREAM_RESTORE=1\n\0"
            msg_va = cave_va + 0x100
            data[va2off(sects, msg_va) : va2off(sects, msg_va) + len(msg)] = msg
            printf_va = 0x141AED496 + struct.unpack("<i", bytes.fromhex("3BCD62FE"))[0]
            lea_at = len(code)
            code += b"\x48\x8D\x0D\x00\x00\x00\x00"
            cp = len(code)
            code += b"\xE8\x00\x00\x00\x00"
            skip = len(code)
            struct.pack_into("<i", code, lea_at + 3, msg_va - (cave_va + lea_at + 7))
            struct.pack_into("<i", code, cp + 1, printf_va - (cave_va + cp + 5))
        else:
            skip = len(code)
        for site in (j0, j1, j2, j3):
            code[site + 1] = (skip - (site + 2)) & 0xFF
        struct.pack_into("<i", code, call_at + 1, RESTORE_VA - (cave_va + call_at + 5))

    code += EPILOGUE
    assert len(EPILOGUE) == 28
    data[va2off(sects, cave_va) : va2off(sects, cave_va) + len(code)] = code

    tramp = bytearray(b"\xE9\x00\x00\x00\x00")
    struct.pack_into("<i", tramp, 1, cave_va - (EVICT_TAIL_VA + 5))
    tail_off = va2off(sects, EVICT_TAIL_VA)
    # original epilogue is 28 bytes; overwrite with tramp+int3
    data[tail_off : tail_off + 5] = tramp
    for i in range(5, 28):
        data[tail_off + i] = 0xCC

    open(DST, "wb").write(data)
    h = hashlib.sha256(data).hexdigest().upper()
    print("MODE", MODE)
    print("DST_SHA256", h)
    print("CAVE_LEN", len(code))
    open(
        r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj084_inimage\INIMAGE_BUILD.txt",
        "w",
        encoding="utf-8",
    ).write(f"MODE={MODE}\nDST_SHA256={h}\nCAVE_VA={cave_va:X}\nPROMOTE=0\nFIX=MOV_RSI_REXW\n")


if __name__ == "__main__":
    main()

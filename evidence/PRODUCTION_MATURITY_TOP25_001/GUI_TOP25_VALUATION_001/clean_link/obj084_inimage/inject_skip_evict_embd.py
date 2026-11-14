# In-image: VRAMManager::Evict no-op success for token_embd.weight (skip Release/onEvict).
# Keeps embd RESIDENT through OPEN without keepGPU place-time pin path. PROMOTE=0.
import struct, hashlib

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F_inimage_restore.exe"
EXPECT_SRC = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"
IB = 0x140000000
EVICT_FN = 0x141AED3D0
TELEMETR_VA = 0x140AB0000
# Original first 10 bytes: 48 89 5C 24 20 57 48 83 EC 20
ORIG_HEAD = bytes.fromhex("48895C2420574883EC20")


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
    # Entry: rcx=this, rdx=lease (not yet saved). No stack frame yet.
    # test rdx
    code += bytes.fromhex("4885D2")  # test rdx, rdx
    jz = len(code)
    code += bytes.fromhex("7400")  # jz fallthrough_evict
    # cmp size [rdx+0x18] == 17  (string at lease+8, size at +0x10)
    code += bytes.fromhex("48837A1811")
    jne = len(code)
    code += bytes.fromhex("7500")
    # mov rax, [rdx+8] ; ptr
    code += bytes.fromhex("488B4208")
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
    # match: pin + return true (no Evict)
    code += bytes.fromhex("C6424501")  # mov byte [rdx+45h], 1
    # marker printf — use Evict's printf target
    msg = b"TOKEN_EMBD_STREAM_RESTORE=1 skip_evict=1\n\0"
    msg_va = cave_va + 0x100
    data[va2off(sects, msg_va) : va2off(sects, msg_va) + len(msg)] = msg
    printf_va = 0x141AED496 + struct.unpack("<i", bytes.fromhex("3BCD62FE"))[0]
    # align stack for call: push rax-ish — sub rsp,28h + shadow
    code += bytes.fromhex("4883EC28")
    lea = len(code)
    code += b"\x48\x8D\x0D\x00\x00\x00\x00"
    cp = len(code)
    code += b"\xE8\x00\x00\x00\x00"
    code += bytes.fromhex("4883C428")  # add rsp,28h
    code += bytes.fromhex("B001C3")  # mov al,1; ret
    skip = len(code)  # fallthrough to original Evict
    for site in (jz, jne, j1, j2, j3):
        code[site + 1] = (skip - (site + 2)) & 0xFF
    struct.pack_into("<i", code, lea + 3, msg_va - (cave_va + lea + 7))
    struct.pack_into("<i", code, cp + 1, printf_va - (cave_va + cp + 5))

    # fallthrough: execute original head then jmp back to Evict+10
    code += ORIG_HEAD
    back = len(code)
    code += b"\xE9\x00\x00\x00\x00"
    cont_va = EVICT_FN + len(ORIG_HEAD)
    struct.pack_into("<i", code, back + 1, cont_va - (cave_va + back + 5))

    data[va2off(sects, cave_va) : va2off(sects, cave_va) + len(code)] = code

    # trampoline at Evict fn start
    tramp = bytearray(b"\xE9\x00\x00\x00\x00")
    struct.pack_into("<i", tramp, 1, cave_va - (EVICT_FN + 5))
    off = va2off(sects, EVICT_FN)
    data[off : off + 5] = tramp
    # pad remaining overwritten head bytes with int3 (5 of 10 used by jmp)
    for i in range(5, len(ORIG_HEAD)):
        data[off + i] = 0xCC

    open(DST, "wb").write(data)
    h = hashlib.sha256(data).hexdigest().upper()
    print("DST_SHA256", h)
    print("CAVE_LEN", len(code))
    open(
        r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj084_inimage\INIMAGE_BUILD.txt",
        "w",
        encoding="utf-8",
    ).write(
        f"MODE=SKIP_EVICT_TOKEN_EMBD\nDST_SHA256={h}\nEVICT_FN={EVICT_FN:X}\nCAVE_VA={cave_va:X}\nPROMOTE=0\n"
    )


if __name__ == "__main__":
    main()

# In-image: after VRAMManager::Evict success on token_embd.weight,
# call Restore(lease,0) + pin. Cave in TELEMETR (exec). PROMOTE=0.
import struct, shutil, hashlib, os

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F_inimage_restore.exe"
EXPECT_SRC = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"

IB = 0x140000000
EVICT_TAIL_VA = 0x141AED496  # after printf, original epilogue
RESTORE_VA = 0x141AEEFE0
TELEMETR_VA = 0x140AB0000


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
    return e, sects


def va2off(sects, va):
    rva = va - IB
    for s in sects:
        if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
            return s["rw"] + (rva - s["va"])
    raise ValueError(hex(va))


def main():
    raw = open(SRC, "rb").read()
    h = hashlib.sha256(raw).hexdigest().upper()
    if h != EXPECT_SRC:
        raise SystemExit(f"SRC_HASH_MISMATCH {h}")
    data = bytearray(raw)
    e, sects = pe_sects(data)
    tele = next(s for s in sects if s["name"].startswith("TELEMETR"))
    # IMAGE_SCN_CNT_CODE|MEM_EXECUTE|MEM_READ|MEM_WRITE
    new_ch = 0xE0000020
    struct.pack_into("<I", data, tele["off"] + 36, new_ch)
    print("TELEMETR_CH", hex(tele["ch"]), "->", hex(new_ch))

    cave_va = TELEMETR_VA
    # marker string at cave+0x100
    msg = b"TOKEN_EMBD_STREAM_RESTORE=1\n\0"
    msg_va = cave_va + 0x100
    msg_off = va2off(sects, msg_va)
    data[msg_off : msg_off + len(msg)] = msg

    # printf target from original Evict call at 0x141AED491
    # E8 rel32; next=0x141AED496; rel bytes 3B CD 62 FE
    printf_rel = struct.unpack("<i", bytes.fromhex("3BCD62FE"))[0]
    printf_va = 0x141AED496 + printf_rel
    print("PRINTF_VA", hex(printf_va))

    # Build cave code
    # On entry from Evict: RBX=lease, RDI=this, stack still in Evict frame
    code = bytearray()
    # cmp qword [rbx+0x20], 0x11  ; name.size == 17
    code += bytes.fromhex("48837B2011")
    jne_site = len(code)
    code += bytes.fromhex("7500")  # jne skip patch later
    # mov rax, [rbx+8] ; string ptr (long SSO)
    code += bytes.fromhex("488B4308")
    # mov rcx, imm64 'token_em'
    code += b"\x48\xB9" + b"token_em"
    code += bytes.fromhex("483908")  # cmp [rax], rcx
    jne2 = len(code)
    code += bytes.fromhex("7500")
    # mov rcx, imm64 'bd.weigh'
    code += b"\x48\xB9" + b"bd.weigh"
    code += bytes.fromhex("48394808")  # cmp [rax+8], rcx
    jne3 = len(code)
    code += bytes.fromhex("7500")
    # cmp byte [rax+0x10], 't'
    code += bytes.fromhex("80781074")
    jne4 = len(code)
    code += bytes.fromhex("7500")
    # call Restore(rcx=rdi, rdx=rbx, r8=0)
    # shadow space: we're already in Evict's frame with sub rsp,20 — OK for call
    code += bytes.fromhex("488BCF")  # mov rcx, rdi
    code += bytes.fromhex("488BD3")  # mov rdx, rbx
    code += bytes.fromhex("4533C0")  # xor r8d, r8d
    call_restore_at = len(code)
    code += b"\xE8\x00\x00\x00\x00"
    # pinned = 1 at lease+0x45
    code += bytes.fromhex("C6434501")
    # printf marker: rcx = msg
    lea_at = len(code)
    code += b"\x48\x8D\x0D\x00\x00\x00\x00"  # lea rcx, [rip+msg]
    call_printf_at = len(code)
    code += b"\xE8\x00\x00\x00\x00"
    skip = len(code)
    # patch jne offsets (rel8)
    for site in (jne_site, jne2, jne3, jne4):
        rel = skip - (site + 2)
        assert -128 <= rel <= 127
        code[site + 1] = rel & 0xFF
    # original epilogue
    code += bytes.fromhex(
        "8B742438"  # mov esi, [rsp+38h]
        "B001"  # mov al, 1
        "488B6C2430"  # mov rbp, [rsp+30h]
        "4C8B742440"  # mov r14, [rsp+40h]
        "488B5C2448"  # mov rbx, [rsp+48h]
        "4883C420"  # add rsp, 20h
        "5F"  # pop rdi
        "C3"  # ret
    )

    # fix call Restore rel32
    restore_call_va = cave_va + call_restore_at
    rel = RESTORE_VA - (restore_call_va + 5)
    struct.pack_into("<i", code, call_restore_at + 1, rel)
    # fix lea rcx, msg
    lea_va = cave_va + lea_at
    # lea rcx, [rip+disp] ; disp = msg_va - (lea_va+7)
    disp = msg_va - (lea_va + 7)
    struct.pack_into("<i", code, lea_at + 3, disp)
    # fix printf call
    printf_call_va = cave_va + call_printf_at
    relp = printf_va - (printf_call_va + 5)
    struct.pack_into("<i", code, call_printf_at + 1, relp)

    assert len(code) < 0x100
    cave_off = va2off(sects, cave_va)
    data[cave_off : cave_off + len(code)] = code
    print("CAVE_LEN", len(code), "CAVE_VA", hex(cave_va))

    # trampoline at Evict tail
    tail_off = va2off(sects, EVICT_TAIL_VA)
    # jmp rel32 to cave
    tramp = bytearray(b"\xE9\x00\x00\x00\x00")
    relj = cave_va - (EVICT_TAIL_VA + 5)
    struct.pack_into("<i", tramp, 1, relj)
    # fill rest of old epilogue with INT3 so accidental fallthrough faults loudly
    old_len = 27
    data[tail_off : tail_off + 5] = tramp
    for i in range(5, old_len):
        data[tail_off + i] = 0xCC
    print("TRAMP at", hex(EVICT_TAIL_VA), "->", hex(cave_va), "rel", relj)

    open(DST, "wb").write(data)
    out_h = hashlib.sha256(data).hexdigest().upper()
    print("DST", DST)
    print("DST_SHA256", out_h)
    print("SRC_UNTOUCHED", hashlib.sha256(open(SRC, "rb").read()).hexdigest().upper() == EXPECT_SRC)
    # verify tip RO hash separately not here
    meta = os.path.join(os.path.dirname(DST), "..", "..", "gpu", "INIMAGE_617F_RESTORE_BUILD.txt")
    # write next to obj084_inimage
    meta = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj084_inimage\INIMAGE_BUILD.txt"
    with open(meta, "w", encoding="utf-8") as w:
        w.write(f"SRC_SHA256={EXPECT_SRC}\n")
        w.write(f"DST_SHA256={out_h}\n")
        w.write(f"DST={DST}\n")
        w.write(f"INJECT=EVICT_TAIL_RESTORE_PIN\n")
        w.write(f"EVICT_TAIL_VA={EVICT_TAIL_VA:X}\n")
        w.write(f"RESTORE_VA={RESTORE_VA:X}\n")
        w.write(f"CAVE_VA={cave_va:X}\n")
        w.write("PROMOTE=0\n")
        w.write("CROSS_SHA_CREDIT=0\n")
    print("META", meta)


if __name__ == "__main__":
    main()

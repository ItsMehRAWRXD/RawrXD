# In-image Restore v2 on LOCKED 617F784E copy.
# 1) At Evict success fprintf for token_embd.weight: save (vm=rdi, lease=rbx) into cave slots.
# 2) At GENERATE_STREAM_ENTER lea site: call Restore(saved) then continue.
# PROMOTE=0. Tip + LOCKED snap untouched.
import struct, shutil, hashlib, sys

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E_inimage_restore.exe"
EXPECT = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"
RESTORE_RVA = 0x1AEEFE0
SCN_CNT_CODE = 0x20
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest().upper()


def main():
    if sha256(SRC) != EXPECT:
        print("SRC_HASH_FAIL")
        return 2
    shutil.copy2(SRC, DST)
    with open(DST, "r+b") as f:
        data = bytearray(f.read())
        e = struct.unpack_from("<I", data, 0x3C)[0]
        ns = struct.unpack_from("<H", data, e + 6)[0]
        so = struct.unpack_from("<H", data, e + 20)[0]
        ib = struct.unpack_from("<Q", data, e + 24 + 24)[0]
        sect_off = e + 24 + so
        sects = []
        for i in range(ns):
            o = sect_off + i * 40
            name = bytes(data[o : o + 8]).split(b"\0")[0].decode()
            vs, va, rs, rw = struct.unpack_from("<IIII", data, o + 8)
            ch = struct.unpack_from("<I", data, o + 36)[0]
            sects.append(
                dict(o=o, name=name, vs=vs, va=va, rs=rs, rw=rw, ch=ch)
            )

        def off2rva(off):
            for s in sects:
                if s["rw"] <= off < s["rw"] + s["rs"]:
                    return s["va"] + (off - s["rw"])
            return None

        def va2off(va):
            rva = va - ib
            for s in sects:
                if s["va"] <= rva < s["va"] + max(s["vs"], s["rs"]):
                    return s["rw"] + (rva - s["va"])
            return None

        def lea_xrefs(rva):
            text = next(s for s in sects if s["name"] == ".text")
            tr, tv, tsz = text["rw"], text["va"], text["rs"]
            hits = []
            j = tr
            end = tr + tsz - 7
            while j < end:
                if (
                    data[j] in (0x48, 0x4C)
                    and data[j + 1] == 0x8D
                    and (data[j + 2] & 0xC7) == 0x05
                ):
                    disp = struct.unpack_from("<i", data, j + 3)[0]
                    tgt = (tv + (j + 7 - tr)) + disp
                    if tgt == rva:
                        hits.append(ib + tv + (j - tr))
                j += 1
            return hits

        tele = next(s for s in sects if s["name"] == "TELEMETR")
        new_ch = tele["ch"] | SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
        struct.pack_into("<I", data, tele["o"] + 36, new_ch)
        cave_budget = min(tele["rs"] - tele["vs"], 384)
        struct.pack_into("<I", data, tele["o"] + 8, tele["vs"] + cave_budget)
        cave_off = tele["rw"] + tele["vs"]
        cave_va = ib + tele["va"] + tele["vs"]
        # layout: [0:8]=saved_vm, [8:16]=saved_lease, [16:]=code
        SLOT_VM = 0
        SLOT_LEASE = 8
        CODE0 = 32
        # zero slots
        data[cave_off : cave_off + 32] = b"\x00" * 32

        te_va = ib + off2rva(data.find(b"token_embd.weight"))
        restore_va = ib + RESTORE_RVA

        # --- stub A: Evict fprintf hook — save if token_embd ---
        stub_a = bytearray()
        # call original fprintf (placeholder)
        a_fprintf = len(stub_a)
        stub_a += b"\xE8\x00\x00\x00\x00"
        # push volatiles
        stub_a += b"\x50\x51\x52\x41\x50\x41\x51"
        # length check [rbx+0x20] == 17
        stub_a += b"\x48\x83\x7B\x20\x11"  # cmp qword [rbx+0x20], 17
        stub_a += b"\x75\x30"  # jne skip (~48)
        jne_a = len(stub_a) - 1
        # c_str
        stub_a += b"\x48\x8D\x53\x08\x48\x83\x7B\x20\x0F\x76\x03\x48\x8B\x12"
        # lea r8, token_embd
        a_lea = len(stub_a)
        stub_a += b"\x4C\x8D\x05\x00\x00\x00\x00"
        # cmp 16 bytes
        stub_a += b"\x48\x8B\x02\x49\x3B\x00\x75\x18"
        jne_a2 = len(stub_a) - 1
        stub_a += b"\x48\x8B\x42\x08\x49\x3B\x40\x08\x75\x0C"
        jne_a3 = len(stub_a) - 1
        # save rdi/rbx into slots via rip-relative
        # lea rax, [rip+slot_vm]; mov [rax], rdi; mov [rax+8], rbx
        a_slot = len(stub_a)
        stub_a += b"\x48\x8D\x05\x00\x00\x00\x00"  # lea rax, [rip+slot]
        stub_a += b"\x48\x89\x38"  # mov [rax], rdi
        stub_a += b"\x48\x89\x58\x08"  # mov [rax+8], rbx
        skip_a = len(stub_a)
        stub_a[jne_a] = (skip_a - (jne_a + 1)) & 0xFF
        stub_a[jne_a2] = (skip_a - (jne_a2 + 1)) & 0xFF
        stub_a[jne_a3] = (skip_a - (jne_a3 + 1)) & 0xFF
        stub_a += b"\x41\x59\x41\x58\x5A\x59\x58"
        a_back = len(stub_a)
        stub_a += b"\xE9\x00\x00\x00\x00"

        # --- stub B: GENERATE_STREAM_ENTER — Restore if saved ---
        stub_b = bytearray()
        # save rcx (engine this) and other volatiles used by fprintf path
        stub_b += b"\x50\x51\x52\x41\x50\x41\x51\x41\x52"
        # load slots
        b_slot = len(stub_b)
        stub_b += b"\x48\x8D\x05\x00\x00\x00\x00"  # lea rax, [rip+slot]
        stub_b += b"\x48\x8B\x08"  # mov rcx, [rax] ; vm
        stub_b += b"\x48\x8B\x50\x08"  # mov rdx, [rax+8] ; lease
        stub_b += b"\x48\x85\xC9\x74\x14"  # test rcx,rcx; jz skip
        stub_b += b"\x48\x85\xD2\x74\x0F"  # test rdx,rdx; jz skip
        stub_b += b"\x45\x33\xC0"  # xor r8d,r8d
        b_call = len(stub_b)
        stub_b += b"\xE8\x00\x00\x00\x00"  # call Restore
        # clear slots after attempt
        stub_b += b"\x48\x8D\x05\x00\x00\x00\x00"
        b_slot2 = len(stub_b) - 7
        stub_b += b"\x48\x33\xC9\x48\x89\x08\x48\x89\x48\x08"
        skip_b = len(stub_b)
        # fix short jz — recompute manually with exact layout after build
        stub_b += b"\x41\x5A\x41\x59\x41\x58\x5A\x59\x58"
        # original lea rcx/r8 setup for GENERATE_STREAM_ENTER was AT patch site;
        # we replaced 5 bytes of the lea? Better replace a call after ENTER setup.
        # We'll patch the fprintf call for GENERATE_STREAM_ENTER similarly.
        b_back = len(stub_b)
        stub_b += b"\xE9\x00\x00\x00\x00"

        # Place stubs in cave: CODE0 alignment
        off_a = CODE0
        off_b = CODE0 + ((len(stub_a) + 15) // 16) * 16
        if off_b + len(stub_b) > cave_budget:
            print("CAVE_OVERFLOW", off_b + len(stub_b), cave_budget)
            return 3
        va_a = cave_va + off_a
        va_b = cave_va + off_b
        slot_va = cave_va + SLOT_VM

        # Fix stub A relocs
        # find Evict fprintf call
        ev_x = lea_xrefs(off2rva(data.find(b"[VRAMManager] Evicted '%s'")))[0]
        eoff = va2off(ev_x)
        call_a = None
        for k in range(0, 40):
            if data[eoff + k] == 0xE8:
                call_a = eoff + k
                break
        call_a_va = ib + off2rva(call_a)
        fprintf_a = call_a_va + 5 + struct.unpack_from("<i", data, call_a + 1)[0]
        struct.pack_into(
            "<i", stub_a, a_fprintf + 1, fprintf_a - (va_a + a_fprintf + 5)
        )
        struct.pack_into("<i", stub_a, a_lea + 3, te_va - (va_a + a_lea + 7))
        struct.pack_into(
            "<i", stub_a, a_slot + 3, slot_va - (va_a + a_slot + 7)
        )
        struct.pack_into(
            "<i", stub_a, a_back + 1, (call_a_va + 5) - (va_a + a_back + 5)
        )

        # Fix stub B — find GENERATE_STREAM_ENTER fprintf call (after lea)
        gs_x = lea_xrefs(off2rva(data.find(b"GENERATE_STREAM_ENTER=")))[0]
        goff = va2off(gs_x)
        # at lea: 48 8D 15 ... then args then E8 fprintf
        call_b = None
        for k in range(0, 48):
            if data[goff + k] == 0xE8:
                call_b = goff + k
                break
        if call_b is None:
            print("NO_GS_FPRINTF")
            return 4
        call_b_va = ib + off2rva(call_b)
        fprintf_b = call_b_va + 5 + struct.unpack_from("<i", data, call_b + 1)[0]
        # Rebuild stub B properly: call fprintf first, then Restore, then return
        stub_b = bytearray()
        b_fprintf = len(stub_b)
        stub_b += b"\xE8\x00\x00\x00\x00"  # fprintf ENTER line
        stub_b += b"\x50\x51\x52\x41\x50\x41\x51"
        b_slot = len(stub_b)
        stub_b += b"\x48\x8D\x05\x00\x00\x00\x00"
        stub_b += b"\x48\x8B\x08"  # rcx=vm
        stub_b += b"\x48\x8B\x50\x08"  # rdx=lease
        # jz skip restore if null — use near jumps with placeholders
        jz1_at = len(stub_b)
        stub_b += b"\x48\x85\xC9\x74\x00"  # test rcx; jz
        jz2_at = len(stub_b)
        stub_b += b"\x48\x85\xD2\x74\x00"
        stub_b += b"\x45\x33\xC0"
        b_call = len(stub_b)
        stub_b += b"\xE8\x00\x00\x00\x00"
        b_clr = len(stub_b)
        stub_b += b"\x48\x8D\x05\x00\x00\x00\x00"
        stub_b += b"\x48\x33\xC9\x48\x89\x08\x48\x89\x48\x08"
        skip_b = len(stub_b)
        stub_b[jz1_at + 3] = (skip_b - (jz1_at + 4)) & 0xFF
        stub_b[jz2_at + 3] = (skip_b - (jz2_at + 4)) & 0xFF
        stub_b += b"\x41\x59\x41\x58\x5A\x59\x58"
        b_back = len(stub_b)
        stub_b += b"\xE9\x00\x00\x00\x00"

        off_b = CODE0 + ((len(stub_a) + 15) // 16) * 16
        if off_b + len(stub_b) > cave_budget:
            print("CAVE_OVERFLOW2", off_b + len(stub_b), cave_budget)
            return 3
        va_b = cave_va + off_b

        struct.pack_into(
            "<i", stub_b, b_fprintf + 1, fprintf_b - (va_b + b_fprintf + 5)
        )
        struct.pack_into(
            "<i", stub_b, b_slot + 3, slot_va - (va_b + b_slot + 7)
        )
        struct.pack_into(
            "<i", stub_b, b_call + 1, restore_va - (va_b + b_call + 5)
        )
        struct.pack_into(
            "<i", stub_b, b_clr + 3, slot_va - (va_b + b_clr + 7)
        )
        struct.pack_into(
            "<i", stub_b, b_back + 1, (call_b_va + 5) - (va_b + b_back + 5)
        )

        # write stubs
        data[cave_off + off_a : cave_off + off_a + len(stub_a)] = stub_a
        data[cave_off + off_b : cave_off + off_b + len(stub_b)] = stub_b
        for i in range(off_b + len(stub_b), cave_budget):
            data[cave_off + i] = 0xCC
        marker = b"INIMAGE_V2\0"
        # slots occupy [0:16); leave [16:CODE0) for marker only (CODE0=32)
        if 16 + len(marker) <= CODE0:
            data[cave_off + 16 : cave_off + 16 + len(marker)] = marker

        # patch both call sites to jmp stubs
        data[call_a] = 0xE9
        struct.pack_into("<i", data, call_a + 1, va_a - (call_a_va + 5))
        data[call_b] = 0xE9
        struct.pack_into("<i", data, call_b + 1, va_b - (call_b_va + 5))

        f.seek(0)
        f.write(data)
        f.truncate(len(data))

    print("DST_SHA", sha256(DST))
    print("SHA16", sha256(DST)[:16])
    print("VA_A", hex(va_a), "VA_B", hex(va_b), "SLOT", hex(slot_va))
    print("CALL_A", hex(call_a_va), "CALL_B", hex(call_b_va))
    print("RESTORE", hex(restore_va))
    return 0


if __name__ == "__main__":
    sys.exit(main())

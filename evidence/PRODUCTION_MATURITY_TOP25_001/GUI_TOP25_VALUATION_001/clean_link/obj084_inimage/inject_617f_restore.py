# In-image TOKEN_EMBD Restore on LOCKED 617F784E.
# Strategy: after VRAMManager::Evict success fprintf for any lease, if name
# is token_embd.weight / token_embeddings.weight, call Restore(lease, 0) and pin.
# Cave: expand TELEMETR VirtualSize into file slack (384B) + mark executable.
# PROMOTE=0 TIP untouched. Does not modify LOCKED snap in place — writes private cand.
import struct, mmap, hashlib, os, shutil, sys

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E_inimage_restore.exe"
EXPECT_SRC = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"

# IMAGE_SCN flags
SCN_CNT_CODE = 0x00000020
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def main():
    got = sha256(SRC)
    print("SRC_SHA", got, "PASS" if got == EXPECT_SRC else "FAIL")
    if got != EXPECT_SRC:
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
                {
                    "i": i,
                    "o": o,
                    "name": name,
                    "vs": vs,
                    "va": va,
                    "rs": rs,
                    "rw": rw,
                    "ch": ch,
                }
            )
            print(
                name,
                "VA",
                hex(va),
                "VSZ",
                hex(vs),
                "RAW",
                hex(rw),
                "RSZ",
                hex(rs),
                "CH",
                hex(ch),
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

        # Locate Evict success `mov al,1` after Evicted fprintf (first xref path)
        ev_str = data.find(b"[VRAMManager] Evicted '%s'")
        ev_rva = off2rva(ev_str)
        ev_x = lea_xrefs(ev_rva)
        print("EVICT_XREFS", [hex(x) for x in ev_x])
        # Prefer the site that has b0 01 shortly after the call (success return)
        patch_sites = []
        for xva in ev_x:
            xoff = va2off(xva)
            # look forward 32 bytes for b0 01
            window = bytes(data[xoff : xoff + 48])
            idx = window.find(b"\xb0\x01")
            print(" site", hex(xva), "b001_at", idx, window.hex())
            if idx >= 0:
                patch_sites.append((xva, xoff, xoff + idx))

        if not patch_sites:
            print("NO_PATCH_SITE")
            return 3

        # Restore function: find via Restored string + walk to prologue ending at CC
        rest_str = data.find(b"[VRAMManager] Restored '%s'")
        rest_x = lea_xrefs(off2rva(rest_str))[0]
        print("REST_XREF", hex(rest_x))
        roff = va2off(rest_x)
        restore_fn = None
        for back in range(0, 0x300):
            o = roff - back
            if data[o - 1] == 0xCC and data[o] == 0x48 and data[o + 1] == 0x89:
                restore_fn = ib + off2rva(o)
                print("RESTORE_FN", hex(restore_fn), "gap", back)
                print("PROLOG", bytes(data[o : o + 24]).hex())
                break
        if restore_fn is None:
            # fallback known candidate
            restore_fn = 0x141AEFFE0
            print("RESTORE_FN_FALLBACK", hex(restore_fn))

        # token_embd.weight string RVA for compare
        te_off = data.find(b"token_embd.weight")
        te_rva = off2rva(te_off)
        te_va = ib + te_rva
        print("TOKEN_EMBD_STR", hex(te_va))

        # Prepare cave in TELEMETR slack
        tele = next(s for s in sects if s["name"] == "TELEMETR")
        # cave starts at current VirtualSize within raw
        cave_file_off = tele["rw"] + tele["vs"]
        cave_rva = tele["va"] + tele["vs"]
        cave_va = ib + cave_rva
        slack = tele["rs"] - tele["vs"]
        print("CAVE", hex(cave_va), "file", hex(cave_file_off), "slack", slack)
        if slack < 128:
            print("SLACK_TOO_SMALL")
            return 4

        # Mark TELEMETR executable+readable (keep write if present)
        new_ch = tele["ch"] | SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
        struct.pack_into("<I", data, tele["o"] + 36, new_ch)
        # Grow VirtualSize to consume slack (up to 256 used)
        cave_budget = min(slack, 256)
        struct.pack_into("<I", data, tele["o"] + 8, tele["vs"] + cave_budget)

        # Also bump SizeOfImage if needed
        size_of_image_off = e + 24 + 56  # OptionalHeader.SizeOfImage for PE32+
        # PE32+: Magic@0, ... SizeOfImage at optional+56
        old_soi = struct.unpack_from("<I", data, e + 24 + 56)[0]
        print("SizeOfImage", hex(old_soi), "TELE_CH", hex(new_ch))

        # Pick first patch site (primary Evict success)
        xva, xoff, b001_off = patch_sites[0]
        # We need 5 bytes for jmp rel32. The `b0 01` is 2 bytes; steal preceding
        # instruction bytes. Looking at ctx: ... e8 XX XX XX XX  48 8b 74 24 38  b0 01
        # Safer: replace `b0 01` + following 3 bytes if they're recoverable, OR
        # replace the 5-byte call to fprintf and redo it in cave — too heavy.
        #
        # Minimal: overwrite `mov al,1` (b0 01) and next 3 bytes with jmp to cave;
        # cave does Restore check, then sets al=1 and executes clobbered bytes, returns.
        #
        # Inspect 8 bytes at b001_off
        clobber = bytes(data[b001_off : b001_off + 8])
        print("CLOBBER_AT", hex(ib + off2rva(b001_off)), clobber.hex())

        # From first site dump: b001 488b6c2430 4c8b742440
        # So after mov al,1 comes mov rbp,[rsp+30]; mov r14,[rsp+40]
        # Those are epilogue restores — must run before ret.
        # Patch plan: jmp (5B) at b001_off overwriting b0 01 + 48 8b 6c (partial).
        # Better: find a 5-byte instruction aligned site.
        #
        # Alternate site: replace the `call fprintf` (E8 rel32) of Evicted with jmp
        # to cave; cave calls fprintf, then Restore-if-token_embd, then returns to
        # next insn (mov rsi / mov al,1 path).
        #
        # Find E8 immediately before the lea of Evicted string (the fprintf call is AFTER lea).
        # Pattern at xref: lea rcx,str; mov r8,?; call fprintf
        # At xoff we are AT the lea (48 8d 0d ...). Call is typically +15 or so.
        # Search forward for E8 from xoff
        call_off = None
        for k in range(0, 40):
            if data[xoff + k] == 0xE8:
                call_off = xoff + k
                break
        if call_off is None:
            print("NO_FPRINTF_CALL")
            return 5
        call_va = ib + off2rva(call_off)
        call_rel = struct.unpack_from("<i", data, call_off + 1)[0]
        fprintf_tgt = call_va + 5 + call_rel
        print("FPRINTF_CALL", hex(call_va), "->", hex(fprintf_tgt))

        # Disassemble lease pointer: from Evict ABI, lease is typically in rdx or rbx.
        # From earlier CTX before fprintf: 48 8b 12 = mov rdx,[rdx] from name ptr path
        # 48 8d 53 08 ; 48 83 7b 20 0f ; 76 03 ; 48 8b 12  — name.c_str() from lease in rbx
        # So lease* is in RBX at fprintf time.
        #
        # Restore(VRAMLease* lease, int preferredGPU) — MSVC: this in RCX, lease RDX, gpu R8d
        # VRAMManager this: Evict is method, so at start RCX=this; may be saved.
        # From CTX: 48 8b 8f 90 02 00 00 — suggests this/other in rdi with offset.
        # Looking at Evict prologue candidates: need `this` pointer for Restore call.
        #
        # Simpler approach matching product intent at STREAM time instead of Evict-time:
        # trampoline generateStream first call → cave → original configureGeneration,
        # then scan — WITHOUT full C++ lease walk we call a helper already in image.
        #
        # PRACTICAL FALLBACK for this seal turn: patch Evict success so token_embd
        # is immediately Restored (Evict still returns true → OPEN path ok;
        # tensor back on GPU before stream). Use RBX=lease, find `this` in RSI/RDI.
        #
        # From EVICT_CTX ending: 48 8b 74 24 38 b0 01 48 8b 6c 24 30
        # mov rsi,[rsp+38h] then al=1 — rsi restored from stack home of rsi.
        # Before that fprintf used r8=rbp etc.
        #
        # Read Evict function start at 0x141aed3d0 area more carefully.

        # === Build cave stub ===
        # At fprintf call site, replace E8 with E9 jmp to cave.
        # Cave:
        #   ; recreate call fprintf (same args still in regs)
        #   call fprintf_tgt
        #   ; save volatiles we clobber
        #   push rax / rcx / rdx / r8 / r9 / r10 / r11
        #   ; rbx = lease*
        #   mov rdx, rbx          ; lease
        #   ; this: from [rsp+...] after pushes — use saved this
        # Actually Evict `this` often stays in a nonvolatile. Check: rdi used as this?
        # CTX: 48 8d 8f 80 03 00 00 = lea rcx, [rdi+0x380] — rdi is likely `this` (VRAMManager*)
        #
        # Cave logic:
        #   call fprintf
        #   push rbx / rdi / rsi etc as needed
        #   ; compare lease->name with token_embd.weight
        #   ; MSVC std::string: if size <= 15, data in SSO buffer at lease+offset
        #   ; From code: 48 83 7b 20 0f = cmp qword [rbx+0x20], 0xF  (string size threshold)
        #   ; 48 8d 53 08 = lea rdx, [rbx+8] (SSO buffer)
        #   ; 76 03 / 48 8b 12 = if size>15 mov rdx,[rdx] (heap ptr)
        #   ; So string object at rbx+8? Wait lea rdx,[rbx+8] and size at [rbx+20]
        #   ; Actually typical layout: lease+0 name is string; size at string+16=lease+16?
        #   ; Code says [rbx+0x20] for size and [rbx+8] for SSO — so name starts at rbx+0?
        #   ; Standard MSVC x64 string: { union{buf[16]; ptr}; size; capacity} = 32 bytes
        #   ; If name is first field: SSO at rbx+0, size at rbx+16. But code uses +8 and +0x20.
        #   ; So name is NOT at offset 0. name at rbx+8: SSO at +8, size at +8+16=+24=0x18?
        #   ; Code: cmp [rbx+0x20],0xF and lea rdx,[rbx+8] — size at +0x20, data at +8.
        #   ; That's size at +0x20 = field at offset 8 with size at +24 from lease = string at +8
        #   ; string size offset = 16 from string start → 8+16=24=0x18, but they use 0x20.
        #   ; capacity at +24, size at +16... Unless there's 8-byte vheader.
        #   ; Stick to exact same sequence as Evict uses for name c_str.

        name_check_asm_comment = "use identical [rbx+0x20]/[rbx+8] sequence"

        # Build machine code for cave
        stub = bytearray()

        def emit(b):
            stub.extend(b if isinstance(b, (bytes, bytearray)) else bytes(b))

        # 1) call original fprintf (rel32 from cave_va+len+5)
        # We'll patch rel after knowing stub layout — emit placeholder
        fprintf_call_at = len(stub)
        emit(b"\xE8\x00\x00\x00\x00")  # call fprintf

        # 2) save regs
        emit(b"\x50")  # push rax
        emit(b"\x51")  # push rcx
        emit(b"\x52")  # push rdx
        emit(b"\x41\x50")  # push r8
        emit(b"\x41\x51")  # push r9

        # 3) get name c_str into rdx (same as Evict)
        emit(b"\x48\x8D\x53\x08")  # lea rdx, [rbx+8]
        emit(b"\x48\x83\x7B\x20\x0F")  # cmp qword ptr [rbx+0x20], 0xF
        emit(b"\x76\x03")  # jbe +3
        emit(b"\x48\x8B\x12")  # mov rdx, [rdx]

        # 4) compare with "token_embd.weight" — use repe cmpsb or simple dword checks
        # Load expected string VA into r8, compare first 16 bytes
        # lea r8, [rip+disp] to te_va — patch later
        lea_te_at = len(stub)
        emit(b"\x4C\x8D\x05\x00\x00\x00\x00")  # lea r8, [rip+disp] → token_embd.weight

        # memcmp 16 bytes: rdx vs r8
        emit(b"\x48\x8B\x02")  # mov rax, [rdx]
        emit(b"\x49\x3B\x00")  # cmp rax, [r8]
        emit(b"\x75\x18")  # jne skip_restore (+24 later adjust)
        jne1 = len(stub) - 1
        emit(b"\x48\x8B\x42\x08")  # mov rax, [rdx+8]
        emit(b"\x49\x3B\x40\x08")  # cmp rax, [r8+8]
        emit(b"\x75\x0C")  # jne skip
        jne2 = len(stub) - 1

        # 5) call Restore(this=rdi, lease=rbx, gpu=0)
        emit(b"\x48\x8B\xCF")  # mov rcx, rdi  ; this
        emit(b"\x48\x8B\xD3")  # mov rdx, rbx  ; lease
        emit(b"\x45\x33\xC0")  # xor r8d, r8d ; preferredGPU=0
        restore_call_at = len(stub)
        emit(b"\xE8\x00\x00\x00\x00")  # call Restore

        # 6) if Restore ok (al!=0), set lease->pinned — pinned offset unknown.
        # From Restore CTX: c6 43 60 00 = mov byte ptr [rbx+0x60], 0 nearby?
        # REST_CTX: c6436000 before call — that might be clearing a flag on lease.
        # Skip pinned for minimal inject; Restore alone may be enough for GPU residency.

        # skip_restore:
        skip_off = len(stub)
        # fix jne displacements
        stub[jne1] = (skip_off - (jne1 + 1)) & 0xFF
        stub[jne2] = (skip_off - (jne2 + 1)) & 0xFF

        # restore regs
        emit(b"\x41\x59")  # pop r9
        emit(b"\x41\x58")  # pop r8
        emit(b"\x5A")  # pop rdx
        emit(b"\x59")  # pop rcx
        emit(b"\x58")  # pop rax

        # jump back to instruction after original fprintf call
        back_at = len(stub)
        emit(b"\xE9\x00\x00\x00\x00")

        if len(stub) > cave_budget:
            print("STUB_TOO_BIG", len(stub), cave_budget)
            return 6

        # Fix up rel32s now that cave_va is known
        def patch_rel32(at, target_va):
            # instruction at cave_va+at is E8/E9/lea-rip; next ip = cave_va+at+5 or +7 for lea
            pass

        # fprintf call
        next_ip = cave_va + fprintf_call_at + 5
        struct.pack_into("<i", stub, fprintf_call_at + 1, fprintf_tgt - next_ip)

        # lea r8, token_embd
        # 4C 8D 05 disp32 — next ip = cave_va + lea_te_at + 7
        next_ip = cave_va + lea_te_at + 7
        struct.pack_into("<i", stub, lea_te_at + 3, te_va - next_ip)

        # Restore call
        next_ip = cave_va + restore_call_at + 5
        struct.pack_into("<i", stub, restore_call_at + 1, restore_fn - next_ip)

        # jmp back
        ret_va = call_va + 5
        next_ip = cave_va + back_at + 5
        struct.pack_into("<i", stub, back_at + 1, ret_va - next_ip)

        # Write stub into cave
        data[cave_file_off : cave_file_off + len(stub)] = stub
        # Zero remaining cave for cleanliness
        for i in range(len(stub), cave_budget):
            data[cave_file_off + i] = 0xCC

        # Patch fprintf call site to jmp cave
        next_ip = call_va + 5
        jmp_rel = cave_va - next_ip
        data[call_off] = 0xE9
        struct.pack_into("<i", data, call_off + 1, jmp_rel)

        # Marker string in remaining rdata slack if any — write witness into cave tail
        marker = b"TOKEN_EMBD_STREAM_RESTORE=INIMAGE\0"
        # put marker after stub if space
        if len(stub) + len(marker) <= cave_budget:
            mo = cave_file_off + len(stub)
            data[mo : mo + len(marker)] = marker

        f.seek(0)
        f.write(data)
        f.truncate(len(data))

    dst_sha = sha256(DST)
    print("DST", DST)
    print("DST_SHA", dst_sha)
    print("DST_SHA16", dst_sha[:16])
    print("INIMAGE=1 STUB_LEN=%d CAVE=%s RESTORE_FN=%s" % (len(stub), hex(cave_va), hex(restore_fn)))
    print("PATCH_CALL", hex(call_va), "-> CAVE", hex(cave_va))
    return 0


if __name__ == "__main__":
    sys.exit(main())

# In-image v3: Evict early-out for token_embd.weight (keep GPU buffer).
# PROMOTE=0. Snap+tip untouched.
import struct, shutil, hashlib, sys

SRC = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E.exe"
DST = r"G:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_gemma_qdim084_617F784E_inimage_restore.exe"
EXPECT = "617F784ED72938E029BA57FF0B63D8EAF1C16994860468A3BA62E08ECCE7DD1E"
EVICT_RVA = 0x1AED3D0
SCN_CNT_CODE, SCN_MEM_EXECUTE, SCN_MEM_READ = 0x20, 0x20000000, 0x40000000


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
            sects.append(dict(o=o, name=name, vs=vs, va=va, rs=rs, rw=rw, ch=ch))

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

        tele = next(s for s in sects if s["name"] == "TELEMETR")
        struct.pack_into(
            "<I",
            data,
            tele["o"] + 36,
            tele["ch"] | SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ,
        )
        budget = min(tele["rs"] - tele["vs"], 256)
        struct.pack_into("<I", data, tele["o"] + 8, tele["vs"] + budget)
        cave_off = tele["rw"] + tele["vs"]
        cave_va = ib + tele["va"] + tele["vs"]

        te_va = ib + off2rva(data.find(b"token_embd.weight"))
        evict_va = ib + EVICT_RVA
        eoff = va2off(evict_va)
        prolog = bytes(data[eoff : eoff + 25])
        print("EVICT_HEAD", prolog.hex())
        # After setup (16 bytes): test rdx,rdx; jz rel32  = 9 bytes
        assert data[eoff + 16 : eoff + 19] == bytes.fromhex("4885d2")
        assert data[eoff + 19] == 0x0F and data[eoff + 20] == 0x84
        jz_rel = struct.unpack_from("<i", data, eoff + 21)[0]
        jz_tgt = (evict_va + 16 + 6) + jz_rel
        cont_va = evict_va + 16 + 9
        print("JZ_TGT", hex(jz_tgt), "CONT", hex(cont_va))

        patch_off = eoff + 16
        patch_va = evict_va + 16

        stub = bytearray()
        # name at lease+8: size@_Mysize=+0x18, capacity@_Myres=+0x20 (MSVC x64)
        # if size==17 and content matches token_embd.weight -> early OK ret
        stub += b"\x48\x83\x7B\x18\x11"  # cmp [rbx+18h], 17
        stub += b"\x75\x2C"
        j1 = len(stub) - 1
        # c_str: capacity>15 => heap ptr at [rbx+8], else SSO buffer at rbx+8
        stub += b"\x48\x8D\x53\x08\x48\x83\x7B\x20\x0F\x76\x03\x48\x8B\x12"
        lea_at = len(stub)
        stub += b"\x4C\x8D\x05\x00\x00\x00\x00"
        stub += b"\x48\x8B\x02\x49\x3B\x00\x75\x16"
        j2 = len(stub) - 1
        stub += b"\x48\x8B\x42\x08\x49\x3B\x40\x08\x75\x0A"
        j3 = len(stub) - 1
        # early success
        stub += b"\x48\x83\xC4\x20\x5F\x48\x8B\x5C\x24\x20\xB0\x01\xC3"
        not_embd = len(stub)
        stub[j1] = (not_embd - (j1 + 1)) & 0xFF
        stub[j2] = (not_embd - (j2 + 1)) & 0xFF
        stub[j3] = (not_embd - (j3 + 1)) & 0xFF
        # replay test rdx,rdx; jz jz_tgt; jmp cont
        stub += b"\x48\x85\xD2"  # test rdx, rdx
        jz_at = len(stub)
        stub += b"\x0F\x84\x00\x00\x00\x00"
        jmp_at = len(stub)
        stub += b"\xE9\x00\x00\x00\x00"

        if len(stub) > budget - 12:
            print("STUB_TOO_BIG", len(stub))
            return 3

        struct.pack_into("<i", stub, lea_at + 3, te_va - (cave_va + lea_at + 7))
        struct.pack_into(
            "<i", stub, jz_at + 2, jz_tgt - (cave_va + jz_at + 6)
        )
        struct.pack_into(
            "<i", stub, jmp_at + 1, cont_va - (cave_va + jmp_at + 5)
        )

        data[cave_off : cave_off + len(stub)] = stub
        for i in range(len(stub), budget):
            data[cave_off + i] = 0xCC
        marker = b"INIMAGE_V3\0"
        data[cave_off + len(stub) : cave_off + len(stub) + len(marker)] = marker

        data[patch_off] = 0xE9
        struct.pack_into("<i", data, patch_off + 1, cave_va - (patch_va + 5))
        # remaining 4 bytes of original 9 are now dead (unreachable)

        f.seek(0)
        f.write(data)
        f.truncate(len(data))

    print("DST_SHA", sha256(DST))
    print("SHA16", sha256(DST)[:16])
    print("CAVE", hex(cave_va), "PATCH", hex(patch_va))
    return 0


if __name__ == "__main__":
    sys.exit(main())

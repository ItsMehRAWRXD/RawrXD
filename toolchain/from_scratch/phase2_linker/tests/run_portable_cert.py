#!/usr/bin/env python3
"""RAWR_NATIVE_LINKER_PORTABLE_001: first-party COFF -> PE32+ certification.

Python standard library is used only by the test harness. The production linker
and COFF fixture generator remain pure C, with no third-party runtime dependency.
On Linux/macOS this certifies PE emission, not execution of Windows programs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

def u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated PE u16")
    return struct.unpack_from("<H", data, offset)[0]

def u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated PE u32")
    return struct.unpack_from("<I", data, offset)[0]

def u64(data, offset):
    if offset < 0 or offset + 8 > len(data):
        raise ValueError("truncated PE u64")
    return struct.unpack_from("<Q", data, offset)[0]

def read_cstr(data, offset):
    if offset < 0 or offset >= len(data):
        raise ValueError("string offset outside file")
    end = data.find(b"\0", offset, min(len(data), offset + 4096))
    if end < 0:
        raise ValueError("unterminated PE string")
    return data[offset:end].decode("ascii")

class PE:
    def __init__(self, path):
        b = Path(path).read_bytes()
        self.data = b
        if len(b) < 0x40 or b[:2] != b"MZ":
            raise ValueError("missing MZ signature")
        pe = u32(b, 0x3c)
        if pe + 24 > len(b) or b[pe:pe + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        coff = pe + 4
        self.machine = u16(b, coff)
        nsec = u16(b, coff + 2)
        opt_size = u16(b, coff + 16)
        opt = coff + 20
        if self.machine != 0x8664 or u16(b, opt) != 0x20b:
            raise ValueError("not a PE32+ x64 image")
        self.entry = u32(b, opt + 16)
        self.image_base = u64(b, opt + 24)
        self.section_alignment = u32(b, opt + 32)
        self.file_alignment = u32(b, opt + 36)
        self.size_image = u32(b, opt + 56)
        self.size_headers = u32(b, opt + 60)
        self.sections = []
        sec_base = opt + opt_size
        if sec_base + 40 * nsec > len(b):
            raise ValueError("section table truncated")
        for i in range(nsec):
            p = sec_base + 40 * i
            name = b[p:p + 8].split(b"\0")[0].decode("ascii")
            sec = dict(name=name, virtual_size=u32(b, p + 8),
                       rva=u32(b, p + 12), raw_size=u32(b, p + 16),
                       raw_offset=u32(b, p + 20), characteristics=u32(b, p + 36))
            if sec["raw_offset"] + sec["raw_size"] > len(b):
                raise ValueError("section extends past EOF: " + name)
            if sec["rva"] + sec["virtual_size"] > self.size_image:
                raise ValueError("section exceeds image size: " + name)
            self.sections.append(sec)
        self.directories = []
        count = min(16, u32(b, opt + 108))
        if opt + 112 + count * 8 > sec_base:
            raise ValueError("data directories exceed optional header")
        for i in range(count):
            self.directories.append((u32(b, opt + 112 + i * 8),
                                     u32(b, opt + 116 + i * 8)))

    def rva_offset(self, rva, size=1):
        for s in self.sections:
            if s["rva"] <= rva and rva + size <= s["rva"] + s["raw_size"]:
                off = s["raw_offset"] + rva - s["rva"]
                if off + size <= len(self.data):
                    return off
        raise ValueError("unmapped RVA 0x%x size %d" % (rva, size))

    def imports(self):
        if len(self.directories) < 2 or self.directories[1][0] == 0:
            return []
        start = self.directories[1][0]
        records = []
        for i in range(64):
            d = self.rva_offset(start + i * 20, 20)
            ilt, _, _, name_rva, iat = struct.unpack_from("<IIIII", self.data, d)
            if not (ilt or name_rva or iat):
                break
            name = read_cstr(self.data, self.rva_offset(name_rva))
            funcs = []
            for j in range(256):
                t = u64(self.data, self.rva_offset(ilt + 8 * j, 8))
                if t == 0:
                    break
                if t & (1 << 63):
                    funcs.append("#" + str(t & 0xffff))
                else:
                    funcs.append(read_cstr(self.data, self.rva_offset(t + 2)))
            records.append(dict(dll=name, functions=funcs, ilt=ilt, iat=iat, name_rva=name_rva))
        return records

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--linker", required=True, type=Path)
    ap.add_argument("--fixtures", required=True, type=Path)
    ap.add_argument("--workdir", required=True, type=Path)
    ap.add_argument("--report", type=Path)
    args = ap.parse_args()
    linker = args.linker.resolve()
    fixtures = args.fixtures.resolve()
    work = args.workdir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    results = {}
    def check(name, condition, detail=""):
        results[name] = dict(pass_=bool(condition), detail=str(detail))
        print(("[PASS] " if condition else "[FAIL] ") + name + (" " + str(detail) if detail else ""))
    def run(command):
        return subprocess.run([str(x) for x in command], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=60)
    def link(name, fixture, *flags):
        output = work / name
        if output.exists():
            output.unlink()
        p = run([linker, "-o", output, "-subsys", "3", "-entry", "entry",
                 *flags, work / fixture])
        return output, p

    try:
        check("tools_exist", linker.is_file() and fixtures.is_file())
        if not linker.is_file() or not fixtures.is_file():
            raise ValueError("linker or COFF fixture generator missing")
        gen = run([fixtures, work])
        check("fixtures_run", gen.returncode == 0, gen.stderr[-600:])
        for name in ["fixture_exit42.obj", "fixture_multi.obj", "fixture_undef.obj",
                     "fixture_addr64.obj", "fixture_tail.obj", "fixture_call.obj"]:
            check("fixture_" + name, (work / name).is_file())

        undef, p = link("must_not_link.exe", "fixture_undef.obj")
        check("reject_undefined_symbol", p.returncode != 0 and not undef.exists()
              and re.search("unresolved|could not be bound", p.stdout + p.stderr, re.I) is not None)

        output, p = link("exit42.exe", "fixture_exit42.obj")
        check("emit_exit42", p.returncode == 0 and output.is_file(), p.stderr[-500:])
        if output.is_file():
            pe = PE(output)
            check("pe32plus_x64", pe.machine == 0x8664)
            check("entry_nonzero", pe.entry != 0)
            check("image_base", pe.image_base == 0x140000000)
            check("section_alignment", pe.section_alignment == 0x1000)
            check("file_alignment", pe.file_alignment == 0x200)
            check("header_alignment", pe.size_headers > 0 and
                  pe.size_headers % pe.file_alignment == 0)
            check("image_alignment", pe.size_image > 0 and
                  pe.size_image % pe.section_alignment == 0)
            check("section_order", all(a["rva"] <= b["rva"]
                  for a, b in zip(pe.sections, pe.sections[1:])))
            imports = pe.imports()
            check("import_descriptors", len(imports) >= 1)
            check("import_kernel32_exitprocess", any("kernel32" in i["dll"].lower()
                  and "ExitProcess" in i["functions"] for i in imports))
            check("import_image_relative_rvas", all(i["ilt"] >= 0x1000 and
                  i["iat"] >= 0x1000 and i["name_rva"] >= 0x1000 for i in imports))
            check("iat_is_writable", all(any(s["rva"] <= i["iat"] <
                  s["rva"] + s["virtual_size"] and
                  s["characteristics"] & 0x80000000 for s in pe.sections) for i in imports))
            if os.name == "nt":
                r = run([output])
                check("windows_exit42", r.returncode == 42, r.stderr[-500:])
            else:
                print("[SKIP] Windows loader execution requires Windows runner")

        multi, p = link("multi.exe", "fixture_multi.obj")
        check("emit_multi_import", p.returncode == 0 and multi.is_file())
        if multi.is_file():
            mi = PE(multi).imports()
            fnames = {fn for imp in mi for fn in imp["functions"]}
            for name in ["ExitProcess", "GetStdHandle", "GetTickCount"]:
                check("multi_import_" + name, name in fnames)
            if os.name == "nt":
                check("windows_multi_exit42", run([multi]).returncode == 42)

        dataexe, p = link("addr64.exe", "fixture_addr64.obj")
        check("emit_addr64", p.returncode == 0 and dataexe.is_file())
        if dataexe.is_file():
            check("data_section", any(s["name"] == ".data" for s in PE(dataexe).sections))

        da, p1 = link("det_a.exe", "fixture_exit42.obj", "-deterministic")
        db, p2 = link("det_b.exe", "fixture_exit42.obj", "-deterministic")
        check("deterministic_bytes", p1.returncode == 0 and p2.returncode == 0
              and da.is_file() and db.is_file()
              and hashlib.sha256(da.read_bytes()).digest() == hashlib.sha256(db.read_bytes()).digest())

        if os.name == "nt":
            for fixture, expected in [("fixture_tail.obj", 42), ("fixture_call.obj", 7)]:
                exe, p = link(fixture + ".exe", fixture)
                check("emit_" + fixture, p.returncode == 0 and exe.is_file())
                if exe.is_file():
                    check("execute_" + fixture, run([exe]).returncode == expected)
    except (ValueError, OSError, subprocess.TimeoutExpired, struct.error) as exc:
        check("cert_exception", False, str(exc))
    failed = [name for name, val in results.items() if not val["pass_"]]
    report = {"certificate": "RAWR_NATIVE_LINKER_PORTABLE_001",
              "host": sys.platform, "passed": len(results) - len(failed),
              "failed": failed, "checks": results,
              "scope": "PE32+ x64 emission; Windows loader execution only on Windows"}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "failed": failed}))
    return 1 if failed else 0

if __name__ == "__main__":
    sys.exit(main())

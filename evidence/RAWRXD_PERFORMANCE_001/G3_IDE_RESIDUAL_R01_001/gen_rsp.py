import re
import pathlib

bd = pathlib.Path(r"g:/~dev/rawrxd/build-fd")
text = (bd / "build.ninja").read_text(encoding="utf-8", errors="replace")
m = re.search(
    r"^build bin\\RawrXD-Win32IDE\.exe: CXX_EXECUTABLE_LINKER__RawrXD-Win32IDE_Release (.+)$",
    text,
    re.M,
)
if not m:
    raise SystemExit("build edge not found")
rest = m.group(1)
objs_part = rest.split("|")[0].strip()
objs = objs_part.split()


def norm(s: str) -> str:
    return s.replace("G$:", "G:").replace("C$:", "C:").replace("D$:", "D:")


objs = [norm(o) for o in objs]
chunk = text[m.end() : m.end() + 12000]
lm = re.search(r"LINK_LIBRARIES = (.+)", chunk)
pm = re.search(r"LINK_PATH = (.+)", chunk)
libs = norm(lm.group(1).strip()) if lm else ""
lpath = norm(pm.group(1).strip()) if pm else ""
rsp_lines = objs + [lpath, libs]
out = bd / "CMakeFiles" / "RawrXD-Win32IDE.rsp"
out.write_text("\n".join(rsp_lines) + "\n", encoding="utf-8")
print("wrote", out, "bytes", out.stat().st_size, "objs", len(objs))
print("deep2", [o for o in objs if "Deep2Engine" in o])
missing = [o for o in objs if o.endswith(".obj") and not pathlib.Path(bd / o).exists() and not pathlib.Path(o).exists()]
print("missing_count", len(missing))
for x in missing[:40]:
    print("MISSING", x)

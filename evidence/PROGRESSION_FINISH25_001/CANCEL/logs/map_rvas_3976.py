import struct
from pathlib import Path
exe=Path(r"F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe")
data=exe.read_bytes()
e=struct.unpack_from("<I",data,0x3C)[0]
coff=e+4
ns=struct.unpack_from("<H",data,coff+2)[0]
opt_size=struct.unpack_from("<H",data,coff+16)[0]
opt=coff+20
er,es=struct.unpack_from("<II",data,opt+112+3*8)
sec_off=opt+opt_size
sections=[]
for i in range(ns):
 o=sec_off+i*40
 name=data[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
 vsize,va,rawsize,rawptr=struct.unpack_from("<IIII",data,o+8)
 sections.append((name,va,vsize,rawptr,rawsize))
def rva_to_off(rva):
 for name,va,vsize,rawptr,rawsize in sections:
  if va<=rva<va+max(vsize,rawsize): return rawptr+(rva-va),name
 return None,None
ex_off,_=rva_to_off(er)
pdata=data[ex_off:ex_off+es]
entries=[struct.unpack_from("<III",pdata,i)[:2] for i in range(0,len(pdata),12)]
entries.sort()
# pull product frames from stack parse
text=Path(r"F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs\stack_parse_3976.txt").read_text(encoding="utf-8",errors="replace")
import re
rvas=sorted({int(m.group(1),16) for m in re.finditer(r"RawrXD-Win32IDE-Native\.exe\+0x([0-9A-Fa-f]+)", text)})
out=["SHA=4ED342CE"]
for r in rvas:
 hit=None
 for b,e2 in entries:
  if b<=r<e2: hit=(b,e2); break
 off,sec=rva_to_off(r)
 if hit: out.append(f"RVA=0x{r:X} FUNC=[0x{hit[0]:X}..0x{hit[1]:X}) SIZE={hit[1]-hit[0]}")
 else: out.append(f"RVA=0x{r:X} FUNC=NOT_IN_PDATA SEC={sec}")
# identify 0x5247 in candidate WndProc funcs near 0x119xxx
for b,e2 in entries:
 if 0x118000<=b<=0x11C000:
  off,_=rva_to_off(b)
  sl=data[off:off+(e2-b)]
  has=b"\x47\x52\x00\x00" in sl
  if has: out.append(f"GHOST_TIMER_FUNC=[0x{b:X}..0x{e2:X})")
Path(r"F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs\rva_pdata_map_3976.txt").write_text("\n".join(out)+"\n",encoding="utf-8")
print("\n".join(out))

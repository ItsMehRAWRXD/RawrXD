# Message-pump source map — `+0x12789F` on SHA 4ED342CE

ASOF_UTC=2026-11-09T03:22:00Z
ACTIVE_SHA=4ED342CE16BC868681B06AA41C68B1719FE69BD8DA87357160D65EEE6A442885
METHOD=pdata + llvm-objdump on local tip EXE (no cdb)
PDB=ABSENT
MAPFILE=ABSENT
PROMOTE=0

## Binary placement

| Field | Value |
|-------|-------|
| Stack slot | rsp+0x480 RET `RawrXD-Win32IDE-Native.exe+0x12789F` |
| pdata | `[0x127820..0x1278F8)` SIZE=**216** |
| F41 analog | `+0x127AEF` in `[0x127A70..0x127B48)` SIZE=216 (same-shaped helper, tip-shifted) |

## Disasm shape (tip EXE 18FA04F9 cross-check; layout matches sealed pdata size)

Source log: `CANCEL/logs/disasm_tip18FA_127820_llvm.txt`

```
0x127820  prologue / SEH-ish frame (sub $0x188)
0x12788c  xor r9,r8,edx ; lea msg ; call IAT     → GetMessageW-class
0x12789f  test eax,eax ; jle exit                ← STACK RET SITE
0x1278a3  load HWND from [this+0x570]
0x1278b7  call IAT                               → TranslateMessage-class
0x1278c6  call IAT                               → (pair)
0x1278d1  call IAT                               → DispatchMessage-class
0x1278d8  jmp 0x12788c                           → loop
```

```
RET_SITE_MEANING=return address immediately after GetMessage IAT call
NESTING=fault in comctl32 while this pump frame is live below user32
  (GetMessage nested sent-message dispatch and/or later DispatchMessage —
   residual scan cannot separate; no product WndProc on 4ED stack)
```

4ED dump MemoryList did **not** contain EXE bytes at `base+0x127820`; identity rests on pdata from the sealed 4ED EXE mapping pass (`rva_pdata_map_3976.txt`) plus same-size helper disasm on the drifted tip binary.

## Source family (fail-closed)

| Candidate | Evidence | Verdict |
|-----------|----------|---------|
| `Win32IDE::runMessageLoop` (`Win32IDE_Core.cpp` ~2622+) | Product message-loop owner; tip **source** now Peek+MsgWait+Drain | Family owner; **not** byte-exact to this 216B GetMessage helper |
| Compact GetMessage/Translate/Dispatch helper (Window / dialog / nested pump) | 216B pdata + `this+0x570` HWND load matches a small member pump | **Best binary match**; exact .cpp line **unproven without PDB** |
| GhostText `editorProc` | Present F41; **absent** 4ED | Eliminated as live stack owner on 4ED |

```
SOURCE_MAP=
  BINARY_FUNC=compact_member_GetMessage_pump @ [0x127820..0x1278F8)
  PRODUCT_FAMILY=Win32IDE UI message pump (Core/Window)
  EXACT_SOURCE_LINE=UNPROVEN (no PDB/map)
  LIVE_MSG_OR_CONTROL_AT_CRASH=UNPROVEN
```

## Law

```
MESSAGE_PUMP_FRAME ≠ ORIGIN
NEAREST_PRODUCT_FRAME ≠ OWNERSHIP_PROOF
NOT_RUN ≠ PASS
```

# Origin assessment — SHA 4ED342CE (fail-closed, evidence-only)

ASOF_UTC=2026-11-09T03:22:00Z
ACTIVE_SHA=4ED342CE16BC868681B06AA41C68B1719FE69BD8DA87357160D65EEE6A442885
AUTHORITY=User Crash Evidence Update + POST_E59D_CANDIDATE_001/NEXT_ACTION.md
CDB=NOT_INSTALLED
AVOID_RECURSIVE_CDB_SEARCH=1
STOP_SPECULATIVE_UI_FIXES=1
PROMOTE=0
CERTIFIED=0
T08_REOPEN=0
FINISH_25=19

## Inputs analyzed (sealed only)

| Artifact | Role |
|----------|------|
| `CANCEL/CRASH_STACK_4ED342CE.md` | 4ED stack seal |
| `CANCEL/CRASH_STACK_F41BAFB8.md` | F41 contrast (GhostText present) |
| `CANCEL/logs/stack_parse_3976.txt` (+ alt) | residual RSP scan |
| `CANCEL/logs/stack_parse_35440.txt` | F41 residual |
| `CANCEL/logs/rva_pdata_map_3976.txt` | pdata for +0x12789F |
| `CANCEL/logs/exception_context_4ED342CE_deepened.txt` | full regs + fault insn |
| `CANCEL/logs/disasm_tip18FA_127820_llvm.txt` | pump shape cross-check |
| `CANCEL/logs/WER_F41BAFB8/Report.wer` | COMCTL32 5.82 version |
| `%LOCALAPPDATA%\CrashDumps\RawrXD-Win32IDE-Native.exe*.3976.dmp` | present (copies also under CANCEL/logs) |

Sealed remote evidence `36c15cbe` untouched.

## Exception context (deepened)

```
FAULT_SITE_OBSERVED=COMCTL32.dll+0xBD02
FAULTING_INSTRUCTION=mov word ptr [rcx], ax   ; bytes 66 89 01
AV_WRITE_TARGET=0xC04C54E510 (=Rcx=Rdi=R15)
COMCTL32_VARIANT=5.82.26100.8328 (WER Sig[4]; module size 0xB5000)
PE_TEXT_RVA_MATCHING_BYTES=0x96D2C in WinSxS common-controls 5.82.26100.8328
Rbp=0xF000 Rdx=0xFFFF  (same sentinel pattern as F41)
Rax=0x4D R12=0x40D     (recorded; hwnd/class NOT proven from these)
HWND_CLASS=NOT_RECOVERABLE (HandleDataStream absent)
```

`COMCTL32+0xBD02 = OBSERVED_FAULT_SITE ≠ PROVEN_ORIGIN`.

## Stack contrast (origin filter)

| | F41BAFB8 | 4ED342CE |
|--|----------|----------|
| GhostText `editorProc` on stack | YES `+0x119EB0` @ rsp+0x360 | **ABSENT** |
| Nearest product | editorProc + pump | pump only `+0x12789F` @ rsp+0x480 |
| COMCTL32 AV write | YES | YES |
| REQUEST_A_SURVIVES | 0 | 0 |

```
GHOSTTEXT_CLEARED_FROM_STACK=1
GHOSTTEXT_AS_LIVE_CALLBACK_OWNER_ON_4ED=NOT_SUPPORTED
PRODUCT_WNDPROC_ON_4ED_STACK=0
ORIGIN_CALLBACK=UNPROVEN
CONTROL_LIFETIME_DEFECT=UNPROVEN
```

Clearing GhostText from the fault stack did **not** clear Request A death. That falsifies GhostText-as-sole-owner for 4ED; it does **not** by itself prove a replacement owner.

## Message-pump source map (`+0x12789F`)

See `CANCEL/MESSAGE_PUMP_SOURCE_MAP_4ED342CE.md`.

```
PDATA=[0x127820..0x1278F8) SIZE=216
RET_SITE=+0x12789F = instruction after GetMessage IAT call (test eax,eax)
SHAPE=compact GetMessage → TranslateMessage → DispatchMessage loop (member this+0x570 HWND)
SOURCE_FAMILY=Win32IDE message-pump helper (not the large accelerator body alone)
BINARY_VS_TIP_SOURCE=tip Core.cpp runMessageLoop currently coded Peek+MsgWait;
  exercised 4ED/tip pump frame is GetMessage-shaped 216B helper — map is to pump family, not a single proven line without PDB
PDB=ABSENT MAP=ABSENT
PUMP_BYTES_IN_4ED_DUMP_MEMORYLIST=ABSENT (map via pdata + llvm on drifted tip EXE 18FA04F9)
```

Live path at crash: UI thread nested inside user32/comctl32 callback chain with pump frame below; **no product subclass on 4ED residual stack**. Message identity / control HWND at fault = **not recovered**.

## Ownership / tip-fix gate

```
TIP_FIX_JUSTIFIED_BY_STACK=0
OWNERSHIP_LIFETIME_CAUSALITY=NOT_PROVEN
TIP_FIX=NOT_APPLIED
STOP_SPECULATIVE_UI_FIXES=1
```

Hypothesis (confidence **LOW**, not actionable): remaining Request A deaths are inside a comctl32 v5.82 control callback (AV write via `mov [rcx],ax` with poisoned RCX) reached through the main UI GetMessage/Dispatch nesting — possible use-after-free / invalid control state — **without** a dump-proven product WndProc or HWND/class to patch against.

Do **not** patch from this hypothesis.

## Tip EXE drift note

```
LOCKED_SHA=4ED342CE…
BUILD_DIR_EXE_NOW=18FA04F9… (size still 2509824)
REBUILD_NOT_PERFORMED=1  (no justified tip fix)
```

## Gate board

```
REQUEST_A_SURVIVES=0
TIP_FIX=NOT_APPLIED
T05=NOT_RUN
T10=NOT_RUN
T07=NOT_RUN
T08=NOT_RUN
T17=NOT_RUN
PROMOTE=0
CERTIFIED=0
NOT_RUN != PASS
NEXT_GATE=ORIGIN_CALLBACK_OR_LIFETIME_STILL_OPEN
```

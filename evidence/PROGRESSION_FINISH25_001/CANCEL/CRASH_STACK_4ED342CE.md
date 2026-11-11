# 4ED342CE Request A native crash stack (fail-closed)

ASOF_UTC=2026-11-09T03:11:30Z
ACTIVE_CANDIDATE_SHA=4ED342CE16BC868681B06AA41C68B1719FE69BD8DA87357160D65EEE6A442885
PRIOR_TIP_SHA=F41BAFB874DEEA452D2BD0E8FE5EFB848D1E148E2E58192DB344B16831B33C75
PID=3976
HARNESS=REQUEST_A_SURVIVAL_RESULT_20261108-221114.txt
PROMOTE=0
CERTIFIED=0
T08_REOPEN=0
STOP_SPECULATIVE_UI_FIXES=1

## Artifacts sealed

| Kind | Path |
|------|------|
| Primary dump | `CANCEL/logs/RawrXD-Win32IDE-Native.exe.3976.dmp` |
| Alt dump | `CANCEL/logs/RawrXD-Win32IDE-Native.exe(1).3976.dmp` |
| Stack residual | `CANCEL/logs/stack_parse_3976.txt` |
| Stack residual alt | `CANCEL/logs/stack_parse_3976_alt.txt` |
| pdata map | `CANCEL/logs/rva_pdata_map_3976.txt` |
| Rebuild log | `CANCEL/logs/deterministic_rebuild_F41.txt` |
| Ninja stdout | `CANCEL/logs/deterministic_ninja_stdout.txt` |

cdb: NOT_PRESENT. Residual minidump parse used.

## Exception context

| Field | Primary | Alt |
|-------|---------|-----|
| ExceptionThreadId | 36868 | 36868 |
| ExceptionCode | `0xC0000005` AV write | `0xC000041D` |
| ExceptionAddress | `comctl32.dll+0xBD02` | same |
| Info[1] | `0xC04C54E510` | 0 |
| Context.Rbp | `0xF000` | same |
| Context.Rdx | `0xFFFF` | same |

```
OBSERVED_FAULT_SITE=COMCTL32.dll+0xBD02
OBSERVED_FAULT_SITE_NE_PROVEN_ORIGIN=1
EXIT=0xC000041D
CRASH_TIMING_S=~4.5
```

## Product frames vs F41

| | F41 (35440) | 4ED342CE (3976) |
|--|-------------|-----------------|
| GhostText editorProc on stack | YES `+0x119EB0` @ rsp+0x360 | **ABSENT** |
| Nearest product frame | editorProc + message pump | message pump only `+0x12789F` @ rsp+0x480 |
| COMCTL32+0xBD02 | YES | YES |

GhostText timer funcs still linked in EXE (`[0x119C60..0x11A2E5)`, `[0x118520..0x1185FB)`) but **not present on the faulting residual stack**.

```
GHOSTTEXT_DETACH_ON_4ED342CE=STACK_CLEARED_EDITORPROC
GHOSTTEXT_DETACH_CLEARS_REQUEST_A=0
STREAMING_BUFFER_FIX=BUILT (partial_buffered string present) / RUNTIME_SURVIVAL=FAIL
```

## HWND / control context

```
MINIDUMP_HANDLE_DATA_STREAM=ABSENT
WER_CONTROL_HWND_LIST=NOT_CAPTURED_THIS_RUN
HARNESS_MAIN_HWND=0x6709F8
HARNESS_CONTROL_IDS=input=1202 send=1204 combo=1206 stop=1210
ACTIVE_PRODUCT_SUBCLASS_ON_STACK=NONE_OBSERVED
NEAREST_PRODUCT_FRAME=RawrXD-Win32IDE-Native.exe+0x12789F (message loop pdata [0x127820..0x1278F8))
```

## Ownership audit (evidence only)

```
UI_THREAD=36868
CALLBACK_CHAIN=user32 ↔ comctl32+0xBD02 (AV write)
PRODUCT_WNDPROC_ON_STACK=0
GHOSTTEXT_AS_LIVE_CALLBACK_OWNER=NOT_SUPPORTED_BY_THIS_STACK
ORIGIN=UNPROVEN
TIP_FIX_JUSTIFIED_BY_STACK=0 (no ownership/lifetime target identified on stack)
```

Do not patch from hypothesis. Do not advance Finish-25. Do not reopen T08.

## Law

```
NOT_RUN != PASS
REQUEST_A_SURVIVES=0
PROMOTE=0
NEXT_GATE=ORIGIN_BEYOND_GHOSTTEXT (still fail-closed)
```

# T08_NEG1_DUMP_PARSE — residual terminate dump

ASOF_UTC=2026-11-09T07:47:02Z
FREEZE_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
EXE_SHA256=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
SHA_MATCH=1
MARKER_SHA_0F054F01_CONFLATED=0
DUMP=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\procdump_r4_26936.dmp
DUMP_SIZE=228102757
DUMP_KIND=procdump_-t_TERMINATE
PARSE_TXT=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\stack_parse_t08_neg1.txt
PARSER=residual_minidump (CANCEL CRASH_STACK_4ED342CE approach; no cdb)
PROMOTE=0
STOP_SPECULATIVE_EDITOR_BATCH=1

## Streams

```
Streams=0,3,4,7,9,11,12,13,14,15,16,17,19,21,22
ThreadCount=1
ModuleCount=121
MemoryKind=Memory64List Ranges=973
ExceptionStreamPresent=0
```

## Exception

- EXCEPTION=**no** (stream absent/empty; consistent with procdump `-t` TERMINATE)

## Last PC / primary thread

- PrimaryTid=3344
- LastPC=`ntdll.dll+0x16A0B4` (0x7FFF1451A0B4)
- Rsp=0x2142FFBC8
- StackScanMode=RSP_DIRECT
- RspInMappedMemory=True

## Product frames

NONE on primary residual stack scan.

## Key modules (abbrev)

```
comctl32.dll base=0x7FFEE3770000 size=0xB5000
comctl32.dll base=0x7FFEFE3B0000 size=0x291000
gdi32.dll base=0x7FFF13780000 size=0x2B000
gdi32full.dll base=0x7FFF115A0000 size=0x129000
imm32.dll base=0x7FFF13D00000 size=0x31000
kernel32.dll base=0x7FFF13F60000 size=0xCB000
KERNELBASE.dll base=0x7FFF11820000 size=0x409000
msctf.dll base=0x7FFF125D0000 size=0x15B000
msvcp140.dll base=0x7FFEA2BC0000 size=0x9D000
msvcp_win.dll base=0x7FFF11E50000 size=0xA3000
ntdll.dll base=0x7FFF143B0000 size=0x26C000
ole32.dll base=0x7FFF138E0000 size=0x199000
RawrXD-Win32IDE-Native.exe base=0x7FF7B7990000 size=0x27D000
riched20.dll base=0x7FFE5AC20000 size=0xBE000
user32.dll base=0x7FFF13570000 size=0x1DE000
VCRUNTIME140.dll base=0x7FFEFA5C0000 size=0x2C000
VCRUNTIME140_1.dll base=0x7FFEF6C80000 size=0xC000
win32u.dll base=0x7FFF11570000 size=0x27000
```

## Threads summary

| Tid | RIP | Module |
|-----|-----|--------|
| 3344 | `ntdll.dll+0x16A0B4` | ntdll.dll |

## Disposition (fail-closed)

```
EXCEPTION_YES_NO=no
CAUSALITY_PROVEN=0
OWNERSHIP_LIFETIME_PROVEN=0
TIP_FIX=NOT_APPLIED
TIP_FIX_YES_NO=no
PROMOTE=0
WER_EXCEPTION_DUMP=NONE_THIS_CAPTURE
NEXT_GATE=HOLD_FOR_EXCEPTION_DUMP (LocalDumps+procdump -e 1 armed; T08 intermittent)
```

Do not conflate MARKER_SHA 0F054F01. Do not invent PASS.

## ThreadInfo deepen (stream 17)

```
ThreadInfoEntries=1
tid=3344 flags=0x0 exit_status=0x103 (STILL_ACTIVE) start=0x7FFF143D4990
CommentW=Process termination; cmdline=procdump64 -accepteula -t -e -ma -n 1 26936 ...
ExceptionStream=ABSENT (type 6 not in directory)
OnlyOneThreadAtTerminate=1
PRODUCT_FRAMES_ON_PRIMARY=NONE
LastPC=ntdll.dll+0x16A0B4 (termination path; not product locus)
```

Residual stack RET candidates near RSP show ntdll/kernel32/urlmon/iertutil/rpcrt4/sspicli/combase — **not** ownership/lifetime proof for editor tip.


## Exception-first re-stress (this turn)

```
ASOF_UTC=2026-11-09T08:05:29Z
PROCDUMP=-e 1 -t -ma -n 2
LOCALDUMPS=ENABLED (DumpType=2 -> dumps_t08_neg1)
RUNS=8 SURVIVED=8 FAIL_MAIN_LOST=0
EXCEPTION_DUMP_NEW=NONE
TERMINATE_DUMP_NEW=NONE
REPRO_HIT=0 (T08 intermittent; exit=-1 not reproduced this batch)
SEAL=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\T08_NEG1_EXC_CAPTURE_SEAL.md
RUNLOG=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\RUNLOG_T08_STRESS_EXC_FIRST.txt
```

## Return board

```
PARSE_SUMMARY=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\T08_NEG1_DUMP_PARSE.md
PARSE_TXT=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\stack_parse_t08_neg1.txt
EXCEPTION=no
TIP_FIX=no (NOT_APPLIED)
PROMOTE=0
```

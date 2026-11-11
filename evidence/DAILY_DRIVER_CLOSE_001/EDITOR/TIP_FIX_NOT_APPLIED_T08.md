# TIP_FIX=NOT_APPLIED — T08 MAIN_LOST causality unproven

ASOF_UTC=2026-11-09T07:35:30Z
FREEZE_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8
SIZE=2592256
EXE=F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe
SHA_VERIFIED=1
STOP_SPECULATIVE_EDITOR_BATCH=1
PROMOTE=0
PRODUCT_PASS=0
CERTIFIED=0
INVENT_PASS=0
NOT_RUN!=PASS=1
NO_CROSS_SHA_PASS_INHERITANCE=1

## Mission result

```
TIP_FIX=NOT_APPLIED
T08_ORIGIN=ABNORMAL_EXIT_NEG1_TERMINATE_DUMP
CAUSALITY_PROVEN=0
STACK=NONE (cdb not at known Windows Kits paths; no recursive hunt)
REBUILD=HELD
NEW_SHA=N/A
DUMP_PATH=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\dumps_t08_neg1\procdump_r4_26936.dmp
DUMP_SIZE=228102757
DUMP_KIND=procdump_-t_terminate (NOT WER/exception LocalDumps)
WER_EXCEPTION_DUMP=NONE
```

## Capture enablement

```
LocalDumps HKLM\...\LocalDumps\RawrXD-Win32IDE-Native.exe = DumpType=2 DumpFolder=EDITOR\dumps_t08_neg1
LocalDumps HKCU\...\LocalDumps = DumpType=2 same folder
procdump64 -t -e -ma attached each stress run
```

## Evidence this turn

| Run | Context | openOk | Lost-at | Exit | Dump | Result |
|-----|---------|--------|---------|------|------|--------|
| Stress A #1 (-e only) | T08-only | 5 | i=5 mid-open | **-1** | NONE | FAIL_MAIN_LOST |
| Stress B #1 (-t -e) | T08-only | 10 | — | RUNNING | NONE | SURVIVED |
| Stress B #2 | T08-only | 10 | — | RUNNING | NONE | SURVIVED |
| Stress B #3 | T08-only | 10 | — | RUNNING | NONE | SURVIVED |
| Stress B #4 | T08-only | 6 | i=6 mid-open | **-1** | **procdump_r4_26936.dmp** | FAIL_MAIN_LOST |

Stress B#4: `post_open5` alive tc=7 → `pre_open6` hasExited=True exitCode=-1 main=0 enum=ROOT_ZERO. Terminate dump written by procdump `-t`. No WER LocalDumps exception dump.

## RCA (fail-closed)

```
CRASH_WITH_EXCEPTION_DUMP = NOT_OBSERVED
TERMINATE_DUMP_PROCDUMP_T = OBSERVED (memory image only)
STACK_ANALYZED           = 0 (cdb unavailable; no recursive hunt)
INTENTIONAL_EXIT_CODE_0  = NOT_OBSERVED
MSGLOOP_STUCK_ALIVE      = NOT_OBSERVED
TAB_CTRL_LIFETIME_BUG    = NOT_PROVEN
OWNERSHIP_CAUSALITY      = NOT_PROVEN
EXIT_NEG1_ALONE          = INSUFFICIENT for TIP_FIX
ASCII_NEEDLE_32MB        = no EXCEPTION_RECORD / STATUS_ACCESS_VIOLATION / ExitProcess string hit
```

## Candidate loci (unproven — do not patch)

1. Mid-open MAIN_LOST after openOk≈5–6 (this turn + historical).
2. Post-settle exit=-1 after openOk=10 (prior session).
3. Non-exception abort / ExitProcess(-1) / external kill — compatible with no WER dump; terminate image alone ≠ locus proof.

## Forbidden

- Speculative editor batch / tip climb on 71D14597 or build_ide 0F054F01
- Claiming DAILY_DRIVER_ACCEPTANCE=PASS
- TIP_FIX without stack-proven ownership/lifetime causality
- PROMOTE / PRODUCT_PASS / CERTIFIED

## Next gate

```
NEXT_GATE=ANALYZE_TERMINATE_DUMP_STACK_OR_EXCEPTION_DUMP_ON_FREEZE
THEN=ONE_MINIMAL_TIP_FIX_ONLY_IF_LOCUS_PROVEN
T05_THIS_SESSION=NOT_RUN
T10_THIS_SESSION=FAIL_SESSION_PRESENT_NOT_RESTORED (unchanged; not retested this dump turn)
```

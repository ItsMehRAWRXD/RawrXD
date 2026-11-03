# CANCEL — CRASH_ISOLATION (Request A)

ASOF_UTC=2026-11-03T12:18:00Z
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SIZE=6080512
PID_ORIGINAL=3664
PROMOTE=0
CERTIFIED=0
REBUILD=HELD
REBUILD_AUTHORIZED=0
GHOSTTEXT_REOPEN=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0

## Isolation checklist

| # | Item | Result | Notes |
|---|------|--------|-------|
| 1 | First-chance exception + native call stack | **NOT_PROVEN** | No cdb/windbg on host. Product unhandled path only (`last_crash.txt`). CONTEXT RVA parse unreliable (Rip nonsense). |
| 2 | Faulting module / thread / callback | **PARTIAL** | Module+RVA+TID proven. Exact UI callback (LISTBOX/TabCtrl/Send handler) **NOT_PROVEN**. |
| 3 | Correlate with Request A dispatch | **PASS** | RUNLOG: `REQUEST_A_SUBMITTED` → ~2.7s `CRASH_ARM` / `unhandled exception; minidump written`. Stop/B never reached. |
| 4 | Product vs harness-induced | **NOT_PROVEN** | See §Classification. |
| 5 | Reproduce same SHA (no source change) | **PARTIAL** | Single-BM_CLICK 30s: **NO_CRASH**. Triple-notify: hung before `REQUEST_A_SUBMITTED_TRIPLE` logged (inconclusive). Original Cancel crash sealed. |
| 6 | Candidate-only repair | **HELD** | No source change; defect not demonstrated to rebuild bar. |
| 7 | Full Cancel rerun after repair | **NOT_RUN** | Blocked. |

## Proven facts (sealed original Cancel)

```
EXIT_PROCESS=-1073740771 (0xC000041D STATUS_FATAL_USER_CALLBACK_EXCEPTION)
UNDERLYING=0xC0000005 ACCESS_VIOLATION write=1
FAULT_RIP=0x7FFC7BE7BD02
FAULT_MODULE=comctl32.dll
FAULT_RVA=0xBD02
EXCEPTION_TID=16940
DUAL_COMCTL32=1 (bases 0x7FFC7BE70000 and 0x7FFC92430000)
SHA_PRE=SHA_POST=3B720981… MATCH=1
STOP_REACHED=0
REQUEST_B_REACHED=0
```

Evidence:
- `CANCEL\CANCEL_RUNLOG.txt` / `CANCEL\RECEIPT.md` / `CANCEL\logs\console.txt`
- `CANCEL\logs\last_crash.txt`
- `CANCEL\logs\rawrxd-20261103-070906.dmp` (SHA256=313AA6C75270989AEDEDA456DAB214A0CFDCEE216C725F978122073D724B69ED)
- `CANCEL\logs\dump_parse_070906.txt` (dbghelp HIT comctl32+0xBD02)
- `C:\Users\Garrett\AppData\Local\CrashDumps\RawrXD-Win32IDE-Native.exe.3664.dmp`

## BATCH1 comparison

Identical fault signature to `BATCH1_CANCEL_RECOVERY_001`:
`0xC0000005` → process `0xC000041D`, **comctl32.dll RVA 0xBD02**.
BATCH1 hypothesized nested LISTBOX/TabCtrl reentrancy (tip SOURCE_WIRED, not in CERT 3B720981).
That remains a **hypothesis**, not a proven callback for this CERT run (no stack).

## Classification

| Claim | Status |
|-------|--------|
| Crash is real (not harness scrape false-fail) | **PROVEN** — minidump + last_crash |
| Fault in comctl32 user callback class | **PROVEN** (module+RVA+exit) |
| Exact product root cause (which callback) | **NOT_PROVEN** |
| PRODUCT_DEFECT (rebuild-authorizing) | **NOT_PROVEN** |
| HARNESS_INDUCED sole cause | **NOT_PROVEN** |
| Harness multi-notify amplifier | **SUSPECTED** — original ClickChild = BM_CLICK + sync WM_COMMAND + PostMessage; single BM_CLICK repro did not crash in 30s |

## Repro attempts (same SHA, no rebuild)

| Run | Method | Result |
|-----|--------|--------|
| Original Cancel harness | Triple ClickChild + long essay + Clear | CRASH `0xC000041D` ~3s after submit |
| `harness_repro_request_a_only.ps1` | Single BM_CLICK only | NO_CRASH_IN_30S (`REPRO_REQUEST_A_RESULT.txt`) |
| Inline REPRO2 triple | Triple notify | Inconclusive — no SUBMITTED log; script hang |

## Controlling fields

```
CRASH_ROOT_CAUSE=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
FAULT_SIGNATURE=PROVEN_COMCTL32_0xBD02_SAME_AS_BATCH1
HARNESS_ROLE=SUSPECTED_AMPLIFIER_NOT_SOLE_CAUSE
REBUILD=HELD
REBUILD_AUTHORIZED=0
CANCEL_A_STOP_B=FAIL
STALE_GHOSTTEXT=NOT_RUN
STOPPED_AT=CRASH_ON_REQUEST_A
NEXT_GATE=ISOLATE_REQUEST_A_CRASH
PROMOTE=0
CERTIFIED=0
```

## Next executable steps (still REBUILD=HELD)

1. Attach first-chance debugger (cdb/vs) on CERT_EXE; capture native stack at `comctl32!+0xBD02`.
2. Deterministic repro matrix: single vs triple click × short vs long prompt × Clear on/off.
3. Only if product callback proven → authorize NEW SHA rebuild with targeted fence; then full Cancel A→Stop→B.
4. If only harness multi-notify proven → fix harness ClickChild; retest Cancel on **same** 3B720981.

`NOT_RUN != PASS`. Do not invent PRODUCT_DEFECT or authorize rebuild from signature match alone.

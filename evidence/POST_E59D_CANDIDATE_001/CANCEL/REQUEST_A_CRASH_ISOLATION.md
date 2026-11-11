# POST_E59D Cancel — Request A crash isolation

ASOF_UTC=2026-11-03T12:10:00Z
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PID=3664
PROMOTE=0
CERTIFIED=0
REBUILD=HELD
REBUILD_AUTHORIZED=0
GHOSTTEXT_REOPEN=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0

## Exception (locked)

| Field | Value |
|-------|-------|
| Process exit | `-1073740771` = `0xC000041D` STATUS_FATAL_USER_CALLBACK_EXCEPTION |
| Underlying code | `0xC0000005` ACCESS_VIOLATION (write) |
| Fault address (last_crash) | `0x7ffc7be7bd02` |
| Fault module | **comctl32.dll** (HIT) |
| Fault RVA | **`0xBD02`** (identical to BATCH1) |
| Write target | `0x154AE8E0D0` |
| Dual comctl32 | Yes — bases `0x7FFC7BE70000` and `0x7FFC92430000` |
| Timing | `REQUEST_A_SUBMITTED` → crash ~2.7s (`070906`) |

## Evidence paths

```
CANCEL\RECEIPT.md
CANCEL\CANCEL_RUNLOG.txt
CANCEL\logs\console.txt
CANCEL\logs\last_crash.txt
CANCEL\logs\rawrxd-20261103-070906.dmp
CANCEL\logs\dump_parse_070906.txt
C:\Users\Garrett\AppData\Local\CrashDumps\RawrXD-Win32IDE-Native.exe.3664.dmp
C:\Users\Garrett\AppData\Local\RawrXD\crashes\rawrxd-20261103-070906.dmp
```

## Compare BATCH1_CANCEL_RECOVERY_001

| Dimension | BATCH1 (tip 74678E5A…) | POST_E59D (3B720981…) |
|-----------|------------------------|------------------------|
| Exit | `0xC000041D` | `0xC000041D` |
| AV code | `0xC0000005` write | `0xC0000005` write |
| Module | comctl32.dll | comctl32.dll |
| RVA | `0xBD02` | `0xBD02` |
| When | After REQUEST_A_SUBMITTED | After REQUEST_A_SUBMITTED |
| Stop/B reached | No | No |
| Class | NATIVE_UI / COMCTL32 | **SAME CLASS** |

BATCH1 hypothesis: nested common-controls on send (LISTBOX LBS_NOTIFY, thought timer,
TabCtrl reentrancy). Tip SOURCE_WIRED mitigations are **not** in CERT 3B720981.

## Harness vs product

| Claim | Verdict |
|-------|---------|
| Harness-only false fail | NOT_SUPPORTED (dump faults in comctl32) |
| Harness amplifier | POSSIBLE (triple click notify; long prompt A) |
| Product defect on CERT | ISOLATED_SAME_CLASS as BATCH1 |
| Ollama primary | NOT_PROVEN_PRIMARY |

## Checklist (Cancel gate)

```
1 A starts / actively generating     = 0
2 Stop invalidates A                 = 0
3 B starts after Stop                = 0
4 B completes/renders                = 0
5 Late A rejected                    = 0
6 No crash/hang/stale GT insert      = 0
7 SHA before/after match             = 1
```

## Rebuild policy

```
PRODUCT_DEFECT=ISOLATED_COMCTL32_REQUEST_A_SAME_AS_BATCH1
REBUILD=HELD
REBUILD_AUTHORIZED=0
STOPPED_AT=CANCEL_A_STOP_B
STALE_GHOSTTEXT=NOT_RUN
PROMOTE=0
```

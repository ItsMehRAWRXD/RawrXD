# CRASH_ORIGIN — Request A Cancel-path diagnostics (no rebuild)

ASOF_UTC=2026-11-08T22:30:00Z
AUTH=CONTINUE_FINISH_25_REMAINING
GATE=FINISH_25_REQUEST_A_CRASH_ORIGIN
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
SIZE=6080512
SHA_MATCH=1
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0

## Controlling result

```
CRASH_ORIGIN=COMCTL32_RVA_0xBD02_SAME_PATH_LIVE_REPRO
CRASH_ROOT_CAUSE=NOT_PROVEN
CONCRETE_CALLBACK=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
REQUEST_A_SURVIVES=0
T05=NOT_RUN
BATCH1_CANCEL_RECOVERY=FAIL
T18=BLOCKED
T19=BLOCKED
CAUSAL_CLOSURE=DEFERRED
```

Advance note: `CRASH_ORIGIN` moves beyond `NOT_PROVEN` only as **fault-locus / same-path identity**. It does **not** authorize PRODUCT_DEFECT or rebuild.

## Live Cancel-path Request A (this turn)

| Field | Value |
|------:|-------|
| Harness | NO_CLEAR + WM_SETTEXT_ONLY + SINGLE_BM_CLICK |
| Model | Local models / Ollama / gemma3:4b |
| SETEDIT_LEN | 171 |
| REQUEST_A_SUBMITTED | 1 |
| A_ARMED | 0 |
| Exit | `-1073740771` = `0xC000041D` STATUS_FATAL_USER_CALLBACK_EXCEPTION |
| Underlying | `0xC0000005` ACCESS_VIOLATION write=1 |
| Fault RIP (ASLR) | `0x7FFEE377BD02` |
| Fault RVA | **`0xBD02`** (identical to sealed triad) |
| TID | 28144 |
| NEW_DUMP | `CANCEL\logs\rawrxd-20261108-172824.dmp` |
| Survival | **0** — crash ~0.6–3.4s after Send; Stop/B never reached |

Artifacts:
- `REQUEST_A_SURVIVAL_RUNLOG_20261108-172816.txt`
- `REQUEST_A_SURVIVAL_RESULT_20261108-172816.txt`
- `harness_request_a_survival.ps1`

## Sealed triad preserved (untouched)

```
logs\rawrxd-20261103-070906.dmp  5839489
logs\rawrxd-20261103-073409.dmp  5837586
logs\rawrxd-20261103-092638.dmp  5876135
```

Live dump is additive evidence only — does not replace sealed dumps.

## Signature compare vs sealed triad (T02)

| Dump | Code | Write | RVA | Same path |
|------|------|-------|-----|-----------|
| 070906 | 0xC0000005 | 1 | comctl32+0xBD02 | Y |
| 073409 | 0xC0000005 | 1 | comctl32+0xBD02 | Y |
| 092638 | 0xC0000005 | 1 | comctl32+0xBD02 | Y |
| **172824 (live)** | 0xC0000005 | 1 | **+0xBD02** | **Y** |

```
SAME_PATH=YES
FAULT_SIGNATURE=PROVEN_COMCTL32_RVA_0xBD02
LIVE_REPRO_CANCEL_PATH=1
HARNESS_SOLE=REFUTED (already; live narrow harness still crashes)
```

## Gate consequences (fail-closed)

```
REQUEST_A_SURVIVES=0
→ T05 A→Stop→B + late A reject = NOT_RUN
→ BATCH1 = FAIL (unchanged)
→ T18/T19 = BLOCKED (Cancel/Request A prerequisites unmet)
→ REBUILD = HELD (no speculative rebuild; PRODUCT_DEFECT=NOT_PROVEN)
→ PROMOTE = 0
```

Phase3 sealed PASSes (T11–T15) unchanged. Agentic cancel 4107 ≠ Request-A Stop.

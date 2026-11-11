# EA5D_CC79_LINEAGE

ASOF_UTC=2026-11-09T11:13:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
ACTIVE_ACCEPTANCE=EA5D
ACTIVE_SHA=EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE
PRIOR_CONTROLLING_TIP=CC79
LINEAGE_RECONCILIATION=PENDING
IDLE_FOUR_PANEL_PROBE=ABORTED_SUPERSEDED
FROZEN_A4F_UNTOUCHED=1
NO_CROSS_SHA_PASS_INHERITANCE=1
NO_HISTORICAL_19_25_INHERIT=1
MASM_PE_WRITER=SEPARATE_TRACK  # must not delay v1.0 unless autonomous loop depends on it
```

## Ordered milestones (no feature expansion until measured)

1. **EA5D HWND receipt (next valid)** — same SHA: native Build output lines + Problems items>0 + click-to-line  
2. Debug UI on that SHA — BP / step / continue / stop  
3. Four-panel integration 1–17 on that SHA  
4. **Lineage reconciliation** — EA5D vs CC79 before advancing controlling tip  
5. Autonomous E2E — broken C++ project → inspect/repair/compile/run/test (decisive capability)  
6. Final certification — Finish-25 / regression / endurance / packaging on exact release EXE  

Autonomous E2E ≠ sole release gate; reliability + packaging still required after it.

## Law

```
ACTIVE_ACCEPTANCE ≠ PRIOR_CONTROLLING_TIP REPLACED
PARTIAL_HWND ≠ LINEAGE_RECONCILED ≠ PROMOTE ≠ PRODUCT_PASS ≠ CERTIFIED
```

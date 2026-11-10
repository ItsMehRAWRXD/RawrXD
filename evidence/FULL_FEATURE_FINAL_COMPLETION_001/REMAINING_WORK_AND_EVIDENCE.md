# Remaining work and evidence required for full acceptance

```text
ASOF_UTC=2026-11-09T13:12:00Z
ENGINEERING_MATURITY_ESTIMATE=82%
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
AUDIT_NEQ_ACCEPTANCE_PASS=1
CONTROLLING_TIP=CC79
PHASE_A=IN_PROGRESS_CHOOSE_LIVE_IMAGE
NO_PERCENTAGE_CREDIT_PER_ROW=1
```

**82% is an engineering maturity estimate, not a weighted completion score.**  
The 117 register entries cannot be divided into the remaining 18 percentage points.  
Reassess maturity only after a substantial integrated acceptance milestone (Issue #49–class single-SHA E2E).

## Register inventory (sealed — not 117 defects)

| Classification | Count | What must happen |
|---|---:|---|
| CONFIRMED | 9 | Fix each defect and verify acceptance on the applicable binary |
| UNVERIFIED | 81 | Locate valid evidence or run the missing gate |
| INVESTIGATE | 18 | Decide defect vs evidence gap vs duplicate vs out of scope |
| OPTIONAL | 9 | Explicitly retain or exclude from completion scope |
| **Total unique** | **117** | Every row needs an evidence-backed disposition |

Authoritative rows (do not invent B-ID mappings):

- `G:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\MASTER_REGISTER.md`
- `G:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\MASTER_REGISTER.csv`
- `G:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\EXECUTION_ORDER.md`
- `G:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\TRACK_STATUS.md`
- Mirrors: `F:\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\` and `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\`

## Exact immediate blockers (from MASTER_REGISTER)

| Order | ID | Definition (register text) | Required closure |
|------:|----|----------------------------|------------------|
| 1 | **B02** | INTEG_004 cross-subsystem incomplete (NEEDS_REVERIFY; sealed `47451` exe ABSENT; live tip drifts) | Choose **one** real image; remeasure Extension/Chat/Terminal/Output/Debug-headless/Problems+caret; SHA matrix |
| 2 | **B20** | Extension cleanup FAIL (`FORCE_KILL=1`) on sealed `47451F24…` | Clean `--ext-quit` / unload without force-kill on the **chosen** image |
| 3 | **B01** | CC79 Problems UI FAIL (`items=0`) on controlling `CC79F6CD…` | Problems on **authorized controlling** SHA; no candidate→CC79 inherit |
| 4 | **B03** | Tip-move authorization held (`TIP_MOVE_AUTHORIZED=0`) | Explicit auth only after B02 matrix; CC79 stays controlling until then |

Related (not reorder of the four): **B12** = Problems click → actual editor caret navigation (distinct from `POSTED_NM_DBLCLK`).

## Binary identity (measured this turn)

| Role | Full SHA-256 | Path |
|------|--------------|------|
| CONTROLLING | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` |
| Sealed INTEG_004 (receipt-only) | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | EXE **ABSENT** |
| Prior live tip_004 (superseded) | `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351` | overwritten |
| **Current live tip_004** | `27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC` | `...\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` (SHA256.txt MATCH) |
| A4F slim | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | immutable |

**Phase A policy:** because `47451F24…` cannot be recovered, Phase A proceeds on **chosen image = current tip_004 `27E2263E…`** as `RECONCILED_CANDIDATE`. Prior Problems PASS on `47451F24…` is **not** inherited.

## Acceptance areas still open (≠ new register rows)

Phase A · binary identity lineage · candidate≠controlling · B02–B03 chain · extension clean shutdown · build→Problems→caret · cancel A→Stop→B · agent edit→diff→save→reopen→build · chat routing · terminal · subprocess · command reachability · endurance · packaging · repo delivery · Finish-25 reconciliation.

## Next move

```text
1. Finish Phase A on 27E2263E… (six-gate matrix; no invent PASS)
2. Execute B02 → B20 → B01 → B03 using exact register definitions
3. Keep maturity 82% / PROMOTE=0 until Issue #49-class integrated milestone
```

# PHASE_A_PENDING â€” Candidate SHA binary not on disk

```text
ASOF_UTC=2026-11-09T12:40:00Z
MOTD_ACK=1
PHASE_A=PENDING
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_CLIMB=HOLD
CONTROLLING_TIP=CC79
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1
A4F_IMMUTABLE=1
```

## Binding disposition

Phase A **cannot** close. Acceptance for candidate
`47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F`
requires **both**:

1. Located binary whose live `Get-FileHash -Algorithm SHA256` equals that value, and
2. Corresponding acceptance receipts bound to that same SHA.

Filename / directory-name misses do **not** prove absence of receipts.
Absence of a matching **EXE image** does prove Phase A remains PENDING.

## Measured live hashes (this turn)

| Role | Path | Live SHA-256 | EQ `47451F24â€¦` |
|------|------|--------------|----------------|
| CONTROLLING | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | False |
| tip_003 | `...\tip_final_integ_003\RawrXD-Win32IDE-Native-Ext.exe` | `DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C` | False |
| tip_004 (slot) | `...\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351` | False |
| build twin | `F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe` | `35EFA9BAâ€¦` (same) | False |
| g:~dev live | `G:\~dev\rxdn_live\bin\RawrXD-Win32IDE.exe` | `896F8032199211C93FD7087616900B056B6A42E902C4390CD27CC968B107D3DA` | False |

**`896F8032â€¦` cannot inherit `47451F24â€¦` acceptance.**
**`35EFA9BAâ€¦` / prior tip_004 `69FE3D92â€¦` cannot inherit `47451F24â€¦` acceptance.**
**CC79 `CC79F6CDâ€¦` remains controlling; not a candidate substitute for Phase A.**

## Receipts present (EXE for `47451F24â€¦` ABSENT)

Authoritative local locator:
`F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LOCAL_INTEG004_FINISH25_LOCATOR.md`

Receipts sealed to `47451F24â€¦` (content exists; binary overwritten in tip_004 slot):

- `LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md`
- `INTEG004_ACCEPTANCE_DISPOSITION.md` (`TIP_MOVE_AUTHORIZED=0`)
- `INTEG004_EXT_REVERIFY_RECEIPT.md` (EXT_CLEANUP=FAIL â†’ EXTENSIONS=FAIL on that SHA)
- `FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt`
- rebuild stage log citing `REBUILD2_STAGE_SHA=47451F24â€¦`

Locator ABSENT list includes:
`ABSENT on-disk EXE SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F`

## Finish-25 (controlling tree; not Phase A close)

From `FINISH25_MATRIX.md` on CC79:

```text
FINISH25_HISTORICAL=19/25
HISTORICAL_REMAINING_SIX=T05,T07,T08,T18,T19,T25
FINISH25_CURRENT=4/25
FINISH25_CURRENT_PASS_LIST=T10,T16,T17,T20
```

## Closure gate (next executable step)

```text
IF located_binary.SHA256 == 47451F24â€¦ AND receipt_set.SHA256 == 47451F24â€¦
  THEN Phase A reverify MAY begin on that image
ELSE
  PHASE_A=PENDING
  BLOCKER=CANDIDATE_BINARY_ABSENT_OR_OVERWRITTEN
```

Recovery options (authorization required before tip move; none auto-promote):

1. Restore archived `47451F24â€¦` image into a **non-controlling** path and re-hash.
2. Or rebuild to reproduce `47451F24â€¦` bit-identical (unlikely) and re-hash.
3. Or open a **new** candidate SHA, run full Phase A on that SHA, and treat prior `47451F24â€¦` Problems receipts as historical-only (no inheritance).

Until (1) or measured new-SHA Phase A completes: keep `PROMOTE=0`, `CERTIFIED=0`, `PRODUCT_PASS=0`, `CONTROLLING_TIP=CC79`.

## Cross-bind (post GitHub reconcile)

`GITHUB_RECONCILIATION.md` (worker 426d4979): PRs #75–79 and Issues #49/#50/#57 are **not** bound to `47451F24…`. No GitHub item authorizes Phase A close or tip move. Aligns with `PHASE_A=PENDING` / `CANDIDATE_BINARY_ABSENT_OR_OVERWRITTEN`.

## Cross-bind (post local evidence inventory)

Worker 1148a412 inventory: `LOCAL_EVIDENCE_INVENTORY.md`. Confirms `47451F24…` RECEIPT_ONLY / EXE ABSENT; live tip_004 `35EFA9BA…`; Finish-25 historical open six `T05,T07,T08,T18,T19,T25`; Problems caret navigation separately NOT_FOUND (`POSTED_NM_DBLCLK` ? caret). Phase A synonym: `PENDING` = `BLOCKED_CANDIDATE_EXE_ABSENT`.

## Cross-bind (post Phase A reverify worker)

Worker 788dd466: `PHASE_A_SHA_MATRIX.md` / `.json` — all six gates **BLOCKED** on `47451F24…` (EXE absent). No substitute harness runs. Tip move not authorized. VS_UNICODE scrub receipts preserved only.

## Cross-bind (post source hidden-gap audit)

Worker 10fa8ffa: `SOURCE_HIDDEN_GAP_AUDIT.md` — static CONFIRMED risks (Problems dblclk/legacy path, dual ListView HWND, BuildRunner cancel/JobObject/VS_UNICODE gaps, cross-thread refresh, CMake `/FORCE:MULTIPLE` + Win32IDE default-OFF). These are **source defects / investigate targets**, not Phase A runtime PASS. Any repair rebuild ? **new SHA** ? prior `47451F24…` receipts remain non-inheritable; Phase A still requires candidate EXE recover or new-SHA full reverify. `PROMOTE=0`.

## Cross-bind (post master register dedupe)

Worker 18454125: `MASTER_REGISTER.md` / `.csv` / `EXECUTION_ORDER.md` — after dedupe CONFIRMED=9 UNVERIFIED=81 INVESTIGATE=18 OPTIONAL=9 (117 unique). Immediate: B02 ? B20 ? B01 ? B03. Maturity 82% unchanged. Live tip_004 errata: `35EFA9BA…` (not 69FE).

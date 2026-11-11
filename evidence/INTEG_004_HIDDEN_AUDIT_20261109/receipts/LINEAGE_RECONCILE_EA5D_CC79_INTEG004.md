# LINEAGE_RECONCILE — EA5D ↔ CC79 ↔ integ_004

ASOF_UTC=2026-11-09T11:39:00Z
MOTD_ACK=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
AUTO_PROMOTE_INTEG_004=0
CONTROLLING_TIP_CHANGE=0

## Evaluation of integ_004 HWND receipt ([Fresh integ_004 Problems HWND](3c5c4263-7c41-4dea-b530-a39afcd62d49))

| Check | Result |
|-------|--------|
| Bounded rebuild | PASS (staged tip_final_integ_004) |
| Fixture in EXE | PASS (`RAWRXD_PROBLEMS_FIXTURE` / via=cmd_s_pipe_scrub) |
| Problems HWND items | PASS (`PROBLEMS_ITEMS=3`) |
| Click-to-line | PASS (`POSTED_NM_DBLCLK`) |
| Evidence sealed to full SHA | PASS `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` |
| Auto-promote / tip move | **DENIED** |

Root cause (measured): inherited `VS_UNICODE_OUTPUT` hung `cl` after `/nologo` filename; scrub + FORCE_PIPE + drain fixed diagnostics feed to ID1312.

## Lineage board

| Tip | SHA-256 (full or sealed) | Role | Problems UI | Other gates |
|-----|--------------------------|------|-------------|-------------|
| EA5D tip_final_004 | `EA5D9B6979…` | Historical full-feature candidate | PARTIAL / HWND gaps | Separate track; Finish25_CURRENT was 4/25 — ≠ cert |
| CC79 tip_final_integ_002 | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | **CONTROLLING** | **FAIL** (fixture absent; items=0) | EXT/CHAT/TERM/OUTPUT_GUI/DEBUG_HEADLESS **PASS on CC79 only** |
| integ_004 | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | Problems-UI candidate | **PASS** (items=3, click) | EXT/CHAT/TERM/OUTPUT_GUI/DEBUG_HEADLESS = **NEEDS_REVERIFY** |
| A4F slim | `A4F083DF…` | Immutable daily-driver baseline | OUT_OF_SCOPE | UNTOUCHED |

```
CC79_UNRELATED_PASSES ≠ INTEG_004_PROBLEMS_PASS
INTEG_004_PROBLEMS_PASS ≠ CONTROLLING_TIP
INTEG_004_PROBLEMS_PASS ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE
EA5D_4_25 ≠ CC79_PASS_SET ≠ INTEG_004_MEASURE
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Authority decision (this receipt)

```
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_004
INTEG_004_PROBLEMS_UI=PASS
LINEAGE_RECONCILIATION=RECORDED
CONTROLLING_TIP_CHANGE=HELD
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_BASELINE=IMMUTABLE
```

integ_004 is **accepted as Problems-UI evidence only**. It does **not** replace CC79 as controlling tip until NEEDS_REVERIFY gates are remeasured on `47451F24…` (or an explicit owner authorization moves tip authority).

## Next gate

```
NEXT_GATE=NEEDS_REVERIFY_ON_47451F24_OR_OWNER_TIP_MOVE_AUTH
ORDER_HINT=IDE_DEBUG_UI_THEN_FOUR_PANEL_ON_CHOSEN_SHA_AFTER_REVERIFY_OR_AUTH
```

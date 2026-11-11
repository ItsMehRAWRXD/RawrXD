# NEXT_EXECUTABLE_GATES — HIDDEN_GAP_AUDIT_001

```
ASOF_UTC=2026-11-09T12:45:00Z
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
INTEG_004_SEALED_SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
INTEG_004_LIVE_DISK_SHA=69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB
A4F_IMMUTABLE=1
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
NO_CROSS_SHA_PASS_INHERITANCE=1
NOT_RUN_NE_PASS=1
```

## Ordering law

Execute in order. Do not tip-move. Do not inherit PASS across SHAs. Do not invent PASS. A4F slim baseline remains immutable.

```
TIP_MOVE_AUTHORIZED=0
CONTROLLING_TIP_CHANGE=HELD
47451F24_PROBLEMS_PASS ≠ LIVE_69FE3D92_PASS ≠ CC79_PASS
```

---

## Gate 1 — EXT_CLEANUP fix on INTEG lineage (CLOSED on INTEG_005)

| Field | Value |
|-------|-------|
| Gate ID | `G1_EXT_CLEANUP_INTEG004` → closed as `INTEG_005` |
| Status | **CLOSED** `ASOF_UTC=2026-11-09T12:50:18Z` |
| Closed SHA | `7504BAC45CDBA3DACF7A8CE30785971082C88101CC94586577771DE0C0FBAB48` |
| Closed EXE | `candidates\tip_final_integ_005\RawrXD-Win32IDE-Native-Ext.exe` |
| Outcome | `EXT_LOAD/ACTIVATE/UNLOAD/CLEANUP=PASS` · `FORCE_KILL=0` · `ORPHANS=0` · `EXTENSIONS=PASS` |
| Receipt | `INTEG005_EXT_REVERIFY_RECEIPT.md` · `logs\ext_smoke_tip_final_integ_005.txt` |
| Root cause | `--ext-quit` PostQuitMessage-only left HWND alive; destructor joined past WaitForExit |
| Fix | `main_win32` DestroyWindow + PostQuitMessage re-arm + ExitProcess |
| Controlling tip | Still CC79 — **no tip move** |
| Note | Prior `47451F24…` EXT_CLEANUP=FAIL remains historical; do not rewrite that receipt |

---

## Gate 2 — Chat reverify (same SHA as Gate 1 close)

| Field | Value |
|-------|-------|
| Gate ID | `G2_CHAT_REVERIFY` |
| Prerequisite | Gate 1 closed on chosen SHA |
| Why | CC79 Chat Ctrl+Enter 7/7 is sealed **on CC79 only**; INTEG lineage = `NEEDS_REVERIFY` |
| Evidence prior (CC79 only) | `CHAT_CTRL_ENTER_RECEIPT` / Finish25 T20 on CC79 |
| Required outcome | Chat send/stream path PASS on the Gate-1 SHA with SHA-specific receipt |
| Tip move | **UNAUTHORIZED** |

---

## Gate 3 — Terminal reverify (same SHA)

| Field | Value |
|-------|-------|
| Gate ID | `G3_TERM_REVERIFY` |
| Prerequisite | Gates 1–2 |
| Why | Terminal PASS sealed on CC79 / EA5D separately; not inherited to INTEG_004 |
| Maps to | Finish25 T17 · Issue #57 A09 · PR #77 ConPTY |
| Required outcome | Terminal start / output / exit / cancel / cleanup PASS on Gate-1 SHA |
| Tip move | **UNAUTHORIZED** |

---

## Gate 4 — Output panel reverify (same SHA)

| Field | Value |
|-------|-------|
| Gate ID | `G4_OUTPUT_REVERIFY` |
| Prerequisite | Gates 1–3 |
| Why | Final-completion OUTPUT_GUI=PASS is CC79-sealed; oneshot tip005 OUTPUT_HWND=FAIL is a separate axis — neither substitutes for INTEG SHA |
| Maps to | PR #77 Output routing · H20/H22 panel geometry axes (investigate only unless FAIL measured) |
| Required outcome | Output panel GUI E2E PASS on Gate-1 SHA (Build/output content, not chat contamination) |
| Tip move | **UNAUTHORIZED** |

---

## Gate 5 — Debug UI reverify (same SHA)

| Field | Value |
|-------|-------|
| Gate ID | `G5_DEBUG_UI_REVERIFY` |
| Prerequisite | Gates 1–4 |
| Why | CC79: `IDE_DEBUG_CONSOLE_UI_E2E=FAIL`; headless backend PASS ≠ Finish25 auto-credit ≠ UI PASS |
| Maps to | Finish25 T21–T23 (NOT_RUN for Finish credit) · Issue #57 A14 · H16/H18 HWND lifecycle investigate |
| Required outcome | Live IDE Debug UI E2E PASS (or sealed FAIL with SHA) on Gate-1 SHA |
| Tip move | **UNAUTHORIZED** |

---

## Gate 6 — Problems UI re-seal on chosen SHA (conjunction check)

| Field | Value |
|-------|-------|
| Gate ID | `G6_PROBLEMS_RESEAL` |
| Prerequisite | Gates 1–5 path chosen |
| Why | Problems PASS exists only as **candidate** on sealed `47451F24…`; CC79 remains FAIL (items=0); live disk tip may be `69FE3D92…` ≠ sealed |
| Maps to | H27/H28/H32 (VS_UNICODE_OUTPUT / pipe) historical · Finish25 Problems axis |
| Required outcome | On the **same** SHA as Gates 1–5: Problems items>0 + click-to-line, or explicit FAIL sealed |
| Tip move | **UNAUTHORIZED** until owner auth after conjunction |

---

## Gate 7 — Four-panel integrated acceptance on one SHA

| Field | Value |
|-------|-------|
| Gate ID | `G7_FOUR_PANEL` |
| Prerequisite | Gates 1–6 PASS on **one** SHA |
| Why | `FOUR_PANEL_INTEGRATION=OPEN` on CC79; major integrated acceptance = NOT_DEMONSTRATED |
| Required outcome | Chat + Term + Output + Problems + Debug UI operated together on one SHA with receipt |
| Tip move | Still held unless owner authorizes controlling-tip change |

---

## Gate 8 — Issue #49 product-final scenario (decisive maturity milestone)

| Field | Value |
|-------|-------|
| Gate ID | `G8_ISSUE49_PRODUCT_FINAL` |
| Prerequisite | Gate 7 + cert-ladder prerequisites (#50 Layers 0–9) as applicable; do not invent layer PASS |
| Why | Owner law: Issue #49 E2E is the decisive completeness milestone; does **not** by itself authorize tip move |
| Scenario | Fresh clone → launch → local model → R9700 → open project → agent find/fix/build/test → reviewer → evidence → git commit |
| Receipt keys | All #49 keys must be PASS / stub counters =0 (see `GITHUB_PR_ISSUE_INVENTORY.md`) |
| Required outcome | SHA-specific `RAWRXD_PRODUCT_FINAL_001` receipt; then maturity may be **reassessed** — still `PROMOTE=0` until promote tetrad |
| Tip move | **UNAUTHORIZED** unless separate owner authorization |

---

## Explicit non-gates (do not reorder ahead of G1–G8 for daily-driver Win32)

| Item | Disposition |
|------|-------------|
| Issue #57 B13–B15 ELF/Mach-O/Android | `OUT_OF_SCOPE` for Win32 daily-driver unless owner expands product-final scope |
| PR #75 16 native-linker CTests / multi-frontend compilers | Track after IDE conjunction; not Gate-1 substitute |
| PR #76 consolidation merge | Conflict resolution ≠ product PASS |
| Finish25 historical remaining six rewrite | Historical 19/25 immutable until controlling Finish-25 authority updates |
| A4F slim package overwrite | Forbidden (`A4F_IMMUTABLE=1`) |
| Maturity 82% change | Forbidden until Gate 8 (or owner) demonstrates major integrated acceptance |

## Scoreboard (post-audit)

```
NEXT_GATE=G1_EXT_CLEANUP_INTEG004
ORDER=EXT_CLEANUP → Chat → Term → Output → Debug → Problems_reseal → FourPanel → Issue49
TIP_MOVE_AUTHORIZED=0
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY_ESTIMATE=82%
ESTIMATE_CHANGE=0
```

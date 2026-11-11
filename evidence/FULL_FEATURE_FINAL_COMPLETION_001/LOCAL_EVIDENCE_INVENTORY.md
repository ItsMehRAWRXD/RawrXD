# LOCAL_EVIDENCE_INVENTORY — INTEG_004 / CC79 / Finish-25

```
ASOF_UTC=2026-11-09T12:45:00Z
WORKSPACE_REQUESTED=g:\~dev
AUTHORITY_TREE=F:\rawrxd   # historical + current IDE evidence lives here
FAIL_CLOSED=1
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONTROLLING_TIP=CC79
CANDIDATE=INTEG_004
CANDIDATE_SHA256=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
NOT_RUN_NE_PASS=1
PHASE_A=BLOCKED_CANDIDATE_EXE_ABSENT
```

## 0) Verdict (fail-closed)

| Claim | Disposition |
|-------|-------------|
| Authoritative INTEG_004 / Finish-25 receipts under `g:\~dev\rawrxd\evidence` | **NOT_FOUND** (pre-existing); only this audit folder created |
| Authoritative receipts under `F:\rawrxd\evidence` | **FOUND** |
| On-disk EXE whose SHA-256 is `47451F24…` | **NOT_FOUND** (receipt-only; candidate folder overwritten) |
| Inherit Problems/Ext PASS onto live tip_004 / CC79 / G live | **FORBIDDEN** |
| PROMOTE / CERTIFIED / PRODUCT_PASS | **0** |

```
RECEIPT_SHA_47451F24 ≠ LIVE_TIP004_EXE
LIVE_TIP004_35EFA9BA ≠ 47451F24 ≠ CC79 ≠ A4F ≠ G_rxdn_896F8032
PHASE_A_REVERIFY_ON_47451F24 = BLOCKED until byte-identical artifact is located or owner-authorized rebuild freezes that SHA again
```

---

## 1) Search roots — FOUND vs NOT_FOUND

### `g:\~dev` (requested workspace)

| Root | Result |
|------|--------|
| `g:\~dev\rawrxd\evidence\*INTEG_004*` (pre-audit) | **NOT_FOUND** |
| `g:\~dev\rawrxd\evidence\*CC79*` | **NOT_FOUND** |
| `g:\~dev\rawrxd\evidence\*FINISH_25*` / `*Finish-25*` | **NOT_FOUND** |
| `g:\~dev\rawrxd\evidence\*PROBLEMS_UI*` | **NOT_FOUND** |
| `g:\~dev\evidence` / `g:\~dev\reports` / `g:\~dev\validation` | **NOT_FOUND** for INTEG_004 / CC79 / Finish-25 |
| Content rg max-depth≤3 on those roots | **NOT_FOUND** |
| This audit output dir | **FOUND** (created): `g:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\` |

Nearby G name noise (not INTEG_004 authority): `IDE_PRODUCT_FINISH_BATCH_*`, `SOVEREIGN_FINISH_HOUR`, `RAWRXD_IDE_NATIVE_E2E_FINISH_001`, etc.

### `F:\rawrxd` (authoritative local)

| Pattern | Result | Key paths |
|---------|--------|-----------|
| INTEG_004 / tip_final_integ_004 | **FOUND** | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\` |
| CC79 | **FOUND** | same + `package\tip_final_005\` + oneshot |
| Finish-25 / FINISH_25 | **FOUND** | `POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` + matrix files |
| PROBLEMS_UI | **FOUND** | oneshot `artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` etc. |
| A4F slim | **FOUND** | `DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe` |

Agent transcripts under `C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\` **FOUND** (pointers only; not SHA proof).

---

## 2) Hash board (Get-FileHash SHA256 this audit)

### Target candidate

| Role | Path | Measured SHA-256 | vs `47451F24…` |
|------|------|------------------|----------------|
| tip_final_integ_004 EXE (live) | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351` | **MISMATCH** |
| tip_final_integ_004 `SHA256.txt` | same folder | `35EFA9BA…` (MATCH live) | **MISMATCH** vs sealed |
| Sealed receipt SHA | lineage / Problems / EXT receipts | `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F` | RECEIPT_ONLY |
| Byte-identical `47451F24…` EXE | searched F:\rawrxd package/evidence/build candidates + G tip/freeze Win32IDE set | — | **ABSENT** |

Prior intermediate live hashes observed in peer audits before further overwrite: `69FE3D92…` (also ≠ `47451F24…`). Do not credit either as the sealed candidate.

### Controlling tip + immutable + G inventory samples

| Role | Path | Measured SHA-256 | Size |
|------|------|------------------|------|
| **CONTROLLING CC79** | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | 6152704 |
| CC79 alias | `F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe` | `CC79F6CD…` | 6152704 |
| **A4F immutable** | `F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe` | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | 2601472 |
| G rxdn_live | `G:\~dev\rxdn_live\bin\RawrXD-Win32IDE.exe` | `896F8032199211C93FD7087616900B056B6A42E902C4390CD27CC968B107D3DA` | 49569792 |
| G rawrxd\bin | `G:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe` | `D60C6F9A840D6EC824215BAE604EEF2561E5DE844C0F856893BE2E5AF5A0F31C` | 35877376 |

Additional G `RawrXD-Win32IDE.exe` tip-freeze samples (all **other**, none `47451F24…`): dist `3FFBF997…`; evidence freezes `67CA264F…`, `1E61C037…`, `0C621350…`, `D0A6A65C…`, `57B9DB25…`, agent-UI / perf smoke bins, etc. (partial inventory; aborted deep recurse — no MATCH to candidate observed).

---

## 3) Finish-25 authoritative ledger

**Authority (historical 19/25 arithmetic):**  
`F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md`  
Agreement peer: `...\FINISH_25_RECEIPT_AGREEMENT.md`

```
FINISH25_HISTORICAL=19/25
FINISH_25_REMAINING=6
HISTORICAL_OPEN_GATE_IDS=T05, T07, T08, T18, T19, T25
```

| Phase | Score | Open among remaining-six |
|-------|-------|--------------------------|
| Phase1 T01–T05 | 4/5 | **T05** |
| Phase2 T06–T10 | 3/5 | **T07, T08** |
| Phase3 T11–T15 | 5/5 | — |
| Phase4 T16–T20 | 3/5 | **T18, T19** |
| Phase5 T21–T25 | 4/5 | **T25** (CERTIFIED=0); T24 = CANDIDATE_PACKAGE_PASS only |

**Current matrices (≠ rewrite historical):**

| Ledger | Path | CURRENT |
|--------|------|---------|
| Final completion (CC79 board) | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` | **4/25** (T10,T16,T17,T20) |
| Oneshot | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | **4/25** |

```
FINISH25_HISTORICAL_19/25 ≠ FINISH25_CURRENT_4/25 ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE
HISTORICAL_NOT_MUTATED=1
```

---

## 4) INTEG_004 receipts by subsystem (SHA-scoped)

Authority roots:  
`F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\`  
`F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\`  
`F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\`  
`F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\NEXT_ACTION.md`

| Gate | Receipt status on sealed `47451F24…` | Notes |
|------|--------------------------------------|-------|
| Problems UI (items + rebuild clear) | RECEIPT **PASS** claimed | `artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt`; items=3; fixture `cmd_s_pipe_scrub` |
| Problems click | RECEIPT **POSTED_NM_DBLCLK** only | Same receipt + `ide_panels_gui_run_20261109-063546.txt` |
| Problems **caret navigation** | **NOT_FOUND** as separate measure | User/handoff: must be evidenced independently; no EM_SETSEL/GotoLine caret receipt tied to `47451F24…` located |
| Extension | RECEIPT **FAIL** (cleanup) | `INTEG004_EXT_REVERIFY_RECEIPT.md`: LOAD/ACTIVATE/UNLOAD PASS; EXT_CLEANUP=FAIL; FORCE_KILL=1 |
| Chat | **NEEDS_REVERIFY** / NOT_RUN on `47451F24…` | Do not inherit CC79 Chat PASS |
| Terminal | **NEEDS_REVERIFY** / NOT_RUN on `47451F24…` | CC79 term receipts exist separately |
| Output | RECEIPT claims GUI_OUTPUT PASS on panels run for `47451F24…` | Still listed NEEDS_REVERIFY in disposition board for cross-subsystem set — treat as **reverify required** before product credit |
| Debug headless | **NEEDS_REVERIFY** / NOT_RUN on `47451F24…` | CC79 debug receipts ≠ this SHA |

Lineage / disposition (explicit tip hold):

- `LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md`
- `INTEG004_ACCEPTANCE_DISPOSITION.md`
- `LOCAL_INTEG004_FINISH25.md` / `LOCAL_INTEG004_FINISH25_LOCATOR.md` / `BASELINE_SHA_LEDGER.md`

```
CANDIDATE_PROBLEMS_UI_RECEIPT=PASS (47451F24 era; EXE now absent)
CC79_PROBLEMS_UI=FAIL
EXTENSIONS_ON_47451F24=FAIL
TIP_MOVE_AUTHORIZED=0
AUTO_PROMOTE_INTEG_004=0
```

---

## 5) Gaps summary

| Item | Status |
|------|--------|
| `47451F24…` EXE on disk | **NOT_FOUND** / ABSENT (folder present, bytes replaced → now `35EFA9BA…`) |
| G:\~dev authoritative INTEG_004 ledger | **NOT_FOUND** |
| Finish-25 open six IDs | **FOUND** = T05 T07 T08 T18 T19 T25 |
| Problems POSTED_NM_DBLCLK receipt | **FOUND** (receipt-only; SHA era) |
| Problems caret navigation receipt on `47451F24…` | **NOT_FOUND** |
| Chat/Term/Debug-headless receipts on `47451F24…` | **NOT_FOUND** (NEEDS_REVERIFY) |
| Ext cleanup PASS on `47451F24…` | **NOT_FOUND** (measured FAIL) |
| A4F unmodified | **FOUND** MATCH `A4F083DF…` |
| PASS invent / promote | **DENIED** |

---

## 6) Exact next executable commands — Phase A reverify

**Gate 0 (mandatory):** recover or freeze a byte-identical `47451F24…` artifact. Until `Get-FileHash` returns that exact digest, Phase A disposition remains **BLOCKED** (no substitute SHA PASS).

```powershell
# 0a) Locate / confirm candidate (fail-closed)
$need = '47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F'
$exe  = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe'
Get-FileHash -LiteralPath $exe -Algorithm SHA256
# Expect MATCH $need. If not: search bak/freeze; DO NOT proceed with 35EFA9BA/69FE3D92/CC79/A4F/G live.

# 0b) Broad recover hunt (example)
Get-ChildItem F:\rawrxd -Recurse -Include *.exe,*.bak -ErrorAction SilentlyContinue |
  Where-Object { $_.Length -ge 5MB -and $_.Length -le 8MB -and $_.FullName -notmatch '\\models\\' } |
  ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    if ($h -eq $need) { $_.FullName }
  }
```

**Only after Gate 0 MATCH**, run in order (same `$exe`, re-hash before each gate):

```powershell
# 1) Extensions (must reach EXT_CLEANUP with FORCE_KILL=0)
powershell -NoProfile -ExecutionPolicy Bypass -File `
  F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1 `
  -Exe $exe
# Prior seal: F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md

# 2–5) Chat / Terminal / Output / Debug-headless
# Prefer existing oneshot/final harnesses aimed at $exe with SHA assert;
# write new receipts under:
#   g:\~dev\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\phase_a\
# or F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\
# Do NOT credit CC79 PASS files:
#   term_smoke_receipt_CC79.txt, CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt, etc.

# 6) Problems UI — require BOTH measures on $need
#    a) POSTED_NM_DBLCLK (existing class of probe)
#    b) independent caret navigation (EM_SETSEL / documented caret line/col) — currently GAP
# Fixture: F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp
# Prior panels receipt (SHA era only): ...\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt
```

**Hard holds:**

```
PROMOTE=0
CERTIFIED=0
TIP_MOVE_AUTHORIZED=0
DO_NOT_MODIFY_A4F=1
NO_REBUILD_SOLELY_TO_REPRODUCE_PROBLEMS_UI=1
NO_CROSS_SHA_PASS_INHERITANCE=1
```

---

## 7) Peer locator docs (do not treat as new PASS)

- `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\LOCAL_INTEG004_FINISH25.md`
- `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\BASELINE_SHA_LEDGER.md`
- `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\PHASE_A_PENDING.md`
- `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LOCAL_INTEG004_FINISH25_LOCATOR.md`

```
END_INVENTORY
PROMOTE=0
CERTIFIED=0
CANDIDATE_EXE_47451F24=ABSENT
PHASE_A=BLOCKED
```

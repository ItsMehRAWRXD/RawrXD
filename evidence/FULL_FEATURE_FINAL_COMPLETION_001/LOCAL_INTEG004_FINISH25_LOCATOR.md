# LOCAL_INTEG004_FINISH25_LOCATOR

```
ASOF_UTC=2026-11-09T12:36:00Z
MOTD_ACK=1
SCOPE=LOCAL_DISK_ONLY
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
CONTROLLING_TIP=CC79
NO_CROSS_SHA_PASS_INHERITANCE=1
```

Locator for local (non-GitHub-indexed) INTEG_004 / Finish-25 / hash-board evidence under `F:\rawrxd\evidence\**`. Fail-closed: measured paths only; sealed PASS on CC79 is not re-credited to candidates.

---

## 0) Authority (must not supersede CC79)

| Role | Tip | SHA-256 | Path |
|------|-----|---------|------|
| **CONTROLLING** | `tip_final_integ_002` | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` (live hash MATCH; SIZE=6152704; ASOF=2026-11-09T05:11:26-05:00) |
| Frozen baseline | A4F slim | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | prior package root — **UNTOUCHED / IMMUTABLE** |

**MUST NOT SUPERSEDE CC79:** `tip_final_integ_003` (any SHA including historical `0EA05DF7…`), `tip_final_integ_004` / INTEG_004 (`47451F24…` or live `69FE3D92…`), EA5D `tip_final_004`, peer specialty tips (D28128AE / 7F8EB407 / BD529691). Problems-UI PASS on INTEG_004 ≠ CONTROLLING_TIP ≠ PRODUCT_PASS ≠ CERTIFIED ≠ PROMOTE.

---

## 1) INTEG_004 / tip_final_integ_004 / 0EA05DF7 lineage (LOCAL PRESENT)

### Lineage board (receipts)

| Artifact | Path | ASOF (file mtime local) | SHA / note | Role |
|----------|------|-------------------------|------------|------|
| LINEAGE_RECONCILE | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md` | 2026-11-09T06:40:07-05:00 | seals Problems-UI to `47451F24…` | CANDIDATE Problems-UI only; CONTROLLING=CC79 |
| INTEG004_ACCEPTANCE | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md` | 2026-11-09T07:16:05-05:00 | `CANDIDATE_SHA=47451F24…` | CANDIDATE; TIP_MOVE_AUTHORIZED=0 |
| INTEG004_EXT_REVERIFY | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md` | 2026-11-09T07:18:57-05:00 | measured on `47451F24…`; EXT_CLEANUP=FAIL → EXTENSIONS=FAIL | CANDIDATE reverify; ≠ invent CC79 re-PASS |
| EXT smoke alias | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_tip_final_integ_004.txt` | 2026-11-09T07:18:21-05:00 | TIP_SHA=`47451F24…` | run log |
| EXT smoke run | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\logs\ext_smoke_run_20261109-071737.txt` | same | same | run log |
| Problems UI (oneshot) | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\PROBLEMS_UI_INTEG_004_RECEIPT.txt` | ~06:35 | `47451F24…` | CANDIDATE Problems measure |
| Bounded rebuild log | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\build_integ_004_bounded.log` | — | `REBUILD2_STAGE_SHA=47451F24…` | stage receipt |
| Interim audit note | `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\INTERIM_LOCAL_FINDINGS.md` | — | cites `47451F24…` | secondary pointer |

### tip_final_integ_00{2,3,4} on-disk images (live Get-FileHash this locator turn)

| Tip | EXE path | Live SHA-256 | SIZE | ASOF | Role |
|-----|----------|--------------|------|------|------|
| 002 | `...\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe` | `CC79F6CD…` | 6152704 | 05:11:26 | **CONTROLLING** |
| 003 | `...\candidates\tip_final_integ_003\RawrXD-Win32IDE-Native-Ext.exe` | `DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C` | 6167040 | 06:38:50 | CANDIDATE NOT_CONTROLLING |
| 004 | `...\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` | 6167040 | 07:22:08 | CANDIDATE (post-incr); **overwrote** prior `47451F24…` image |

### 0EA05DF7 lineage (receipt-only; EXE ABSENT)

| Item | Path | Detail |
|------|------|--------|
| Four-panel followup run | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\cc79_followup_four_panel_run_20261109-062358.txt` | TIP_EXE=`...\tip_final_integ_003\...`; TIP_SHA256=`0EA05DF722DCF26F9692584EB90CB03E243664363AA318D944FD813BFF7395E2` at 06:24:00 |
| Live tip_003 EXE | same folder | **now** `DD60FFB8…` — `0EA05DF7…` binary **ABSENT** on disk (superseded in place) |
| HASH_VERIFY_BOARD row for 0EA05 | — | **ABSENT** |

**Lineage chain (local):** EA5D (`tip_final_004` historical) → CC79 (`tip_final_integ_002` CONTROLLING) → tip_003 interim `0EA05DF7…` (receipt) → tip_003 live `DD60FFB8…` → INTEG_004 sealed Problems/EXT measure `47451F24…` (receipts; EXE gone) → post-incr tip_004 live `69FE3D92…` (EXE+SHA256.txt).

---

## 2) Authoritative Finish-25 ledger (LOCAL PRESENT)

| Layer | Path | ASOF | Authority |
|-------|------|------|-----------|
| **CURRENT on CC79 (primary for this tree)** | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md` | file 05:20:05; header ASOF_UTC=2026-11-09T10:19:30Z | CONTROLLING tip CC79 |
| CURRENT oneshot (EA5D track; peer) | `F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md` | 05:35:27; ASOF_UTC=10:34:00Z | oneshot / EA5D — must not override CC79 board |
| HISTORICAL backlog | `F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md` | 2026-11-08T19:22:33-05:00 | HIST authority cited by both matrices |

### Counts (from FINAL_COMPLETION FINISH25_MATRIX — do not invent higher)

```
FINISH25_HISTORICAL=19/25
HISTORICAL_REMAINING_SIX=T05,T07,T08,T18,T19,T25
FINISH25_CURRENT=4/25
FINISH25_CURRENT_PASS_COUNT=4
FINISH25_CURRENT_PASS_LIST=T10,T16,T17,T20
CONTROLLING_TIP=CC79
FINAL_CANDIDATE_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
CERTIFIED=0
PROMOTE=0
HISTORICAL_NOT_MUTATED=1
```

T25 remains CERTIFIED=0 / held. T08 noted SEALED/TIP_FIX=0 under T01–T09 — not credited as CURRENT PASS beyond the PASS_LIST above.

---

## 3) HASH_VERIFY_BOARD / PEER_ABSORPTION / SHA256.txt

| Artifact | Path | ASOF | Status |
|----------|------|------|--------|
| HASH_VERIFY_BOARD | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\HASH_VERIFY_BOARD.md` | 05:19:43; ASOF_UTC=10:19:30Z | **PRESENT** — CONTROL=CC79; peers EA5D/D281/7F8E/7582/BD52; **no rows** for integ_003/004, `0EA05DF7`, `47451F24`, or `69FE3D92` |
| PEER_ABSORPTION | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\PEER_ABSORPTION.md` | 05:10:45; ASOF_UTC=10:08:00Z | **PRESENT** — pre-promotion absorb; still lists `FINAL_CANDIDATE_SHA256=EA5D…` + `NOT_SINGLE_SHA_YET=1` (historical peer doc; **does not** move CONTROLLING off CC79) |
| tip_004 SHA256.txt | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\SHA256.txt` | 07:22:42 | **PRESENT** = `69FE3D92…` (MATCH live EXE) |
| tip_003 SHA256.txt | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_003\SHA256.txt` | 06:38:53 | **PRESENT** = `DD60FFB8…` (MATCH live EXE) |
| tip_002 SHA256.txt | `...\tip_final_integ_002\SHA256.txt` | — | **ABSENT** (hash known via HASH_VERIFY_BOARD + live Get-FileHash + README) |
| tip_001 SHA256.txt | `...\tip_final_integ_001\SHA256.txt` | — | **ABSENT** |

tip_002 README (hash sidecar substitute): `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\README.md` — TIP_SHA256=CC79…; PROMOTE=0.

---

## 4) Incremental rebuild worker → tip_004 EXE + prove_ide_compiler_feed

**YES — left measurable artifacts.** Agent ownership: `f49b636b-f2b5-40fc-98d7-8163de63dcd4` (“Incremental rebuild prove feed”). No evidence file *named* `f49b636b*`.

| Work product | Path | ASOF | Note |
|--------------|------|------|------|
| tip_004 EXE | `...\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` | 07:22:08 | live SHA `69FE3D92…` |
| tip_004 SHA256.txt | (above) | 07:22:42 | MATCH |
| build tree twin | `F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe` | 07:22:08 | same `69FE3D92…` |
| incr bats/logs | `artifacts\_incr_rebuild_004.bat`, `_incr_071739.bat`, `build_integ_004_followup_incr.log`, `build_incr_071739.log`, `build_incr_followup2.log` | 07:16–07:22 | PRESENT |
| prove_ide_compiler_feed.ps1 | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\prove_ide_compiler_feed.ps1` | 07:22:42 | PRESENT |
| prove run log | `...\artifacts\prove_ide_compiler_feed_run.log` | 07:24:46 | PRESENT |
| IDE_COMPILER_FEED_RECEIPT | `...\artifacts\IDE_COMPILER_FEED_RECEIPT.txt` | 07:24:46 | MEASURED; CANDIDATE_SHA=`69FE3D92…`; CANDIDATE_NOT_PROMOTED=1 |
| COMPILER_CAPTURE_RECEIPT | `...\artifacts\COMPILER_CAPTURE_RECEIPT.txt` | 07:23:06 | START line only observed |
| COMPILER_ROOT_CAUSE_001 | `...\artifacts\COMPILER_ROOT_CAUSE_001.txt` | 07:03:25 | VS_UNICODE_OUTPUT root cause |
| prove_compiler_capture.ps1 + ISOLATED receipt | `artifacts\prove_compiler_capture.ps1`, `COMPILER_CAPTURE_ISOLATED_RECEIPT.txt` | ~06:34 | isolated scrub proof (pre-incr) |

### Fail-closed measure on `69FE3D92…` (NOT PASS invent)

```
COMPILER_EXECUTION=VERIFIED
COMPILER_OUTPUT_CAPTURE=NOT_VERIFIED
DIAGNOSTIC_FEED=NOT_VERIFIED
DIAGNOSTIC_PARSED_COUNT=0
PROBLEMS_ID1312_ITEMS=0
BUILD_RESULT_DISPOSITION=running
PROCESS_EXIT_SEEN=False
PROMOTE=0
```

Prior sealed Problems-UI on `47451F24…` remains receipt-only; that EXE image is **ABSENT** under scanned `F:\rawrxd\**\RawrXD-Win32IDE-Native-Ext.exe` (first-page inventory + tip_004 live hash). Do not treat `69FE3D92…` as inheriting Problems PASS.

f49 transcript: `C:\Users\Garrett\.cursor\projects\g-dev\agent-transcripts\4aa15404-044f-497e-b610-6cef7366d9ff\subagents\f49b636b-f2b5-40fc-98d7-8163de63dcd4.jsonl` (SIZE=2355; ASOF=07:06:39 — kickoff; later prove/EXE artifacts are the runtime footprint).

---

## 5) ABSENT list (explicit)

```
ABSENT tip_final_integ_002\SHA256.txt
ABSENT tip_final_integ_001\SHA256.txt
ABSENT on-disk EXE SHA=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
ABSENT on-disk EXE SHA=0EA05DF722DCF26F9692584EB90CB03E243664363AA318D944FD813BFF7395E2
ABSENT HASH_VERIFY_BOARD rows for tip_final_integ_003 / tip_final_integ_004 / 0EA05DF7 / 47451F24 / 69FE3D92
ABSENT evidence artifact filename containing f49b636b
ABSENT FINISH25_CURRENT promotion beyond 4/25
ABSENT CERTIFIED / PRODUCT_PASS / PROMOTE
ABSENT GitHub-remote index of this local tree (expected — this locator is LOCAL_ONLY)
```

---

## 6) Absolute path index (quick)

```
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINISH25_MATRIX.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\HASH_VERIFY_BOARD.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\PEER_ABSORPTION.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_ACCEPTANCE_DISPOSITION.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG004_EXT_REVERIFY_RECEIPT.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FINAL_VERDICT.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_002\README.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_003\SHA256.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_003\RawrXD-Win32IDE-Native-Ext.exe
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\SHA256.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\prove_ide_compiler_feed.ps1
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\prove_ide_compiler_feed_run.log
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\IDE_COMPILER_FEED_RECEIPT.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\COMPILER_CAPTURE_RECEIPT.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\COMPILER_ROOT_CAUSE_001.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\COMPILER_CAPTURE_ISOLATED_RECEIPT.txt
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\prove_compiler_capture.ps1
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\cc79_followup_four_panel_run_20261109-062358.txt
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\FINISH25_MATRIX.md
F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md
F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LOCAL_INTEG004_FINISH25_LOCATOR.md
```

```
PROMOTE=0
TIP_CLIMB=HOLD
CONTROLLING_TIP=CC79
CANDIDATE_TIPS=tip_003,tip_004/INTEG_004
```

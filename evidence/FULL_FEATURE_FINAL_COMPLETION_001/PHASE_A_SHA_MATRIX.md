# PHASE_A_SHA_MATRIX — INTEG_004 cross-subsystem reverify

```text
ASOF_UTC=2026-11-09T12:42:00Z
MOTD_ACK=1
PHASE=A
MISSION=Reverify INTEG_004 gates on candidate SHA only
CANDIDATE_SHA256=47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F
CANDIDATE_EXE_PRESENT=0
PHASE_A_OVERALL=BLOCKED
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
CONTROLLING_TIP=CC79
CONTROLLING_TIP_SHA256=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
INVENT_PASS=0
HARNESS_RUN_THIS_TURN=0
SUBSTITUTE_SHA_RUNS=0
```

## Binding law (this turn)

```text
IF live Get-FileHash(EXE) != CANDIDATE_SHA256 THEN all gates = BLOCKED
NOT_RUN != PASS
CC79_PASS ≠ CANDIDATE_PASS
POSTED_NM_DBLCLK ≠ ACTUAL_EDITOR_CARET_NAVIGATION
Historical receipt ≠ this-turn reverify PASS
```

## Candidate binary locate

| Field | Value |
|-------|-------|
| Expected path | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_004\RawrXD-Win32IDE-Native-Ext.exe` |
| Live SHA (tip_004 slot) | `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351` |
| Live SHA (build twin) | `35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351` |
| Prior overwrite seen | `69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB` (locator) |
| Target match | **False** |
| Locate log | `logs/phase_a_sha_locate_20261109.txt` |
| Scan roots | FULL_FEATURE_FINAL_COMPLETION_001, FULL_FEATURE_ONESHOT_001, build_tip_debug_rel, build, release, dist — **0 hits** for `47451F24…` |

**BLOCKER_PRIMARY:** Candidate EXE image `47451F24…` is **ABSENT** (slot overwritten). No harness may run against a substitute SHA and claim Phase A PASS.

---

## Gate matrix (this-turn reverify bound to `47451F24…`)

### 1) Extension host

| Field | Value |
|-------|-------|
| Gate | EXTENSION_HOST |
| Command | `powershell -NoProfile -File F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1` (would bind TIP_EXE to candidate) |
| Env | Candidate EXE + fixture `FULL_FEATURE_ONESHOT_001\fixtures\ext_hello` |
| Expected | INIT/LOAD/ACTIVATE (+ lifecycle if harness); clean quit `FORCE_KILL=0` |
| Observed | **NOT_RUN this turn** — candidate EXE absent |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

Historical (not this-turn PASS): `receipts/INTEG004_EXT_REVERIFY_RECEIPT.md` + `logs/ext_smoke_*` on `47451F24…` → `EXT_LOAD/ACTIVATE/UNLOAD=PASS`, `EXT_CLEANUP=FAIL` (`FORCE_KILL=1`, harness exit 1) → `EXTENSIONS=FAIL`.

### 2) Chat / local AI

| Field | Value |
|-------|-------|
| Gate | CHAT_LOCAL_AI |
| Command | Harness candidates: `harness/chat_ctrl_enter_verify.ps1`, `harness/chat_17_probe_matrix.ps1` |
| Env | Candidate EXE; stream/stop/clear surface |
| Expected | Stream + stop + clear evidenced on candidate SHA |
| Observed | **NOT_RUN this turn** — candidate EXE absent; no prior `47451F24…` chat receipt |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

### 3) Terminal

| Field | Value |
|-------|-------|
| Gate | TERMINAL |
| Command | Harness candidates: `harness/term_job.ps1`, ConPTY probes under `harness/terminal_*` |
| Env | Candidate EXE |
| Expected | Spawn/output/exit(/restart) on candidate SHA |
| Observed | **NOT_RUN this turn** — candidate EXE absent; CC79 `term_smoke_receipt_CC79.txt` is **not** transferable |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

### 4) Output

| Field | Value |
|-------|-------|
| Gate | OUTPUT |
| Command | `harness/ide_panels_gui_verify.ps1` / `ea5d_output_problems_hwnd.ps1` (OUTPUT channel) |
| Env | Candidate EXE |
| Expected | Diagnostic routing/render measured on candidate SHA |
| Observed | **NOT_RUN this turn** — EXE absent. Historical Problems run log notes `OUTPUT_ID1012_LEN=-1` / `GUI_OUTPUT_PANEL_E2E=PASS` on `47451F24…` is **receipt-only**, not re-verified this turn |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

### 5) Debug-headless

| Field | Value |
|-------|-------|
| Gate | DEBUG_HEADLESS |
| Command | Prior CC79 path used `debug_backend_verify` + fixture; no candidate-bound reverify this turn |
| Env | Candidate EXE + debuggee fixture |
| Expected | Launch/BP/step/cleanup on candidate SHA |
| Observed | **NOT_RUN this turn** — EXE absent; CC79 debug receipts are **not** transferable |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

### 6) Problems UI (population + click navigation)

| Field | Value |
|-------|-------|
| Gate | PROBLEMS_UI |
| Command | `harness/ide_panels_gui_verify.ps1` (historical runlog `logs/ide_panels_gui_run_20261109-063546.txt`) |
| Env | `RAWRXD_PROBLEMS_FIXTURE=...\fixtures\broken_multi.cpp`; scrubbed `VS_UNICODE_OUTPUT` path |
| Expected | (a) `PROBLEMS_ITEMS=3` **and** (b) `POSTED_NM_DBLCLK` **and** (c) **ACTUAL editor caret/line navigation** evidenced separately |
| Observed | **NOT_RUN this turn** — EXE absent |
| Exit | N/A |
| SHA | `47451F24…` **ABSENT** |
| Disposition | **BLOCKED** |

#### Historical split (receipt-only; ≠ this-turn PASS)

| Sub-check | Historical on `47451F24…` | Full Phase-A requirement |
|-----------|---------------------------|--------------------------|
| Three-item population | `PROBLEMS_ID1312_ITEMS=3` (`PROBLEMS_UI_INTEG_004_RECEIPT.txt`) | Required |
| Click event | `CLICK_TO_LINE=POSTED_NM_DBLCLK` only | Required but **insufficient alone** |
| Actual caret navigation | **NOT evidenced** in sealed receipt/runlog | Required for Problems UI **full** PASS |

```text
POSTED_NM_DBLCLK = message posted
ACTUAL_EDITOR_CARET_NAVIGATION = independent measure (caret/line/file change)
POSTED_NM_DBLCLK ≠ ACTUAL_EDITOR_CARET_NAVIGATION
```

---

## VS_UNICODE_OUTPUT compiler-output fix (preserved evidence)

| Artifact | Path (copied under this audit dir where noted) | Status |
|----------|-----------------------------------------------|--------|
| Isolated poison/scrub proof | `receipts/COMPILER_CAPTURE_ISOLATED_RECEIPT.txt` | **PRESERVED** — scrub → `diag=True out_len=887`; poison → `diag=False out_len=74` |
| Root-cause writeup | `receipts/COMPILER_ROOT_CAUSE_001.txt` | **PRESERVED** |
| Problems fixture path | Historical `FIXTURE_VIA=cmd_s_pipe_scrub` on `47451F24…` | Receipt-only; EXE gone |

Does **not** authorize tip move. Does **not** re-PASS Problems on live `35EFA9BA…`.

---

## Substitute / non-candidate images (explicit non-PASS)

| Role | SHA-256 | May inherit `47451F24…`? |
|------|---------|--------------------------|
| CONTROLLING CC79 | `CC79F6CD…` | **No** |
| tip_004 live | `35EFA9BA…` | **No** |
| tip_004 prior overwrite | `69FE3D92…` | **No** |
| tip_003 live | `DD60FFB8…` | **No** |
| g:~dev live `896F8032…` | (PHASE_A_PENDING) | **No** |
| Frozen A4F | `A4F083DF…` | **Untouched / immutable** |

---

## Harnesses inventoried (not executed this turn)

```text
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ide_panels_gui_verify.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\chat_ctrl_enter_verify.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\chat_17_probe_matrix.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\term_job.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ea5d_output_problems_hwnd.ps1
F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\problems_gui_measure_007.ps1
```

Reason not run: binding EXE for `47451F24…` missing. Prefer restore existing candidate over rebuild.

---

## Blockers (precise)

1. **CANDIDATE_BINARY_ABSENT_OR_OVERWRITTEN** — no on-disk EXE with SHA `47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F`.
2. All six Phase A gates **BLOCKED** for lack of bindable image.
3. Historical Problems seal used `POSTED_NM_DBLCLK` without separate **actual caret navigation** evidence → even after binary restore, Problems **full** PASS still needs that independent measure.
4. Historical Extensions on `47451F24…` already `EXTENSIONS=FAIL` (`EXT_CLEANUP`/`FORCE_KILL`) — must be remade after restore; do not invent PASS.

## Authority close

```text
PHASE_A_OVERALL=BLOCKED
TIP_MOVE_AUTHORIZED=0
CONTROLLING_TIP=CC79
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
A4F_IMMUTABLE=1
NEXT=RESTORE_OR_REPRODUCE_47451F24_THEN_RERUN_GATES
```

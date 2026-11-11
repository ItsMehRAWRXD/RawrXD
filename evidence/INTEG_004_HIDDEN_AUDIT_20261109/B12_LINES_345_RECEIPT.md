# B12_LINES_345_RECEIPT — broken_multi.cpp lines 3/4/5 caret proof

```text
ASOF_UTC=2026-11-09T16:06:48Z
MOTD_ACK=1
GATE_ID=B12
LAW=POSTED_NM_DBLCLK_NE_ACTUAL_EDITOR_CARET_NAVIGATION
HASH_MATCH_NE_RUNTIME_ACCEPTANCE=1
NO_CROSS_SHA_PASS_INHERITANCE=1
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
MATURITY=82%_UNCHANGED
```

## SHA selection

| Candidate | Measured SHA-256 | B12 strings (`navigateToFileLine`) | Role |
|-----------|------------------|--------------------------------------|------|
| tip_b02_remediation_001 | `7B3C0ECB46A2AF063D626057111B0EF6730607AC839B40A805A121ABF1756655` | YES | Expected `2CCAE57A…` **ABSENT on disk** (slot superseded) |
| tip_final_integ_006 | `B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC` | NO | Rejected (no B12 path) |
| **tip_rc_integ_001 (chosen)** | `1AE26B8F3A6BE63462C1C6F860B09153DB077786505D32F9A4C051E1D80F0CB5` | YES | Measured acceptance image |

```text
MEASURED_SHA256=1AE26B8F3A6BE63462C1C6F860B09153DB077786505D32F9A4C051E1D80F0CB5
EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_integ_001\RawrXD-Win32IDE-Native-Ext.exe
SHA_STABLE=1
LIVE_AT_SEAL=0
```

## Problems populate (same SHA)

| Field | Disposition |
|-------|-------------|
| Items | 3 |
| Fixture | `broken_multi.cpp` |
| **POPULATE** | **PASS** |

User screenshot VISIBLE_DIAGNOSTIC_POPULATION (C2065@3 / C2660@4 / C2440@5) is now **SHA-bound** to this image for populate only. See `SCREENSHOT_PROBLEMS_POPULATE_OBSERVATION.md`.

## B12 line activations (fail-closed)

Activation methods attempted on `1AE26B8F…`:

1. Cross-process `WM_NOTIFY`/`NM_DBLCLK` with `NMITEMACTIVATE*` — **insufficient** (pointer lParam does not marshal cross-process).
2. `LVM_SETITEMSTATE` + `WM_COMMAND 1312` — selection not proved cross-process; caret stayed line 1; **NAV log ABSENT**.
3. SendInput / `PostMessage WM_LBUTTONDBLCLK` approximate row hit — caret stayed line 1; **NAV log ABSENT**.

| Line | Expected | EDITOR_LINE (EM_LINEFROMCHAR) | NAV_LOG | Disposition |
|------|----------|-------------------------------|---------|-------------|
| 3 | 3 | 1 | ABSENT | **FAIL** |
| 4 | 4 | 1 | ABSENT | **FAIL** |
| 5 | 5 | 1 | ABSENT | **FAIL** |

```text
B12_LINES_345_OVERALL=FAIL
B12_CLOSED=0
ACTUAL_EDITOR_CARET_NAVIGATION=FAIL
REASON=NO_CARET_NO_NAV_LOG_AFTER_ACTIVATE
```

## Other panels (same SHA; smoke only)

| Panel | Disposition |
|-------|-------------|
| Terminal (WM_COMMAND 2034) | PASS |
| Output (2025) | PASS |
| Debug Console (2021) | PASS |

Smoke ≠ integrated four-panel acceptance.

## Rebuild note (non-controlling)

Source patch landed in `Win32IDE_Core.cpp`: `case 1399` → `goToProblem((int)lParam)` (integer-only harness, cross-process safe). Incremental rebuild via `_build_once.bat` / vcvars was started; winget `ninja` previously warned `build log version is too old; starting over` (unintended full rebuild path — **not** a deliberate `.ninja_log` delete). **New tip_rc SHA not staged / not remeasured in this seal.** `PROMOTE=0`.

## Receipts

- `receipts/B12_LINES_345_1AE26B8F.txt` (G: + F: mirror)
- `GATE_SHA_BIND.md` rows updated for this SHA only

```text
PROMOTE=0
CERTIFIED=0
TIP_MOVE_AUTHORIZED=0
CONTROLLING=CC79
MATURITY=82
```

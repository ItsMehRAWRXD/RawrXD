# INTEG006_B12_CARET_NAV_RECEIPT — Fail-closed B12 caret navigation

ASOF_UTC=2026-11-09T14:55:00Z
MOTD_ACK=1

```
CONTROLLING_TIP=CC79
MATURITY=82%
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0
TIP_CLIMB=HOLD
NO_CROSS_SHA_PASS_INHERITANCE=1
NO_INHERIT_FROM_27E2263E=1
NO_INHERIT_FROM_47451F24=1
NO_INHERIT_FROM_CC79=1
```

## Measured EXE (mission start)

| Field | Value |
|-------|-------|
| EXE | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_006\RawrXD-Win32IDE-Native-Ext.exe` |
| Expected SHA256 | `B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC` |
| Measured SHA256 | `B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC` |
| SHA_MATCH_AT_START | **1** |
| DISK_DRIFT | **0** |
| FROZEN | 1 (DO_NOT_OVERWRITE) |

## Harness

| Field | Value |
|-------|-------|
| HARNESS | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\run_integ006_b12_caret_nav.ps1` |
| HARNESS_RECEIPT | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\INTEG006_B12_CARET_HARNESS_RECEIPT.txt` |
| RUNLOG | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\integ006_b12_caret_run_20261109-091259.txt` |
| PRIOR_PROBLEMS_UI | `INTEG006_PROBLEMS_UI_REVERIFY_RECEIPT.md` (CLICK_TO_LINE=`POSTED_NM_DBLCLK` only) |

## B12 proof fields (measured)

```
PROBLEMS_ID1312_ITEMS=-1
CLICK_TO_LINE=BLOCKED_NO_ITEMS
TITLE_BEFORE=
TITLE_AFTER=
TITLE_AFTER_EMPTY=1
TITLE_HAS_FILE=0
EDITOR_LINE_BEFORE=-1
EDITOR_CP_BEFORE=-1
EDITOR_LINE_AFTER=-1
EDITOR_CP_AFTER=-1
CARET_MOVED=0
CARET_ON_EXPECTED=0
NAVIGATE_TELEMETRY=ABSENT
ACTUAL_EDITOR_CARET_NAVIGATION=FAIL
REASON=CLICK_BLOCKED=BLOCKED_NO_ITEMS
LAW=POSTED_NM_DBLCLK_NE_ACTUAL_EDITOR_CARET_NAVIGATION
B12_DISPOSITION=FAIL
```

## Corroboration / non-inheritance

- Prior Problems UI on same SHA recorded `CLICK_TO_LINE=POSTED_NM_DBLCLK` with items=3 — **insufficient for B12** by law.
- Re-run of `problems_gui_measure_007.ps1` on `B50A2AB1…` at measure time: `EXIT_DURING_WAIT` / items=-1 (IDE exited before poll; concurrent agents force-stopping `RawrXD-Win32IDE-Native*`).
- Fixture compile still produced `RAWRXD_BUILD_OUTPUT_latest.log` with `error C2065` / `error C2660` / `error C2440` — build path ran; HWND survival / caret measure did not.
- Do **not** inherit PASS from `27E2263E…` / `47451F24…` / CC79.

## Source fix attempted (not yet sealed into a new tip EXE)

File: `F:\rawrxd\src\win32app\Win32IDE_VSCodeUI.cpp` :: `goToProblem`

- Switch caret set from `EM_SETSEL` → RichEdit `EM_EXSETSEL`
- `updateTitleBarText` + status line/col after navigate
- Product proof line: `[B12] navigateToFileLine path:line` via `appendToOutput` + `F:\rawrxd\evidence\B12_NAVIGATE_LATEST.log`

```
REBUILD_OR_NOT=ATTEMPTED
REBUILD_STATUS=WEDGED_FULL_NINJA_AFTER_BUILDLOG_RESET
NEW_TIP_PATH=NOT_STAGED
NEW_SHA=NOT_PRODUCED
```

Full `ninja RawrXD-Win32IDE-Native-Ext` under vcvars was started after `.ninja_log` reset forced ggml/vulkan rebuild; host shells wedged under compile load; tip_final_integ_006 left frozen untouched.

## Disposition

```
B12=FAIL
B02_CLOSED_ON_INTEG006=0
B02_ON_27E2263E=FAIL (unchanged; do not rewrite)
MEASURED_SHA=B50A2AB10C4261CCC085AB74C02B5979A26FEED714BE3E628DEBFAAF6D041CFC
PROMOTE=0
TIP_MOVE_AUTHORIZED=0
CONTROLLING=CC79
```

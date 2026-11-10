# B12_CARET_NAV_RECEIPT — tip_b02_remediation_001

```text
ASOF_UTC=2026-11-09T14:30:00Z
GATE_ID=B12
CANDIDATE_SHA256=2CCAE57A02AEB778E8DB678BC8937C63512B296924E4784DB0FE9BCCEFD385DD
PRIOR_27E2_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
NO_CROSS_SHA_PASS_INHERITANCE=1
TIP_EXE=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_b02_remediation_001\RawrXD-Win32IDE-Native-Ext.exe
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```

## Source fix (Native-Ext linked path)

Native-Ext **does not** link `Win32IDE_ProblemsPanel.cpp` / `m_problemsViewCache`.
Product Problems activate path is `Win32IDE_lifecycle.cpp` → `goToProblem` → `m_problems`.

Applied on `F:\rawrxd\src\win32app\Win32IDE_VSCodeUI.cpp::goToProblem`:

- Prefer `openDocumentPath(problem.file)` (tab/title/doc path) over raw `ifstream` + `setEditorText`
- Then `EM_LINEINDEX` / `EM_SETSEL` / `EM_SCROLLCARET` with validated line/col
- Binary contains `B12_NAV_OPENDOC_PATH=1` string (compiled into `2CCAE57A…`)

## Runtime measure (this SHA)

| Assertion | Result |
|-----------|--------|
| IMAGE contains B12_NAV_OPENDOC_PATH | **YES** |
| GUI main HWND for caret harness | **FAIL** (`main_hwnd_not_found` / EARLY_EXIT on integ006 B12 script) |
| POSTED_NM_DBLCLK | **NOT_RUN** (no live HWND) |
| ACTUAL_EDITOR_CARET_NAVIGATION | **FAIL** / **NOT_RUN** |
| LAW | `POSTED_NM_DBLCLK ≠ ACTUAL_EDITOR_CARET_NAVIGATION` |

```text
B12_DISPOSITION=FAIL
B12_CLOSED=0
REASON=SOURCE_WIRED_ON_2CCA; RUNTIME_CARET_NOT_PROVED (GUI early-exit / HWND missing)
NOT_RUN_NE_PASS=1
INVENT_PASS=0
```

## vs sealed 27E2263E…

Prior 27E2 measure: items=3 + `POSTED_NM_DBLCLK` without caret proof → FAIL.
No inheritance of any 27E2 Problems/B12 result onto `2CCAE57A…`.

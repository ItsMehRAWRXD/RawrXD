# BASELINE_RECONCILIATION_001 — RawrXD v1.0 completion handoff

ASOF_UTC=2026-11-09T10:50:00Z
MOTD_ACK=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1

## Source of truth

| Layer | Value | Notes |
|-------|-------|-------|
| Primary workspace | `F:\rawrxd` | Handoff authority |
| Secondary mirror | `G:\~dev\rawrxd` | Used for earlier GitHub push of three feature branches |
| Controlling full-feature tip | `CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4` | `package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe` |
| Tip label | `tip_final_005` | RelWithDebInfo / Ext packaging path |
| Immutable slim daily-driver | `A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E` | `DAILY_DRIVER_CLOSE_001\package\` — DO NOT OVERWRITE |
| Historical Finish-25 | **19/25** | Not current; do not inherit |
| Current Finish-25 (oneshot) | **4/25** | T10, T16_EXT, T17_TERMINAL, T20_CHAT on measured tips |
| Certification | `CERTIFIED=0` | Held |
| Promotion | `PROMOTE=0` | Held |

## GitHub PR track (separate from F:\ tip authority)

| PR | Branch | Tip OID | State | Mergeable |
|----|--------|---------|-------|-----------|
| [#77](https://github.com/ItsMehRAWRXD/RawrXD/pull/77) | `feature/ide-agentic-product-path-20261026` | `9edf63fed82bdf427f734591bff262282f6fe822` | OPEN | **CONFLICTING** vs `main` |
| [#78](https://github.com/ItsMehRAWRXD/RawrXD/pull/78) | `feature/agent-session-gui-20261026` | `84b4725f798f329a31660e87820c2f57115247ce` | OPEN | **CONFLICTING** vs `main` |
| [#79](https://github.com/ItsMehRAWRXD/RawrXD/pull/79) | `feature/extensionhost-runtime-clean-20261102` | `13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c` | OPEN | **CONFLICTING** vs `main` |

```
PR_OPEN ≠ MERGED ≠ INTEGRATED ≠ TIP_AUTHORITY
CI_FAILURE_ON_PR77 ≠ LOCAL_TIP_VERDICT
G_DEV_FEATURE_PUSH_TRACK ≠ F_RAWRXD_ONESHOT_TIP
```

Opening PRs does **not** authorize merge. Conflict resolution + SHA-specific gates required before any merge into `main`.

## Measured tip board (CC79 / tip_final_005)

From `NEXT_ACTIONS_RESUME.md` / `POST_E59D_CANDIDATE_001\NEXT_ACTION.md`:

| Gate | Verdict |
|------|---------|
| CHAT_CTRL_ENTER_SEND | PASS 7/7 (remeasured on CC79) |
| EXT_LOAD | PASS (remeasured on CC79) |
| TERMINAL ConPTY | PASS |
| DEBUG_CONSOLE | PASS (WFDE E2E on tip) |
| OUTPUT_GUI_E2E | **FAIL** |
| PROBLEMS_GUI_E2E | **NOT_RUN** |
| FOUR_PANEL | **NOT_VERIFIED** |
| DEEP2_VULKAN | PARTIAL |
| PACKAGING | PARTIAL_RC_STAGED |
| FINISH25_CURRENT | **4/25** |
| A4F_UNTOUCHED | 1 |

## Controlling failure (next executable gate)

Evidence: `artifacts\ide_panels_gui_run_20261109-051949.txt`

```
TIP_EXE=F:\rawrxd\package\tip_final_005\RawrXD-Win32IDE-Native-Ext.exe
TIP_SHA256=CC79F6CD…
POST_WM_COMMAND id=3014   # Build Project
PROCESS_EXITED_DURING_WAIT exit=-1 t=11
CHILD_COUNT=0
MAX_EDIT_LEN=0
```

```
NEXT_GATE=OUTPUT_PROBLEMS_GUI_E2E_OR_FOUR_PANEL_ON_CC79
ROOT_SYMPTOM=IDE_TERMINATES_ON_BUILD_PROJECT_3014
```

## Integration candidate decision

```
SOURCE_OF_TRUTH_INTEGRATION_CANDIDATE=F:\rawrxd tip_final_005 (CC79)
SLIM_BASELINE_PRESERVE=A4F083DF (immutable)
GITHUB_PR_TRACK=OPEN_CONFLICTING_HOLD_MERGE
UNIFIED_FULL_FEATURE_BUILD=NOT_YET — blocked on Output/Problems HWND survival after Build
PRODUCT_COMPLETE=0
```

Do **not** treat G:\~dev three-branch tips as superseding CC79 without a fresh unified build + SHA-specific retest.

## Continuation order (handoff §15 aligned)

1. Fix Build Project process survival + Output Build lines HWND + Problems list on a staged tip (new SHA).
2. Four-panel scenarios on that same SHA (re-verify CHAT/EXT/TERM/DEBUG if SHA changes).
3. Resolve PR #77–#79 conflicts only after local tip gates pass or explicitly rebase onto the F:\ integration candidate.
4. Autonomous coding E2E + Finish-25 recount on unified EXE.
5. Packaging / clean install / independent cert — only then `CERTIFIED=1` / `PROMOTE=1`.

## Probe hygiene

```
GIT_STATUS_BROAD=AVOID (observed hang / abort on large trees)
REMOTE_SYNC=UNCONFIRMED_AT_PROBE_TIME
USE_BOUNDED_REV_PARSE_ONLY=1
```

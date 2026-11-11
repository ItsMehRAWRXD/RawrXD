# DISPOSITION — PROGRESSION_FINISH25_001

ASOF_UTC=2026-11-09T00:22:33Z
PROGRESSION_CANDIDATE_SHA=55BE19B7D594118C9C803D8D7DA3B127E33C0C8C82A62BD50E4956D0AC2298A3
LINK_PROFILE=SLIM_WIN32IDE_DEEP2_LINKED_OPTREF
SIZE=2504704
PROMOTE=0
CERTIFIED=0
FINISH_25_PASS=19
TIP_CLIMB=HOLD
CLOSEOUT_RESTART=0
fad4e87f_SEALED_PARTIAL=NOT_RESTARTED

## Gate block
T17=PASS
T07=FAIL (BINARY=REJECTED UNICODE=FAIL)
T08=FAIL_TABCTRL_STUCK_AT_1_DESPITE_OPENS (product t08_tab_trace tabctrl=11; harness count=1 — not sealed PASS)
T10=PASS
REQUEST_A_SURVIVES=NOT_RUN
T15=CLOSED_PRIOR (not reopened)
T24_INSTALLER=NOT_RUN

## Notes
- New candidate dir only: build_progression_finish25 (baseline 3B720981 tree untouched).
- Binary reject works on progression SHA; unicode open still replaces CJK with U+003F in editor buffer.
- Multi-tab accumulation implemented and observed in-process (tabctrl grows to 11); harness IDC_DOC_TABS bind still reports 1 — fail-closed.

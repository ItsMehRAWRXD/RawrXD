# Request A tip retest disposition (fail-closed)

ASOF_UTC=2026-11-09T02:52:00Z
PROMOTE=0
CERTIFIED=0
CERTIFICATION=HELD
T08_REOPEN=0

## Sealed remote evidence (untouched)

```
REMOTE_EVIDENCE_REF=progression/finish25-323a38a0-evidence @ 36c15cbe823a384a90f9282f95b35cd824d7dcfb
URL=https://github.com/ItsMehRAWRXD/RawrXD/tree/progression/finish25-323a38a0-evidence
```

## Crash origin (controlling)

```
CRASH_ORIGIN=COMCTL32.dll+0xBD02
EXCEPTION=0xC000041D (STATUS_FATAL_USER_CALLBACK_EXCEPTION)
UNDERLYING=0xC0000005 AV write (prior dump 28836)
NEAREST_PRODUCT_WNDPROC_PRIOR=NativeGhostTextController::editorProc (kGhostTimer=0x5247)
WER_TIP_SHA_F41=same COMCTL32+0xBD02 / c000041d (TargetAppVer 2026/11/09:02:43:44)
COMCTL32_VARIANT=5.82.26100.8328 (WinSxS common-controls v5.82)
```

Evidence:
- `CANCEL/CRASH_ORIGIN_28836.md` (SHA 323A38A0)
- `CANCEL/logs/WER_3A8EE73D/Report.wer`
- WER archive `AppCrash_RawrXD-Win32IDE-_401a2517…` for tip SHA F41BAFB8

## Tip fixes landed (source; not acceptance)

1. HandleCopilotSend: drain WM_APP+106; `detachNativeGhostTextInputs()` (full unsubclass)
2. GhostText: admission pause + kGhostTimer drain; editorProc drops paused timers
3. Stop/complete: clear input while detached; `initializeNativeGhostText()` after
4. Streaming UI: buffer partials only (no streaming SetWindowTextW) — source edit pending rebuild verification

## EXE SHAs exercised this session

| SHA | Result |
|-----|--------|
| 323A38A0… (sealed) | REQUEST_A_SURVIVES=0 CRASH |
| 3A8EE73D… (pause+drain) | REQUEST_A_SURVIVES=0 CRASH ~4.5s exit -1073740771 |
| F41BAFB8… (hard detach) | REQUEST_A_SURVIVES=0 CRASH ~4.5s exit -1073740771 WER=COMCTL32+bd02 |

```
REQUEST_A_SURVIVES=0
T05=NOT_RUN
T10=NOT_RUN
T07=NOT_RUN
T08=NOT_RUN (protected; T08_REOPEN=0)
T17=NOT_RUN
ACTIVE_CANDIDATE_SHA=F41BAFB874DEEA452D2BD0E8FE5EFB848D1E148E2E58192DB344B16831B33C75
REBUILD_STREAM_BUFFER_FIX=IN_PROGRESS_OR_BLOCKED
```

## Judgment

GhostText pause/detach alone did **not** clear REQUEST_A. WER on hard-detach tip still faults the same COMCTL32 offset. Next product gate: streaming/complete transcript + ListBox thought path (sidebar EDIT SetWindowTextW / AgentStepTimeline LB_*), with fail-closed retest after a successful rebuild.

`chat_runtime.log` shows `request_started` without `callback`/`partial_buffered` before process death.

## LFS

```
LFS_STATUS=QUOTA_EXCEEDED
PUSH_ERROR=batch response: This repository exceeded its LFS budget. The account responsible for the budget should increase it to restore access.
OBJECTS_BLOCKING_PUSH=3
  c86e813d… evidence/T05_CANCELLATION_20261108_073852/T05.receipt.json
  c8ef4abb… evidence/T080_CLICK_TO_LINE_20261108_073653/T080_click_to_line_receipt_*.json
  cb4c21e8… evidence/T10_RECOVERY_20261108_073741/T10.receipt.json
GIT_LFS_SKIP_PUSH=NOT_USED (new LFS objects required)
REPAIR_BRANCH_PUSH=BLOCKED
LOCAL_REPAIR_HEAD=106630813b (plus uncommitted tip cancel/GhostText sources)
SEALED_EVIDENCE_NOREWRITE=1
BILLING_API=needs user scope (gh auth refresh -s user) — purchase/quota note: increase Git LFS budget for ItsMehRAWRXD/RawrXD
```

## Law

```
NOT_RUN != PASS
EVIDENCE_PUSH_NE_ACCEPTANCE_PASS=1
PROMOTE=0
```

# BUILD_ATTEMPT_RECEIPT — tip_rc_issue49_001

```text
ASOF_UTC=2026-11-09T18:15:43Z
TIP=tip_rc_issue49_001
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
E6CF_RESTORE=HELD
PROMOTE=0
INCREMENTAL_NINJA=1
NINJA_LOG_WIPE=0
```

## Source revision

```text
GIT_HEAD=23ca021d68062539ddb72b7c8e6ff42194780b84
BUILD_TREE=F:\rawrxd\build_tip_ext_host_001
TARGET=RawrXD-Win32IDE-Native-Ext
```

## Source edits included

1. `Win32IDE_GhostText.cpp` — Unicode `CallWindowProcW`/`DefWindowProcW`
2. `Win32IDE.cpp` / `Win32IDE.h` — chat input subclass, cache, `stageCopilotChatInputUtf8`, `getWindowTextUtf8` WM_GETTEXT path
3. `Win32IDE_AgentCommands.cpp` — `ensureProductAgentSession`, loop wiring, tool/complete ledger hooks
4. `CMakeLists.txt` — AgentSession / `rawrxd_agentic_backend` link policy for Native + Ext

## Outcome

```text
TIP_STAGED=1
CANDIDATE_PATH=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_rc_issue49_001\
CANDIDATE_SHA256=F87B4EE0035DD136FB1C1A2FC2DC6578AD95491FAA007F67F2512EE5B6BE9547
SHA256_TXT=1
LOOP_BESIDE_STAGED=1
LOOP_BESIDE_SHA256=DAFEF57714969C69515C792BC90364E34AE2DAB4E53AB8301D4AAECF1FE6906D
LOOP_BESIDE_NOTE=Copied prior staged deep2_agentic_loop.exe from tip_final_integ_010; NOT rebuilt this attempt (CloudApiClient/ggml_vk link out of scope)
AgentSession_IN_EXE=1
AgentSession_bound_IN_EXE=1
AgenticLoop_IN_EXE=1
NINJA_EXIT=0
NINJA_LOG=F:\rawrxd\evidence\INTEG_004_HIDDEN_AUDIT_20261109\ISSUE49_REMEDIATION\artifacts\ninja_ext_vcvars_20261109-131526.txt
PRIOR_ATTEMPT_NOTE=61522e46 left TIP_STAGED=0 after host shell wedge; this attempt completed incremental link under vcvars64
deep2_agentic_loop_REBUILD=NOT_ATTEMPTED_OUT_OF_SCOPE
```

Fail-closed: staged SHA is authoritative for Issue #49 remeasure `ISSUE49_REMEASURE_F87B4EE0.md`.

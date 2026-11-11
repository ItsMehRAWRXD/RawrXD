# CHAT_INPUT_ASSIGNMENT_RECEIPT — Issue #49 remediation

```text
ASOF_UTC=2026-11-09T18:16:23Z
MOTD_ACK=1
GATE=CHAT_INPUT_ASSIGNMENT
IDC=1202
IDC_NAME=IDC_COPILOT_CHAT_INPUT
TIP=tip_rc_issue49_001
CANDIDATE_SHA256=F87B4EE0035DD136FB1C1A2FC2DC6578AD95491FAA007F67F2512EE5B6BE9547
GIT_HEAD=23ca021d68062539ddb72b7c8e6ff42194780b84
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
E6CF_RESTORE=HELD
NO_CROSS_SHA_PASS_INHERITANCE=1
INVENT_PASS=0
```

## Prior measured failure (authoritative, not re-credited)

| Field | Value |
|-------|-------|
| Prior SHA | `E6CF5BD2B23638B046926F301997926BD35B1524CD3D58B59A75A24946466A3E` |
| Observation | `CHAT_INPUT setOk=True len=0 hwnd≠0` → `S_05_AGENT_PROMPT=FAIL_CHAT_INPUT_SET` |

## Source fix landed

| Change | Path | Intent |
|--------|------|--------|
| GhostText Unicode forward | `Win32IDE_GhostText.cpp` | `CallWindowProcW` + `DefWindowProcW` |
| Chat input subclass + cache | `Win32IDE.cpp` / `Win32IDE.h` | `CopilotChatInputProc` + `installCopilotChatInputSubclass` |
| Readback path | `getWindowTextUtf8` | Prefer `WM_GETTEXT`; fall back to cache |
| Staging helper | `stageCopilotChatInputUtf8` | In-process set + length/cache prove |

## Runtime disposition (SHA-bound)

```text
CHAT_INPUT=PASS
REASON=SHA_BOUND_READBACK_LEN_GT10_SET_EQ_GET
METHOD=EM_REPLACESEL
SETWINDOWTEXTW_ALONE=FAIL_FELL_THROUGH
SETWINDOWTEXTW_LEN_GT10=0
EM_REPLACESEL_LEN=54
SET_EQ_GET=1
HWND_VALID=1
S_05_AGENT_PROMPT=PASS_PROMPT_CTRL_ENTER_SEND
RUNLOG=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_tip_rc_issue49_001\issue49_product_final_tip010_20261109-131613.txt
```

Harness `StageChat` tried `SetWindowTextW` first; length gate failed, then `EM_REPLACESEL` produced `len=54` and `setEqGet=1`. Residual: primary `SetWindowTextW` path still does not stick alone on this SHA.

## Law

```text
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
E6CF_RESTORE=HELD
PROMOTE=0
```

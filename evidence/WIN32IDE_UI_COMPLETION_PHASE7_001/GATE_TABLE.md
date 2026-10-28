# Phase 7 UI gate table — WIN32IDE_UI_COMPLETION_PHASE7_001

```
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
MAIN_HWND=0xDF081A
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 UI_ACCEPTANCE_PASS=0
GHOSTTEXT_ABSORB=NOT_AUTHORIZED (B421 witness only)
NO_INVENT_PASS=1
```

| Gate | Surface | Status | Cite |
|------|---------|--------|------|
| U-CHAT | Chat panel | **RUNTIME_REACHED** | WM_COMMAND 3007 PostMessage=1; child 74→151; dump `Static title=AI Chat visible=1` + Send/Clear |
| U-DIFF | Diff review (agent session) | **RUNTIME_REACHED** | `--headless --agent-gui-proof` → `AGENT_GUI_PROOF ... review=1` on tip 748B |
| U-FILES | File counts | **RUNTIME_REACHED** | same proof line `files=1` (AgentSession bar 4110 path) |
| U-BG | Background tasks UI | **FAIL_CLOSED_NOT_WIRED_MENU** | `showTaskRunnerDialog` exists in `Win32IDE_TaskRunner.cpp` but no Commands.cpp menu case; no `RawrXD_TaskRunner` HWND on tip |
| U-MODEL | Model selector | **RUNTIME_REACHED** | tip ComboBox CB_GETCOUNT max=3 after createWindow children; dump ComboBox rows |
| U-SETTINGS | Settings | **FAIL_CLOSED** | PostMessage 5016/12040 returned 0; no Settings toplevel HWND; Gear present in dump but BM_CLICK=0 this run — not PASS |
| U-GITDIFF | Side-by-side git diff (additive) | **FAIL_CLOSED** | PostMessage 11700=0 on tip this run |

## Acceptance

| Field | Value |
|-------|-------|
| UI_ACCEPTANCE_PASS | **0** |
| RUNTIME_PASS | **0** |
| PROMOTE | **0** |

Phase 7 seals **observations + fail-closed stubs**. Not product UI certification.

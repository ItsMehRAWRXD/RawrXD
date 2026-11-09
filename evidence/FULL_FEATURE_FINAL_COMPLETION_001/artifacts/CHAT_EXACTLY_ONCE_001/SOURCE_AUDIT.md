# CHAT EXACTLY_ONCE — Source audit (win32app)

ASOF_LOCAL=2026-11-09
CONTROLLING_TIP=CC79
PROMOTE=0
EXACTLY_ONCE=NOT_VERIFIED (pre-measure)

## Entry points that can enqueue a send

| # | Path | File | Gate | Notes |
|---|------|------|------|-------|
| E1 | `WM_COMMAND` BN_CLICKED Send (`IDC_COPILOT_SEND_BTN=1204` or HWND match) | `Win32IDE_lifecycle.cpp` `onCommand` | empty/whitespace reject inside `HandleCopilotSend` | Emits `INPUT_EVENT source=button` then `HandleCopilotSend` |
| E2 | AIM `GetMessage` Ctrl+Enter (`WM_KEYDOWN` VK_RETURN + Ctrl, bit30=0) | `Win32IDE_lifecycle.cpp` `runMessageLoop` | held-key repeat suppressed | Emits `INPUT_EVENT source=ctrl_enter` then `HandleCopilotSend` |
| E3 | `HandleCopilotSend()` body | `Win32IDE.cpp` | blank reject; busy→supersede+reclaim; no-model abort | Allocates `DISPATCH_ID` / `CHAT_SEND_ATTEMPT`; arms worker |
| E4 | `generateResponseAsync` | `Win32IDE.cpp` | join live worker / generation fence | `BACKEND_REQUEST_START` + thread; end via `BACKEND_REQUEST_END` |
| E5 | Core TU Ctrl+Enter / `id==1204` | `Win32IDE_Core.cpp` | **NOT linked** into Native / Native-Ext | Dead for CC79 tip_ext; do not count as live dual-handler |

## Non-enqueue / related surfaces

| Path | Effect |
|------|--------|
| Enter / Shift+Enter alone | newline only (`ENTER_NEWLINE` evidence); no send |
| Held Ctrl+Enter auto-repeat | `HELD_KEY_REPEAT_SUPPRESSED`; no second send |
| `HandleCopilotSend_Ollama` | Ollama panel helper; product Native tip uses `HandleCopilotSend` → `generateResponseAsync` |
| `IDC_CMD_SEND_BTN` / `handleCommandSend` | Command palette / agent command lane — **not** Copilot chat send |
| `SecondarySidebarProc` | Forwards child `WM_COMMAND` once to main; Send not dual-handled in sidebar |
| AgenticBridge output callback | `appendCopilotChatUtf8` mirror → chat pane (`TRANSCRIPT_INSERT role=agent_mirror`); PowerShell-hint tracer |

## Correlation chain (instrumented)

```
INPUT_EVENT (source=button|ctrl_enter, hwnd, session, pane)
  → DISPATCH_ID
  → TRANSCRIPT_INSERT role=user
  → BACKEND_REQUEST_START / BACKEND_REQUEST_END (or cancel)
  → RESPONSE_START / RESPONSE_END
  → TRANSCRIPT_INSERT role=assistant
```

Legacy aliases retained: `CHAT_SEND_ATTEMPT`, `request_started`, `CHAT_SEND_ARMED`, `ui_update`.

## Duplicate-execution hypotheses (pre-measure)

1. **Harness multi-axis confusion**: prior `button-probe` runs share a log with prior Ctrl+Enter axes → dispatch_id 1/2 ≠ one click.
2. **Supersede**: second input while busy cancels request A and arms request B (intentional product path; not 1-click→2-dispatch).
3. **Duplicate display**: streaming partials + complete append, or agent_mirror into same pane.
4. **Double WM_COMMAND**: harness BM_CLICK + synthetic WM_COMMAND (current busywait harness uses **one** `SendMessageW(WM_COMMAND)` only).

## Frozen tips

- CC79 `tip_final_integ_002` SHA `CC79F6CD…A22940C4` — **do not overwrite**
- `tip_final_integ_005` FROZEN SHA `27E2263E…` — **do not overwrite**
- Measure on instrumented rebuild candidate; label SHA clearly; `PROMOTE=0`

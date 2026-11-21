# G51 — GhostText lifecycle: source audit (2026-11-21)

## Implemented lifecycle (compiled sources)
- `src/win32app/Win32IDE_GhostTextIntegration.cpp`
  - `initializeNativeGhostText()` (:47) — controller setup
  - `handleNativeGhostTextMessage()` (:195) — message routing
  - `invalidateNativeGhostText()` (:211) — stale-result rejection
  - `notifyGhostTextInputChanged()` (:219) — trigger on input change
  - `runNativeCodexPrompt()` (:233) — model invocation
  - `requestNativeGhostText()` (:244) — request with `RequestCancel`
- `src/win32app/Win32IDE_GhostText.cpp`
  - `attach/detach/onEditorChanged/triggerCompletion/requestCompletion` (:96-272) — generate
  - `showCompletion/positionHint` (:273-332) — render
  - `dismiss()` (:333) — dismiss
  - `accept()` (:369) — accept/insert
  - `handleMessage/ownsMessage/discardMessage` (:424-494) — input routing

## Acceptance status
| Requirement | Status |
| --- | --- |
| Generation (requestCompletion) | Implemented |
| Rendering (showCompletion/positionHint) | Implemented |
| Acceptance (accept → insert) | Implemented |
| Dismissal (dismiss) | Implemented |
| Cancellation (RequestCancel) | Implemented |
| Stale-result rejection (invalidate) | Implemented |
| Runtime GUI verification | **PENDING** (needs an editor + a live model producing completions, and visual/render confirmation) |

## Remaining for G51 closure
Drive the native IDE with a live model, trigger a completion in the editor, and
verify: the ghost text renders inline, accept inserts it, dismiss removes it,
cancel aborts an in-flight request, and a stale completion after further typing
is rejected. This is a GUI-interaction acceptance step, not a source gap.
# S025 — IDE chat input semantics

Date: 2026-11-19  
Source SHA: `40d6b92cd9bb856b66712d24ead3a45d58f16b5a`

## Source contract

The native message loop handles the chat input before `TranslateMessage`:

- Enter without Control remains a newline (`ES_WANTRETURN`).
- Shift+Enter remains a newline.
- Ctrl+Enter invokes `HandleCopilotSend()` once and suppresses synthesized
  carriage-return characters.
- Auto-repeat Ctrl+Enter is suppressed using the previous-key-state bit.
- The Send button (`1204`) invokes the same `HandleCopilotSend()` path.
- Agent mode routes Ctrl+Enter through the agentic task path explicitly.

The implementation is present in both the core message loop and the native
lifecycle message path, with input-event evidence for send and newline cases.

## Runtime status

No fresh GUI key-event acceptance run was executed against the current source
commit because the native IDE link remains blocked by the locked executable.
The source contract is verified; Enter/newline and Ctrl+Enter/Send-button
runtime evidence remains OPEN.

```ini
ENTER_NEWLINE=SOURCE_VERIFIED
CTRL_ENTER_SUBMIT=SOURCE_VERIFIED
SEND_BUTTON_SUBMIT=SOURCE_VERIFIED
HELD_KEY_REPEAT=SUPPRESSED_IN_SOURCE
GUI_KEY_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

# SOURCE_WIRE_PROBE — tip BD529691

ASOF_UTC=2026-11-09T09:27:00Z
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0

```
CANDIDATE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ext_host_oneshot\RawrXD-Win32IDE-Native.exe
SHA256=BD529691FE18D7E2EDB77D98E4C33424FF705C0BEE263429DAD600E11F42D25E
```

## ASCII presence in EXE image (measured)

| Needle | Present |
|--------|---------|
| `CreatePseudoConsole` | 1 |
| `ConPTY start ok` | 1 |
| `CHAT_SEND_ATTEMPT` | 1 |
| `Empty/whitespace message` | 1 |

## Source corroboration

- `Win32TerminalManager.cpp`: DynCreatePseudoConsole + startConPTY preferred, pipe fallback
- `Win32IDE_Core.cpp`: AIM Ctrl+Enter → HandleCopilotSend before TranslateMessage
- `Win32IDE.cpp::HandleCopilotSend`: blank reject; duplicate send blocked via m_inferenceRunning claim

## Law

```
SOURCE_WIRED_IN_IMAGE != RUNTIME_GATE_PASS
PRIOR_TERMINAL_STRING_SCAN_0_ON_OLD_TIP != this tip measurement
CHAT_CTRL_ENTER_RUNTIME still requires HWND harness PASS on this SHA
PROMOTE=0
```

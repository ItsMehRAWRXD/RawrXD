# RAWRXD_FULL_IDE_AUDIT_20261024

Audit scope: F:\\rawrxd product tree and `build_ide\\bin\\RawrXD-Win32IDE-Native.exe`.

## Directly observed

| Gate | Result | Evidence |
|---|---|---|
| Product source exists | PASS | `F:\\rawrxd` Git checkout |
| Executable exists | PASS | `RawrXD-Win32IDE-Native.exe`, 4,770,816 bytes |
| Executable hash captured | PASS | `FEE772E747B516D42CEE936A1EC32A26544BE8248B640726F8281B892EBF7489` |
| Native process launch | PASS | process PID 12600 created |
| Main-process responsiveness | PASS | `Process.Responding=True` at 6 seconds |
| Process cleanup | PASS | owned probe process terminated |
| Compiler bridge source | PASS | integrated in prior release build |
| Shell visibility source fix | PASS | commit `f0e3df6f1` |

## Not certified by this audit

| Gate | Result | Required evidence |
|---|---|---|
| Editor open/edit/save/reopen | PENDING | physical UI interaction and file hash round-trip |
| PowerShell visible after layout recovery | PENDING | HWND visibility and command output receipt |
| PowerShell command execution | PENDING | real command and exit status |
| Debugger stepping/evaluation | PENDING | live target, breakpoint, expression result |
| GhostText model completion | PENDING | model-backed suggestion, accept/dismiss/cancel |
| LSP initialize/diagnostics | PENDING | process handshake and diagnostic response |
| WebView2 rendering | PENDING | rendered page and navigation receipt |
| Native compiler/linker from IDE | PENDING | source compile, link, execute, verify |
| Deep2 full-model generation | PENDING | unified F: runtime output and parity |
| CPU/GPU numerical parity | PENDING | token/logit comparison receipt |
| Agent read/edit/build/test/verify | PENDING | real workspace transaction and verification |
| Full IDE certification | NOT_CERTIFIED | all critical runtime gates required |

## Decision

The unified F: executable launches and remains responsive during the bounded
probe. This is a valid runtime smoke result, not full IDE certification. The
remaining gates require interaction and model-backed execution that were not
observed in this audit.

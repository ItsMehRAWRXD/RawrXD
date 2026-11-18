# Win32 crash reproduction after harness fix

```ini
EXECUTABLE_SHA256=7B3A9ECE2694C82C6E578F751E3050FCE945F5B4ACFC32596CD667EEBC36E255
REQUEST_A_SUBMISSION=PASS
REQUEST_A_ARMED=PASS
CANCEL_SIGNAL=PASS
IDE_CRASH=NOT_OBSERVED
REQUEST_B_SUBMISSION=PASS
REQUEST_B_COMPLETION=TIMEOUT_OR_REPEATED_PONG
PRODUCTION_WIN32_E2E=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

The earlier access violation was caused by the harness sending `SB_GETTEXTW`
with a `StringBuilder` pointer owned by the PowerShell process. The target
status-bar control dereferenced that foreign pointer. The harness now uses
cross-process-safe `GetWindowTextW`; the same executable reaches cancellation
and Request B without reproducing `0xC000041D`.

# Final Verdict

`FOREGROUND_ACTIVATION=FAIL`

`ACTIVATION_ROOT=CONFIRMED_FOREGROUND_OWNERSHIP_DENIED`

The first failed invariant is the normal foreground request: `SetForegroundWindow` returned false and ownership remained with another PID. This is a Windows activation/session boundary in the harness environment, not evidence of a production IDE defect. `GATE_6=HELD`, `PROMOTE=0`.

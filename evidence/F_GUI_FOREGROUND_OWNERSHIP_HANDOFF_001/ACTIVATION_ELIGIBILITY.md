# Activation Eligibility Analysis

Prior physical run: target PID `23916`, target GUI thread `23916`, foreground PID `10416`, foreground HWND `0xA0296`. `SetForegroundWindow` returned false and ten samples showed no transfer.

The current foreground owner is Microsoft Edge PID `10416` (`msedge.exe`, default profile), confirming that the prior foreground HWND belonged to another application. This identifies the owner but does not prove which Windows foreground-lock rule denied the request.

No source evidence establishes that the harness was foreground-eligible, that the target and caller shared an input queue, or that a desktop/session mismatch caused the denial.

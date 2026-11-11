# T05 Runtime Receipt — Current Candidate

Date: 2026-11-04 (America/New_York)
Candidate: `F:\\rawrxd\\build_repair_candidate\\bin\\RawrXD-Win32IDE-Native.exe`
SHA256: `D7101D09DCCFEDBCC9CFFC377AB0B218A7A1D42DE4F1EF9D85C2B569483CE5D0`
Source commit: `fc362b7126f9c92ffa27a26abc742886c58f24af`

## Physical sequence

1. Launched the exact candidate and observed a responsive native Win32 IDE.
2. Submitted Request A: `T05_RUNTIME_A_20261104` with a deliberately long prompt.
3. Stop became enabled during active inference.
4. Activated Stop. The status bar reported `Chat generation stopped.` and the transcript displayed `[stopped] generation cancelled`.
5. Submitted Request B: `T05_RUNTIME_B_20261104`.
6. An immediate duplicate Send while B was still active was rejected with: `Inference is already running; press Stop before sending another message.`
7. Request B then completed asynchronously and the ChatWindow rendered `AI: T05_RUNTIME_B_20261104`.

## Disposition

```ini
REQUEST_A_STARTED=PASS
STOP_ENABLED_DURING_INFERENCE=PASS
STOP_ACTIVATED=PASS
CANCELLATION_UI_ACK=PASS
REQUEST_B_ACCEPTED=PASS
CANCELLATION_CLEANUP=PASS_BEHAVIORAL
T05=PASS_BEHAVIORAL

The transient busy guard was observed during B and is not itself a failure; the required post-cancel request completed without restarting the process. A lower-level worker-termination receipt remains unavailable.
```

This receipt is tied to the candidate hash above. No source or binary mutation occurred during the test.

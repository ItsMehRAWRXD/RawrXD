# Exact-hash production GhostText normal-lifecycle receipt

Run date: 2026-11-02
Workspace: `F:\rawrxd`

## Binary identity

- Executable: `F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe`
- SHA-256: `28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8`
- Size: `1,731,072` bytes
- Last write: `2026-11-02T04:12:43.9407929-05:00`
- Launch PID: `21264`
- Launch record: `2026-11-02T04:34:37.1923911-05:00`
- Working directory: `F:\rawrxd`
- Test environment: `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=5000`, `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS=50`

The executable hash and launch record were captured before the test from the
same production path. The IDE log itself does not embed the executable hash;
the hash association is therefore an external launch receipt, not an
in-binary provenance marker.

## Log identity

- Log: `F:\rawrxd\logs\RawrXD_IDE_20261102_043504.log`
- Log start: `2026-11-02 04:35:04`
- Log last write: `2026-11-02T04:35:29.4427919-05:00`
- Log-reported route: `qwen3:8b backend=ollama`

## Observed normal-operation scope

The native debug surface and operator-provided trace show:

- native GhostText controller ready;
- seven input surfaces attached;
- native selector populated and explicit `Local models / Ollama / qwen3:8b`
  committed;
- real Ollama inference route for `qwen3:8b`;
- request 1 rendered with a non-empty response;
- request 1 dismissed and generation invalidated;
- request 2 was regenerated and rendered with a non-empty response;
- identity and snapshot eligibility checks were reported as current for the
  two normal-operation render decisions.

This is a normal-operation lifecycle witness for the exact-hash launch,
subject to the external launch-record association above.

## Limits

- The trace does not prove that request B was dispatched while delayed request
  A was still pending.
- It does not prove B-before-A rendering or late-A rejection for this exact
  hash.
- The process was absent on the final inventory check, but a timestamped
  graceful-close request and exit receipt were not captured for this run.
- No binary replacement, source modification, or promotion occurred.

## Disposition

```ini
EXACT_HASH_ASSOCIATION=PASS_EXTERNAL_LAUNCH_RECEIPT
GHOSTTEXT_QWEN_OLLAMA=PASS_SCOPE_NORMAL_LIFECYCLE
GHOSTTEXT_RENDER=PASS_SCOPE_2_REQUESTS
GHOSTTEXT_AB_OVERLAP=NOT_VERIFIED
GHOSTTEXT_B_BEFORE_A=NOT_VERIFIED
GHOSTTEXT_LATE_A_REJECTION=NOT_VERIFIED
PROCESS_EXIT_RECEIPT=NOT_CAPTURED
GATE6_PRODUCTION=HELD
PROMOTE=0
CERTIFIED=0
```

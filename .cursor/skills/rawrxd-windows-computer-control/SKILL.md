---
name: rawrxd-windows-computer-control
description: Local Windows GUI acceptance harness for RawrXD T05, T10, T080, T15 and soak gates, with same-hash evidence and fail-closed validation.
---

# RawrXD Windows Computer Control

This skill governs physical acceptance testing of an explicitly authorized local
RawrXD process. It never treats a sent command as proof of success, and it
never promotes or replaces a production executable.

## Candidate identity

Before every test, record the executable path, exact SHA-256, source commit,
size, PID, process start time, workspace, and evidence directory. Rehash after
the test. Any mismatch stops the test and invalidates that receipt.

## Control order

Use Microsoft UI Automation first, then read-only Win32 enumeration, then
SendInput only after foreground and focus are independently verified. Use
coordinates only with screenshot calibration and post-action verification.
Never certify by sending WM_COMMAND or synthetic callback messages.

## Gate requirements

- T05: GUI A → observed active generation → GUI Stop → observed cancellation →
  GUI B in the same PID → exact B completion, no late A output, no orphan child.
- T10: create a genuinely unsaved GUI buffer, observe autosave contents, hard
  terminate the verified PID, cold-launch the same binary, and verify exact
  recovered text, tab identity, dirty state, and content hash.
- T080: create a known compiler error, invoke GUI Build/Compile, verify the
  Problems row, activate it physically, and verify document plus caret line and
  column.
- T15: submit a natural-language request through the agent UI and capture the
  raw model tool call, normalization, authorization, dispatch, result, exact
  before/after file hashes, and model continuation. Direct CLI calls do not
  count.
- T18/T19: use the exact acceptance specifications and record resource trends,
  errors, cancellation, recovery, and content integrity over repeated cycles.

## Receipt requirements

Every gate receipt must include identity, timestamps, PID, workspace, action
log, observations, screenshots or equivalent UI evidence, artifact hashes,
expected/actual results, and an explicit PASS/FAIL/NOT_VERIFIED disposition.
Missing observations are NOT_VERIFIED.

## Release controls

Keep `REBUILD=HELD`, `PROMOTE=0`, and `CERTIFIED=0` unless separate authority
and independent evidence establish otherwise. A new executable hash requires
fresh candidate-specific runtime evidence.

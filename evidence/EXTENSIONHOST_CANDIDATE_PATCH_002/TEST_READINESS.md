# Test readiness

`BUILD=NOT_RUN` · `RUNTIME=NOT_RUN`

The candidate is ready for a separately authorized build review, not runtime certification.

Planned focused tests:

- CMake target graph contains all eight runtime TUs and `RawrXD-ExtensionHost`.
- Post-build output contains both `RawrXD-Win32IDE.exe` and `RawrXD-ExtensionHost.exe` beside one another.
- Missing worker path fails closed with PID zero.
- IDs and paths containing spaces, quotes, and trailing backslashes survive argument construction.
- Forced `CreateProcessA` failure exposes the captured Windows error code.
- Child readiness event is required before activation succeeds.
- Readiness timeout cleans up the child and reports failure.
- Shutdown signals the child, observes bounded exit, and uses termination only after timeout.
- Full ExtensionHost matrix reruns against one exact candidate SHA.

No test was executed or marked PASS by this package.


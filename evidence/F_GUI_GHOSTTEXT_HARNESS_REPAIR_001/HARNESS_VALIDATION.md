# Harness Validation

Static validation completed:

- Exact candidate hash is checked before execution.
- Default invocation is static-only and does not launch the GUI.
- `-Run` refuses to start if another production IDE process exists.
- HWND attribution is restricted to the child tree of the newly started PID.
- The editor must be visible, enabled, have positive client geometry, and pass focus verification.
- Close is attempted through `CloseMainWindow`; forced termination is bounded and reported as warning.

Physical execution is not claimed by this receipt.

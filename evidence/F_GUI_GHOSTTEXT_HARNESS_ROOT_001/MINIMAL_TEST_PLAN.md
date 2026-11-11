# Minimal Test Plan

1. Use an isolated temporary workspace and record the exact executable hash.
2. Enumerate the main window and descendants by HWND/class, explicitly locating the `RICHEDIT` editor rather than using center coordinates.
3. Verify visibility, nonzero client rectangle, owning thread, and `GetFocus()` after a target-specific focus operation.
4. Perform file open/edit/save/reload against the fixture and compare bytes on disk.
5. Dispatch real editor input through the focused editor HWND: text change, `Ctrl+Space`, wait for the bounded response, then capture the lifecycle trace.
6. Verify visible suggestion, Tab acceptance, second request, Escape dismissal, and edit-triggered cancellation/stale-result rejection.
7. Close through the main HWND/title-bar command, wait for process exit, and record exit code without force termination.

The test must fail at the first missing HWND/focus/event boundary and retain the trace. It must not synthesize GhostText events or infer a PASS from catalog/configuration labels.

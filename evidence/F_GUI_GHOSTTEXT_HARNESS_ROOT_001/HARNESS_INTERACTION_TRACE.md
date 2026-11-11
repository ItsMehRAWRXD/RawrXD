# Harness Interaction Trace

Evidence source: `F_PRODUCTION_REGRESSION_COMPLETION_002` and the recorded GUI attempt.

1. The exact native executable launched and exposed the main window, workspace tree, chat/model controls, GhostText selector, cloud-consent checkbox, and PowerShell pane.
2. The accessibility surface did not expose a usable editor target.
3. `Ctrl+N` was sent while focus remained on a combo/control and did not create a reachable editor surface.
4. `Ctrl+O` did not produce a file dialog.
5. A coordinate intended for the center editor landed on the PowerShell console, demonstrating stale or incorrect geometry mapping.
6. File-menu and close actions failed with `coordinate input geometry is unavailable`.
7. Because the close action could not be delivered, the harness force-stopped the remaining IDE process. This was cleanup, not clean-shutdown proof.

The trace stops before an editor HWND was focused. Therefore no real editor edit, GhostText trigger, response, render, accept, dismiss, or cancellation event was observed in this run.

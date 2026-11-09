# Runtime comparison

| Aspect | Earlier hanging run | Controlled reproduction |
|---|---|---|
| Candidate executable | Same reported G build path and required hash | Same exact path and verified hash |
| Initial UI | Initialized ScreenPilot/Desktop Preview | Initialized ScreenPilot/Desktop Preview |
| Interaction | Top-level `Commands`, leaf/ID not captured | Top-level `Commands`, menu opened; no leaf selected |
| Result | UI later reported non-responsive; process exited | Responsive after five seconds |
| Dispatch evidence | No marker or command ID | No leaf marker or command ID |
| ExtensionHost | Not observed | Not observed |
| Cleanup | Prior run exited; details limited | Alt+F4 failed; test-owned PID was force-stopped |

The runs are not proven equivalent beyond the top-level menu label. Timing, menu state, startup phase, workspace/configuration state, and the exact accessibility action sequence were not captured identically. The non-reproduction therefore cannot close the earlier failure.

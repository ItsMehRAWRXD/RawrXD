# Prior runtime timeline

Scope: read-only reconstruction from `evidence/G_EXTENSIONHOST_RUNTIME_E2E_001` and the recorded UI/process observations. No new launch was performed.

1. Candidate preflight verified the reported IDE hash `3711804F318C8A81E154C7009E5AD77E7ABC8CF2536AC228CFB2510F854CE652`, worker hash `53078674DEF8127A802F34ECE71C94A2FEBE0291AA6250E17B8BD2D41C41D07B`, and frozen authority hash `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`.
2. The exact candidate IDE was launched from `G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_clean_001\bin\RawrXD-Win32IDE.exe`.
3. Initial UI state appeared in window `HWND=6687086`, process path above, title recorded as `RawrXD ScreenPilot — Desktop Preview`. The accessibility tree showed an initialized desktop preview with menus including `Commands`.
4. The only recorded interaction was a click on accessibility element index 33, the top-level menu item `Commands`. The leaf command and numeric command ID were not captured.
5. After that interaction the UI became non-responsive. A window listing reported the preview as `Not Responding`; PowerShell reported the candidate PID 24408 with `Responding=False`.
6. No `RawrXD-ExtensionHost.exe` child PID, route marker, readiness event, IPC response, or child hash was observed. Later process inspection found no candidate IDE or ExtensionHost process.

The timeline proves post-interaction non-responsiveness, but not the call that blocked, crashed, or timed out.

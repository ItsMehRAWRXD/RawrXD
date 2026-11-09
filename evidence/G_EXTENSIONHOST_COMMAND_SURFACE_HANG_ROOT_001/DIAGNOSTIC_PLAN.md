# Diagnostic plan

No source change or additional runtime launch is authorized in this gate. A future separately authorized single reproduction should capture, in order:

1. Candidate executable hash, PID, main HWND, UI thread ID, and interaction timestamp.
2. Menu text plus the resolved leaf command ID and `WM_COMMAND` parameters.
3. Existing `RawrXD::CommandTelemetry::CmdDiagBreadcrumb` markers at `WM_COMMAND_ENTER`, `onCommand_ENTER`, route entry, handler entry, route return, and `WM_COMMAND_EXIT_OK` (`src/win32app/Win32IDE_Core.cpp:610-622`, `5250+`, approximately `5838-5878`).
4. If dispatch reaches extension handling, the launch attempt, immediate `GetLastError()` on failure, child PID/hash, ready-event result, IPC request/response, and shutdown wait result (`ProductExtensionRuntime_Host.cpp:24-107`).
5. If the UI stops responding, capture a bounded thread stack/wait-chain or hang dump before cleanup, if separately authorized. Record process exit code rather than inferring it from disappearance.

Stop at the first missing marker. Do not record prompts, credentials, or workspace contents. A bounded 10-15 second observation window is sufficient to distinguish an absent dispatch marker from a handler that entered and failed to return.

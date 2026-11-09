# EXTENSIONHOST_CANDIDATE_PATCH_002 — source review

`PATCH_APPLIED=1` · candidate-only · base `273924f…`

## Scope review

Exactly four tracked source/build files changed:

1. `CMakeLists.txt`: adds the eight ProductExtensionRuntime implementation TUs, creates `RawrXD-ExtensionHost`, adds an explicit IDE dependency, and copies the worker beside the IDE output.
2. `src/win32app/ProductExtensionRuntime.hpp`: adds ready/stop event handles and launch-error state.
3. `src/win32app/ProductExtensionRuntime_Host.cpp`: adds canonical executable validation, Windows argument quoting, per-launch named events, immediate `GetLastError()` capture, bounded readiness wait, and graceful shutdown fallback.
4. `src/win32app/ExtensionHostWorker_main.cpp`: parses event names, opens the parent-created events, signals readiness, and exits on the stop event.

No primary-tree files, frozen binaries, unrelated IDE subsystems, or generated outputs were modified.

## Review findings

- Route ownership was already wired in the recovered committed baseline (`Win32IDE_LocalServer.cpp` and `HeadlessIDE_GuiRoutes.cpp`), so no redundant route edits were made.
- The worker target is distinct from the existing smoke companion target and uses the real worker entry point.
- The parent does not mark the extension active until the child signals readiness.
- Launch failures retain the immediate Windows error code in `HostState::lastLaunchError` and expose it through host status.
- Shutdown signals the named stop event, waits up to two seconds, then terminates as a fallback.
- `git diff --check` reports trailing-whitespace warnings on added lines because the Windows source files use mixed line-ending representation; this is recorded and must be cleaned or accepted during review before build authorization.

## Not verified

Compilation, linker correctness, child process creation, event permissions, IPC behavior beyond the readiness event, and clean shutdown are not verified. No PASS is claimed.


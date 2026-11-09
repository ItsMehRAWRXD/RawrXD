# ExtensionHost deployment contract

1. `RawrXD-Win32IDE` and `RawrXD-ExtensionHost` are built from the same source revision and configuration.
2. `RawrXD-ExtensionHost.exe` is a required runtime companion, not an optional smoke artifact.
3. The worker is emitted into the same directory as the candidate IDE executable.
4. The IDE resolves the worker from its own canonical executable directory; it does not search `PATH` or the source tree.
5. The candidate manifest records IDE SHA-256, worker SHA-256, source revision, configuration, and output directory.
6. The build graph has an explicit dependency from IDE to worker deployment.
7. Missing worker, mismatched worker, launch failure, readiness timeout, and protocol mismatch all fail closed with `host_pid=0` and structured diagnostics.
8. The frozen authority at `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` is never an output target of this contract.


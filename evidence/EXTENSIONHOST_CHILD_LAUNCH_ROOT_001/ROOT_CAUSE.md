# EXTENSIONHOST_CHILD_LAUNCH_ROOT_001 — root cause

## Confirmed root cause for the historical failure

The failing candidate did not reach child-process creation. Its extension API was still served by the thin adapter, while the real `ProductExtensionRuntime` objects were not linked and the worker executable was absent. The failure therefore occurred at the route/linkage/deployment boundary:

`extension request → product_thin response → host_pid=0`

Supporting evidence: `evidence/EXTENSION_RUNTIME_MATRIX_001/RECEIPT.md` records all five functional cells as failures with `adapter=product_thin`; `evidence/EXTENSION_RUNTIME_73368_REPAIR_001/DIAGNOSIS.md` records the three root-cause items and the candidate-only repair.

## Confirmed source gaps found during diagnosis

1. `ProductExtensionRuntime_Host.cpp:42-44` constructs a command line without escaping `rec.id`; a path containing quotes or trailing backslashes can be parsed incorrectly.
2. `ProductExtensionRuntime_Host.cpp:46-49` returns only `false` on process-creation failure and does not capture `GetLastError()`, preventing precise launch diagnostics.
3. `ExtensionHostWorker_main.cpp:4-12` has no argument parsing, extension loading, IPC initialization, readiness message, or handshake. It only creates a named stop event and waits.
4. `CloseHostUnlocked()` terminates the process directly and does not signal the named stop event (`ProductExtensionRuntime_Host.cpp:7-19`).

These are source-confirmed defects/gaps, but they are not evidence that any one caused the historical `73368` failure after the route/linkage boundary was repaired.

## Minimal proposed corrective patch

Candidate-only and separately authorized:

- replace ad-hoc command construction with a Windows argument-quoting helper for `rec.id` and `rec.path`;
- capture `GetLastError()` and include a structured launch diagnostic;
- define a real parent/child readiness contract (named event or inherited pipe) and wait with a bounded timeout before marking the extension active;
- make shutdown signal the worker stop mechanism before fallback termination;
- keep route wiring and worker deployment explicit in the candidate target graph.

No source was modified for this diagnosis.


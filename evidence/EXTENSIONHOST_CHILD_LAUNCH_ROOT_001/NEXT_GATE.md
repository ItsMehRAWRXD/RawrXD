# EXTENSIONHOST_CHILD_LAUNCH_ROOT_001 — next gate

## Decision

`PHASE_1=REPORTED_COMPLETE`  
`NEXT_PRIORITY=EXTENSIONHOST_CHILD_LAUNCH_ROOT_001`  
`ROOT_CAUSE=ESTABLISHED_FOR_HISTORICAL_73368`  
`PROMOTE=0` · `TIP_CLIMB=HOLD` · `CERTIFIED=0` · `PRODUCT_RUNTIME=NOT_REVALIDATED`

## Next authorized action

Request authorization for a **candidate-only** patch covering argument quoting, launch-error capture, readiness handshake/timeout, and orderly shutdown. Do not touch or rebuild the frozen `748B210A…` executable.

## Regression tests to specify before implementation

1. Route dispatch reaches `ProductExtensionRuntime::HandleRoute`, not `ProductGuiRoutes::extensionsJson`.
2. Missing worker executable returns a fail-closed error with `host_pid=0` and a diagnosable reason.
3. IDs and paths containing spaces, quotes, and trailing slashes are passed correctly.
4. `CreateProcessA` failure records the Windows error code.
5. Parent observes child readiness before returning `active=true`.
6. Readiness timeout cleans up the child and never reports an active extension.
7. Shutdown signals the worker, closes handles, and clears PID/state.
8. Candidate `EXTENSION_RUNTIME_MATRIX_003` reruns all six cells against one exact candidate SHA.

## Evidence requirements

The next gate must include the candidate SHA, worker SHA, source revision, route-selection trace, launch diagnostics, readiness/shutdown receipts, and explicit tip hash equality. A runtime PASS from `FD07CA61…` must not be transferred to the frozen tip.


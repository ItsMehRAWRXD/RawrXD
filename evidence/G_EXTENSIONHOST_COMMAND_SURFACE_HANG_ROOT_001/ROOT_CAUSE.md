# Root cause

`COMMAND_SURFACE_ROOT=UNVERIFIED`

`HANG_ROOT=UNVERIFIED`

Earliest demonstrated boundary: after clicking the top-level `Commands` menu item, the candidate IDE became non-responsive. No command-dispatch marker was captured before that observation, so the first blocking function is not proven.

Confirmed facts:

- The exact candidate UI initialized.
- The recorded interaction was accessibility element 33, `Commands`.
- Candidate PID 24408 later reported `Responding=False` and then exited.
- No ExtensionHost child or IPC activity was observed.
- The source contains synchronous UI command routing and a separate synchronous child-launch/readiness path.

Not established:

- The leaf command ID.
- Whether `WM_COMMAND` entered `onCommand`.
- Whether a handler blocked, deadlocked, crashed, or starved the message pump.
- Whether the test harness timed out independently of the process.

The most defensible conclusion is a pre-ExtensionHost command-surface failure boundary, with its exact mechanism unproven.

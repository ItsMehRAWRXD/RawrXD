# Next gate

Keep source, binaries, promotion, and frozen authority unchanged. Do not retry the runtime in this gate.

The next gate is a separately authorized, single controlled reproduction with command ID capture, existing dispatch breadcrumbs, process/thread identity, and a bounded wait-chain or hang-dump capture. The goal is to establish whether the first missing marker is before `WM_COMMAND`, inside `onCommand`/routing, or after an actual ExtensionHost launch attempt.

Until that evidence exists:

`HANG_ROOT=UNVERIFIED`

`EXTENSIONHOST_REACHED=0`

`RUNTIME=HELD`

`PROMOTE=0`

# Browser route authority policy

The uploaded HTML contains a large historical `/api/*` surface. The final
ScreenPilot agent path is canonical, but specialty panels still call those
legacy endpoints.

Apply this rule in LocalServer:

## Public/read-only bootstrap routes

These may remain readable from loopback after Host/Origin validation:

- `/api/v1/screenpilot/health`
- `/api/v1/screenpilot/session`
- static `/screenpilot*`
- carefully reviewed status/metrics/model-list routes

## Privileged routes

Require a valid `X-RawrXD-Session` **and** route the operation through canonical
Tool Authority, or deny the browser caller.

At minimum this includes any endpoint that can:

- write/delete/move/create files
- execute a process or CLI command
- build/test/assemble
- alter Git state or contact a Git remote
- install/enable/disable/load extensions
- load/unload/swap models
- hotpatch memory/binaries/server behavior
- mutate debugger state
- perform outbound browsing/download/network access
- change backend/engine/governor state
- invoke an arbitrary tool/subagent

A session token authenticates the local UI. It does **not** authorize a tool.
Mode policy, workspace checks, and approval checks remain mandatory.

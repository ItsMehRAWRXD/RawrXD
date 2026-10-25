# RawrXD Chat Rollback / Snapshot Boundary — 001

Date: 2026-10-25

## Provenance

- Source root: `F:\rawrxd`
- Branch: `fix/deep2-multimodel-safety-20261025`
- Source HEAD at verification: `5c128adf94870c23c2ab296ec14f07f2ae5e2ee7`
- Executable: `F:\rawrxd\build_crashfix_verify\bin\RawrXD-Win32IDE-Native.exe`
- Executable size: `5,607,424` bytes
- Executable SHA-256: `5DB9CDE2CDD97CD8EC9A0E7AD5317AF1C7C43B1755884E2389C531447FAAE23D`

## Implementation

- Each `ChatSessionState` owns a bounded stack of 32 `ChatSessionCheckpoint` values.
- Checkpoints are captured automatically before sending a message and before clearing a chat.
- A checkpoint contains the chat route, GhostText route/mode, cloud-consent state, max-token and context settings, transcript, and in-flight response buffer.
- `Rollback` stops active inference before restoring the checkpoint and refreshes the visible transcript, route selection, context controls, and session-tab state.
- Closing and restoring a chat moves the complete `ChatSessionState`, including its checkpoints.
- Chat rollback is intentionally separate from workspace/file snapshots: it never writes, restores, or mutates project files. Existing workspace snapshots therefore remain safe and independent.

## Runtime smoke evidence

- Release link: PASS; canonical executable rebuilt from current source.
- Native health check: PASS; `healthy (ready=true)`, exit code `0`.
- Canonical GUI launch: PASS; the fresh exact-path smoke process remained alive and responsive after startup and model discovery.
- Model selector: PASS; control `1206` contained `252` rows and arrow-area activation changed dropped state `0 -> 1`.
- GhostText selector: PASS; control `1211` contained `255` rows and arrow-area activation changed dropped state `0 -> 1`.
- Chat checkpoint/rollback: PASS at native control level; Rollback control `1216` was disabled before a checkpoint, enabled after a real Clear command, and disabled after a real Rollback command. The process remained alive.

## Certification boundary

The implementation and live control transaction are verified. A separate manual GUI gate remains for visually confirming the popup and for restoring a multi-message transcript after an actual model response; no synthetic response was used to claim that gate.

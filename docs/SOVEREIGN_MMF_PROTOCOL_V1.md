# Sovereign MMF/Event Protocol v1

This document is the canonical contract for the memory-mapped file transport between Sovereign orchestrator and MASM clients.

## Transport Names

- Mapping: `SOVEREIGN_BEACON_V1`
- Command event: `SOVEREIGN_CMD_EVENT`
- Response event: `SOVEREIGN_RESP_EVENT`
- Inference trigger event: `SOVEREIGN_INFER_EVENT` (manual reset, initially nonsignaled)

## Shared Memory Layout (64 KiB)

| Offset | Size | Field | Notes |
|---|---:|---|---|
| `0x0000` | 4 | `State` | Client writes `1` (`BEACON_READY`) before signaling command event. Orchestrator writes processing/completion states. |
| `0x0004` | 4 | `CommandId` | Requested command ID. |
| `0x0008` | 4 | `CommandType` | Mirrors command family/type. |
| `0x000C` | 4 | `PayloadLength` | Bytes in command payload. |
| `0x0010` | 4 | `ResponseStatus` | `0=OK`, nonzero=error/busy/not-ready. |
| `0x0014` | 4 | `ResponseLength` | Bytes in response payload. |
| `0x0018` | variable | `CommandPayload` | Input payload (ASCII/bytes depending on command). |
| `0x1018` | variable | `ResponsePayload` | Output payload (JSON or binary). |
| `0xFFF0` | 8 | `MagicCookie` | Integrity cookie (`0xCAFEBABEDEADBEEF`). |
| `0xFFF8` | 8 | `Heartbeat` | Monotonic watchdog counter. |

## Startup Audit Banner

At startup (after mapping/events init and before dispatch loop), the orchestrator emits a diagnostic block:

- Process ID
- `hShMem`
- `hCmdEvent`
- `hRespEvent`
- `pShMem` (mapped base)
- `last_error` (`GetLastError` snapshot)
- `uptime_ms` (`GetTickCount64`)

Fail-closed policy:

- If any required handle/base pointer is null, the process exits with a nonzero audit error code.
- If startup `last_error` is neither `ERROR_SUCCESS` nor `ERROR_ALREADY_EXISTS`, the process exits with a nonzero audit error code.

## Protocol Versioning

- Current protocol version: `1`
- Version exposure:
  - `GET_VERSION` response includes `"protocol":1`
  - `STATUS` responses include `"protocol":1`
  - `LOAD_MODEL` ready response includes `"protocol":1`

Versioning rule:
- Increment protocol for any wire-level breaking change.
- Keep old command IDs/legacy mappings until all clients are migrated.

## State Model

- `UNLOADED`
- `LOADING`
- `READY`
- `INFERENCE_ACTIVE`

## Inference Buffer Segmentation (Non-Blocking Handoff)

The v1 implementation uses a **non-blocking handoff pattern** for inference. The orchestrator transitions state and signals a background worker thread, then returns immediately to continue servicing heartbeat commands.

### Memory Map

| Offset | Size | Segment | Purpose |
|---|---:|---|---|
| `0x0000` | `0x0010` | Control Header | `State`, `CommandId`, `CommandType`, `PayloadLength` |
| `0x0010` | `0x1000` | Input Buffer | Prompt/model-path and inference request data |
| `0x1010` | `0x1000` | Output Buffer | Incremental token/result output |
| `0x2010` | `0x0010` | Inference Progress | Streaming flags/percent/status for non-blocking consumers |
| `0xFFF8` | `0x0008` | Watchdog | Heartbeat counter |

### Progress Fields at `0x2010`

- `+0`: `ProgressPercent` (`DWORD`)
- `+4`: `NewTokensAvailable` (`DWORD` flag)
- `+8`: `OutputBytesReady` (`DWORD`)
- `+12`: `InferenceStatus` (`DWORD`)

### Non-Blocking Handoff Sequence

1. **Client sends `CMD_INFER`** with prompt in `OFF_CMD_PAYLOAD`
2. **Orchestrator gates on `READY` state** (rejects if `UNLOADED`, `LOADING`, or `INFERENCE_ACTIVE`)
3. **Transition to `INFERENCE_ACTIVE`**
4. **Signal `g_hInferenceTrigger` event** (background worker wakes)
5. **Return `RESP_OK` immediately** (handoff complete)
6. **Background worker thread**:
   - Waits on `g_hInferenceTrigger` (infinite wait)
   - Verifies `INFERENCE_ACTIVE` state (spurious wake protection)
   - Reads prompt from `OFF_CMD_PAYLOAD`
   - Initializes streamer via `STREAMER_INIT`
   - Generates tokens and calls `STREAMER_PUSH_TOKEN`
   - Updates `OFF_TELEM_TOKENS_GEN` and `OFF_TELEM_PROGRESS`
   - Flushes tokens via `STREAMER_FLUSH`
   - Writes response to `OFF_RESP_PAYLOAD`
   - Resets `g_ModelState` to `READY` on completion

### Worker Thread Architecture

The orchestrator spawns a background worker thread during initialization (`BeaconInit`) that handles all inference operations:

### Thread Lifecycle

1. **Creation**: `CreateThread` called in `BeaconInit` with `InferenceWorkerThread` entry point
2. **Wait State**: Thread blocks on `g_hInferenceTrigger` (manual reset event)
3. **Wake Condition**: Orchestrator signals event after state transition to `INFERENCE_ACTIVE`
4. **Execution**: Worker runs inference loop, streams tokens, updates telemetry
5. **Completion**: Worker resets state to `READY` and returns to wait state

### Thread Safety

- **Atomic token buffer**: `STREAMER_PUSH_TOKEN` uses `lock cmpxchg` for thread-safe token accumulation
- **State protection**: Worker verifies `INFERENCE_ACTIVE` state before proceeding (spurious wake protection)
- **Event synchronization**: Manual reset event ensures clean handoff between orchestrator and worker

### Components Linked

| Component | Purpose |
|-----------|---------|
| `SovereignOrchestrator_Hardened.asm` | Main dispatcher, state machine, MMF management |
| `Sovereign_Model_Streamer.asm` | Token accumulation, Ghost Engine bridge, telemetry signing |
| `Sovereign_GGUF_Loader.asm` | Memory-mapped model loading, tensor table management |
| `Sovereign_Inference_Worker.asm` | Background worker thread, inference loop, state reset |

## Watchdog Safety

The non-blocking pattern ensures the orchestrator continues incrementing the heartbeat counter during inference. The watchdog agent will not falsely detect a "stalled" orchestrator because:

- `STATUS` and `METRICS` commands remain serviceable during inference
- Heartbeat counter continues incrementing in the dispatch loop
- Worker thread handles long-running inference without blocking the main loop
- Telemetry fields (`OFF_TELEM_TOKENS_GEN`, `OFF_TELEM_PROGRESS`) provide real-time progress visibility

### Command Validity (current behavior)

- `UNLOADED`: `STATUS`, `LOAD_MODEL`
- `LOADING`: `STATUS`
- `READY`: `STATUS`, `INFER`, `UNLOAD_MODEL`
- `INFERENCE_ACTIVE`: `STATUS`, `CANCEL_INFER`, `STREAM_STATUS`

## Telemetry (`CMD_GET_METRICS`, `0x7000`)

Current binary payload layout (`24` bytes):

| Offset | Size | Field |
|---|---:|---|
| `+0` | 4 | `ModelState` |
| `+4` | 4 | `LastLoadResult` |
| `+8` | 4 | `LastLoadWin32Error` |
| `+12` | 4 | `LastLoadDurationMs` |
| `+16` | 8 | `Heartbeat` |

Client adapters may convert this binary payload to JSON for dashboards and logs.

## Recommended Client Flow

1. Write command fields (`State=1`, IDs/types, payload).
2. Signal `SOVEREIGN_CMD_EVENT`.
3. Wait on `SOVEREIGN_RESP_EVENT`.
4. Read response status/length/payload.
5. Optionally sample heartbeat and metrics for liveness/state coherence.

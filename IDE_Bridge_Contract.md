# IDE Bridge Contract (Sovereign Kernel Black-Box)

Status: Draft v1.0
Date: 2026-06-02
Scope: IDE to SovereignOrchestrator black-box integration with deterministic cancellation semantics.

## 1. Design Goals

- Keep SovereignOrchestrator.exe immutable as the execution kernel.
- Put all IDE-specific transport policy into a bridge control plane.
- Preserve deterministic behavior under cancel storms.
- Keep telemetry and control separated.

## 2. Runtime Topology

- IDE process writes requests into IDE bridge MMF.
- IDE bridge process is the only writer to Sovereign command lane.
- SovereignOrchestrator remains authoritative for model state and execution.
- IDE reads completions from bridge response ring and observability snapshots.

## 3. Sovereign Black-Box Contract (Existing, Stable)

MMF name: SOVEREIGN_BEACON_V1
Size: 65536 bytes

Event names:
- SOVEREIGN_CMD_EVENT
- SOVEREIGN_RESP_EVENT
- SOVEREIGN_INFER_EVENT
- SOVEREIGN_CANCEL_EVENT

### 3.1 Header/Control Offsets (hex)

- OFF_STATE = 0x0000
- OFF_CMD_ID = 0x0004
- OFF_CMD_TYPE = 0x0008
- OFF_PAYLOAD_LEN = 0x000C
- OFF_RESP_STATUS = 0x0010
- OFF_RESP_LEN = 0x0014
- OFF_CMD_PAYLOAD = 0x0018
- OFF_RESP_PAYLOAD = 0x1018
- OFF_MODEL_STATE = 0x2030
- OFF_RING_HEAD = 0x2040
- OFF_RING_TAIL = 0x2048
- OFF_RING_DROPPED = 0x2050
- OFF_RING_BACKPRESSURE = 0x2058
- OFF_RING_FILL_LEVEL = 0x2060
- OFF_RING_CAPACITY = 0x2064
- OFF_RING_LAST_CMD_ID = 0x2068
- OFF_RING_LAST_STATUS = 0x206C
- OFF_RING_LAST_PLEN = 0x2070
- OFF_RING_LAST_FLAGS = 0x2074
- OFF_RING_LAST_TS = 0x2078
- OFF_RING_LAST_PAYLOAD0 = 0x2080
- OFF_RING_LAST_PAYLOAD1 = 0x2088
- OFF_MAGIC_COOKIE = 0xFFF0
- OFF_HEARTBEAT = 0xFFF8

### 3.2 State Constants

- BEACON_READY = 0x01
- BEACON_PROCESSING = 0x02
- BEACON_COMPLETE = 0x04
- BEACON_SHUTDOWN = 0xFF

### 3.3 Model State Constants

- MODEL_STATE_UNLOADED = 0
- MODEL_STATE_LOADING = 1
- MODEL_STATE_READY = 2
- MODEL_STATE_INFERENCE_ACTIVE = 3
- MODEL_STATE_CANCEL_PENDING = 4

### 3.4 Response Codes

- RESP_OK = 0
- RESP_UNKNOWN_CMD = 1
- RESP_INVALID_PAYLOAD = 2
- RESP_TIMEOUT = 3
- RESP_INTERNAL_ERROR = 4
- RESP_NOT_READY = 5
- RESP_MODEL_NOT_LOADED = 6
- RESP_BUSY = 7
- RESP_CANCELLED = 8

### 3.5 Opcode Table Used by Bridge

- CMD_GET_STATUS = 0x1002
- CMD_SHUTDOWN = 0x1003
- CMD_LOAD_MODEL = 0x2000
- CMD_INFER = 0x3003
- CMD_CANCEL_INFER = 0x3005
- CMD_STREAM_START = 0x4000
- CMD_STREAM_STOP = 0x4001
- CMD_STREAM_STATUS = 0x4004
- CMD_GET_METRICS = 0x7000

## 4. IDE Bridge MMF Contract (New)

MMF name: SOVEREIGN_IDE_BRIDGE_V1
Size: 1048576 bytes (1 MiB)
Endian: little-endian
Concurrency: SPSC for request ring and SPSC for response ring.

### 4.1 Bridge Header (offsets in hex)

- 0x0000 U64 magic = 0x5352565F49444531 ("SRV_IDE1")
- 0x0008 U32 version_major = 1
- 0x000C U32 version_minor = 0
- 0x0010 U32 bridge_state (0 init, 1 ready, 2 degraded, 3 stop)
- 0x0014 U32 feature_bits
- 0x0018 U64 heartbeat_qpc
- 0x0020 U32 request_ring_head
- 0x0024 U32 request_ring_tail
- 0x0028 U32 response_ring_head
- 0x002C U32 response_ring_tail
- 0x0030 U64 dropped_requests
- 0x0038 U64 dropped_responses

#### Cancellation Trapdoor (atomic)

- 0x0040 U64 cancel_epoch (InterlockedExchange/Add on write)
- 0x0048 U64 cancel_target_req_id (0 means "cancel current active")
- 0x0050 U32 cancel_flags (bit0 immediate, bit1 force_stream_stop)
- 0x0054 U32 cancel_ack_epoch

Semantics:
- IDE performs atomic increment of cancel_epoch and writes target/cancel_flags.
- Bridge observes cancel_epoch != cancel_ack_epoch and immediately sends CMD_CANCEL_INFER to Sovereign.
- Bridge then sets cancel_ack_epoch = cancel_epoch after command completion (or terminal error).
- Bridge must prioritize trapdoor over normal dequeue to guarantee preemption.

### 4.2 Request Ring Layout

- Base = 0x1000
- Slot size = 8192 bytes
- Slot count = 64
- Total = 524288 bytes

Request slot fields:
- +0x0000 U64 req_id
- +0x0008 U32 op_code (bridge op, see section 6)
- +0x000C U32 flags
- +0x0010 U32 payload_len
- +0x0014 U32 reserved
- +0x0018 U8 payload[8168]

Payload for OP_COMPLETION:
- UTF-8 prompt bytes, no BOM.

### 4.3 Response Ring Layout

- Base = 0x81000
- Slot size = 4096 bytes
- Slot count = 64
- Total = 262144 bytes

Response slot fields:
- +0x0000 U64 req_id
- +0x0008 U32 status
- +0x000C U32 flags
- +0x0010 U32 payload_len
- +0x0014 U32 model_state
- +0x0018 U64 latency_us
- +0x0020 U8 payload[4064]

## 5. Atomic and Ordering Rules

- Producer writes slot body first, then tail using release semantics.
- Consumer reads head/tail with acquire semantics before slot read.
- Head/tail are monotonically increasing modulo slot_count.
- Full condition: (tail + 1) % N == head.
- Empty condition: head == tail.
- No lock-based cross-lane coupling.

## 6. Bridge Operation Codes (IDE side)

- 0x0001 OP_COMPLETION -> Sovereign CMD_INFER
- 0x0002 OP_CANCEL -> Sovereign CMD_CANCEL_INFER (also reachable through trapdoor)
- 0x0003 OP_STREAM_SET -> Sovereign CMD_STREAM_START/CMD_STREAM_STOP
- 0x0004 OP_STATUS -> Sovereign CMD_GET_STATUS
- 0x0005 OP_METRICS -> Sovereign CMD_GET_METRICS

## 7. Mapping Rules: Bridge -> Sovereign

- OP_COMPLETION:
  - Copy payload into OFF_CMD_PAYLOAD
  - Set OFF_PAYLOAD_LEN
  - Set OFF_CMD_TYPE = CMD_INFER
  - Set OFF_STATE = BEACON_READY
  - Signal SOVEREIGN_CMD_EVENT
  - Wait SOVEREIGN_RESP_EVENT
  - Return response in bridge response ring

- OP_STREAM_SET:
  - If payload byte == 1, send CMD_STREAM_START
  - If payload byte == 0, send CMD_STREAM_STOP
  - Validate with CMD_STREAM_STATUS

- OP_CANCEL and trapdoor:
  - Send CMD_CANCEL_INFER immediately
  - Treat RESP_OK, RESP_CANCELLED, RESP_NOT_READY as terminal cancel outcomes

## 8. Fail-Closed Behavior

- If magic/version mismatch, bridge_state = degraded and reject all non-status ops.
- If Sovereign MMF/event open fails, reject requests with status RESP_INTERNAL_ERROR.
- If command timeout exceeds policy, emit timeout status and continue servicing queue.
- If ring overflow, increment dropped counters and emit explicit overflow response when possible.

## 9. Observability Fields for IDE

Bridge should publish a lightweight snapshot every polling cycle:
- sovereign_model_state
- sovereign_ring_fill
- sovereign_backpressure_delta
- sovereign_dropped_delta
- active_req_id
- last_req_latency_us

Use this to power IDE status bar and diagnostics panel.

## 10. Compatibility and Migration

- v1.0 is additive and does not change SovereignOrchestrator MMF layout.
- Existing scripts (gate, full-cycle, experiment runner) remain valid.
- IDE bridge can be introduced incrementally with no kernel rebuild required.

## 11. Validation Checklist

- Cold start handshake (magic/version/heartbeat) passes.
- Completion request executes with deterministic req_id correlation.
- Trapdoor cancel preempts queue and cancels active inference within timeout budget.
- Streamer toggle path validates via CMD_STREAM_STATUS.
- 3x baseline-first/last drift test shows no material regression.

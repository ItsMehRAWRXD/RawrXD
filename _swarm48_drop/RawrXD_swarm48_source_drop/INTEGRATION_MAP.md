# RawrXD Swarm48 integration map

This drop fills the gap between the already-present RawrXD swarm/multi-GPU infrastructure and a 40–50 logical-agent runtime without duplicating model weights per agent.

## Evidence from the supplied repo audit

The supplied audit shows existing `src/core/swarm_scheduler.cpp`, `src/core/inference_witness.cpp`, `src/core/gguf_swarm_plan_builder.cpp`, runtime placement/memory managers, `certification/CertificationHarness.cpp`, and `src/deep2/Deep2Engine.cpp`. It also shows that a guessed standalone `src/deep2/KVCache.cpp` was absent, so this drop does **not** pretend that such a Deep2 file/API exists. Instead it provides an adapter boundary and a swarm-owned paged-KV allocation policy.

## Additions

1. `SharedModelRegistry` — one immutable resident model image per `(device, model_path)`, shared by many AgentSessions.
2. `PagedKVPool` — lazy page accounting per agent, rather than preallocating full context for every idle worker.
3. `DeviceLeaseManager` — hard per-device active decode-slot caps and device health gate.
4. `ContinuousBatcher` — groups runnable agents by `(device, resident model)` and picks fair priority batches.
5. `AgentSession` — per-agent mutable state only: KV handle, tokens, tool/wait state, priority, role.
6. `SwarmRuntime` — bounded 48-agent lifecycle and batched decode dispatch.
7. `TeamCoordinator` — hierarchical worker/team/synthesizer readiness primitive.
8. `ReceiptLedger` — local JSONL-style execution receipts.
9. `SwarmCommand` — parser contract for `rawr r9700 model task`, `rawr 7800xt ...`, etc.
10. `Deep2BridgeContract` — explicit integration seam into existing Deep2; no duplicate GGUF/Vulkan/tokenizer implementation.

## Recommended RawrXD wiring

- Existing `gguf_swarm_plan_builder.cpp`: produce AgentSpec/team plans, not new model processes.
- Existing `swarm_scheduler.cpp`: either delegate its model/device batch selection to `ContinuousBatcher`, or copy the selection policy into the existing scheduler. Do not run two authorities in parallel.
- Existing `swarm_worker.cpp`: hold an AgentId/SessionId and submit through `SwarmRuntime`; do not own a full model instance.
- Existing `multi_gpu_manager.cpp` / `TensorExecutionRouter.cpp`: map DeviceId 0/1 and feed health/VRAM data into `DeviceLeaseManager`.
- Existing `ResidencyTracker` / Deep2 residency path: implement `IInferenceAdapter::load_shared` as an acquire/reference operation over the real resident model object.
- Existing Deep2 continuous decode path: implement `decode_batch` using the real batched decode entrypoint. One call should receive all same-model runnable sessions selected for that tick.
- Existing Tool Authority: when an agent needs a tool, call `set_waiting_tool(id)`, execute through the one authoritative tool registry, then append tool results to that session and call `set_runnable(id)`.

## R9700 / 7800 XT starting policy

Treat the counts below as logical concurrency defaults, not proof of VRAM fit for any specific model/context:

- R9700: up to 32 registered logical agents, 16 active decode slots.
- RX 7800 XT: up to 16 registered logical agents, 8 active decode slots.
- Global registered-agent cap: 48.

The active slot counts should be tuned by your existing performance/residency telemetry. Logical agents that are waiting on tools or dependencies consume session/KV metadata but no decode slot.

## Deep2 adapter skeleton

```cpp
class RawrXDDeep2SwarmAdapter final : public rawrxd::swarm48::IInferenceAdapter {
public:
    ResidentModel load_shared(const ModelLoadRequest& r) override {
        // Acquire from the EXISTING RawrXD ModelRegistry/Deep2 residency authority.
        // Return the same resident handle for later sessions targeting this (device, model).
    }

    std::vector<DecodeResult> decode_batch(
        const ResidentModel& m, std::span<const DecodeSequence> q) override {
        // Translate q into the EXISTING Deep2 continuous-batch request format.
        // q[i].kv is the agent-owned paged KV identity; do not reload m.
    }
};
```

## Important ownership rule

This source drop must not become another scheduler/model registry alongside existing RawrXD authorities. The classes are deliberately small so they can be merged into/used by the existing `swarm_scheduler`, `swarm_worker`, residency, and Deep2 paths. The missing behavior is the shared-weight/session/lease contract, not another inference engine.

## Decode semantics

The adapter receives `prefill=true` with the complete initial token span only on the first step. Later decode steps receive one token plus its absolute position and reuse the agent KV handle. This avoids accidentally rerunning the full prompt every token.

## Device failure behavior

`set_device_health(device,false)` immediately prevents new decode leases on that GPU. This is intended for cases such as a Windows/Vulkan device failure: single-GPU work on the healthy device can continue while dual-device plans fail closed at the higher policy layer.

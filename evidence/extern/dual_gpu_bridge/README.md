# Deep2 native dual-GPU bridge — source integration slice

This is a **real C++17 planner and orchestration implementation**, not a complete Vulkan transfer implementation. It intentionally fails to construct without all four native engine callbacks. No Vulkan buffers, device contexts, weight loading, or numerical correctness are fabricated.

## Integration contract

- `run_layers(device, begin, end)` must execute actual Deep2 graph operations for a contiguous layer range on the specified Vulkan device; own the residual activation and model-specific per-layer state.
- `synchronize(device)` must wait for completion of the specific device's queued work and propagate failures.
- `transfer_hidden(src, dst, boundary_layer)` must stage the current hidden-state tensor through **host-visible transfer buffers**, use valid Vulkan memory barriers, map/invalidate/flush non-coherent memory where required, and complete the destination upload before returning. The boundary layer identifies the tensor shape and ownership. It must not silently succeed without copying bytes.
- `activate_state_owner(device, first_layer)` must bind the correct device-local KV/MLA/SSM state for the following layers. Each mutable state must have a single owner.

## What remains before it can run a model

1. Wire existing native Vulkan contexts to callback implementations (requires actual repository types and signatures).
2. Allocate/upload resident weights according to the plan, and account for KV/SSM/scratch/headroom in reserved bytes.
3. Implement real cross-device staged Vulkan transfers and lifetime-safe synchronization.
4. Add embedding and output-head placement and transfers, plus per-token state continuity.
5. Run CPU/single-GPU/dual-GPU independent parity, then endurance and performance benchmarks.

## Build

`c++ -std=c++17 -Wall -Wextra -pedantic -c dual_gpu_bridge.cpp`

The planner assumes two devices and an all-resident layer split; if weights do not fit, it **fails closed**. Streaming and MoE expert-aware placement are separate future features, not implied by this slice.

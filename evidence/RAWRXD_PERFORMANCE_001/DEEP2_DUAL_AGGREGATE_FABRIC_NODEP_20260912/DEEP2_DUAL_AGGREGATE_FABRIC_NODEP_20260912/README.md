# DEEP2_DUAL_AGGREGATE_FABRIC_NODEP_20260912

Purpose: make two discrete GPUs behave like one *software-visible aggregate decode fabric*
without pretending they share VRAM or a coherent memory bus.

Target hardware used for the planner defaults:
- GPU0 effective weight-bandwidth weight: 640 GB/s
- GPU1 effective weight-bandwidth weight: 624 GB/s
- Aggregate roofline reference: 1.264 TB/s

The only way that sum becomes useful is when BOTH GPUs read LOCAL weight shards at the
same time. Per-token movement of model weights between GPUs is forbidden.

No external dependencies:
- Win32 API only for threads/events/timing.
- No Vulkan headers in this drop.
- The real runtime binds its existing GPU backend through function pointers.
- The included smoke backend is CPU/mock and exists only to verify concurrency/invariants.

Core invariant:
    aggregate_effective_bw ~= bw0_local + bw1_local - reduction/broadcast/idle penalties

Not:
    GPU0 reads weight -> copies to GPU1 -> GPU1 computes
Not:
    GPU0 completes full layer -> GPU1 runs next full layer
Not:
    unified virtual address == unified bandwidth

Preferred partition:
1. Row/output-channel tensor parallel for GEMV/GEMM projections.
2. Expert ownership for MoE layers.
3. Local LM-head vocabulary slices.
4. Replicate the small input activation to both GPUs.
5. Concatenate or reduce only the small output activation.

Top-15 closure map is in LAW.txt.

Build smoke:
    build_msvc.bat

Run:
    deep2_dual_fabric_smoke.exe

Expected:
    DUAL_FABRIC_SMOKE=PASS
    BOTH_LANES_WORKED=1
    SERIAL_GPU_CHAIN=0
    WEIGHT_MIGRATION_PER_TOKEN=0

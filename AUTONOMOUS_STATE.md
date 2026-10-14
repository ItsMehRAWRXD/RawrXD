# AUTONOMOUS_STATE.md â€” checkpoint (2026-10-14)

Baseline HEAD: 4213f56908 (+ device-aware engine changes in src/: quant_dot_dispatch, runtime_graph_executor, vulkan_compute [+ per-device budgets + in-flight pinning], include/vulkan_compute.h).
Evidence root: evidence/gate5_head_repro_2026-10-14/PARITY_RECEIPTS.txt (master ledger Â§A..Â§P11).
All gate tools rebuild clean; single-GPU bit-identical to original frozen baseline (4,128,000 elems).

## Certified this session (evidence-gated)
G01 freeze baseline; G02/TODO-04 explicit cross-device transfer receipt; G03 independent per-device budgets;
G04 concurrent-safe residency (batch-scoped in-flight pinning; fence-safe eviction; bit-identical under
concurrent both-GPU eviction [1700] and batched heavy eviction [6045]).
Phase1 MoE TODO 01/02/03/05 PASS (DeepSeek-V2-Lite dense+MoE single/split/full-secondary bit-identical;
per-device eviction+stale-guard; device-aware prefetch 1109 on dev4). TODO 06 BLOCKED.

## RESUME HERE â€” next actionable
G05 (native Q2_K/Q3_K GPU kernels). Exact specs captured in Â§P10. Path: add kinds 5/6 in
 quant_dot_dispatch.cpp RowBytesForKind (Q2_K=84,Q3_K=110) + QuantKindOf; extend executor GPU branch
 (currently Q4_K/Q6_K only, ~line 753) + CPU reference KQuantRowDotQ8 for kinds 5/6; write GLSL dequant
 for kinds 5/6 in tools/shaders/quant_dot.comp (exact ggml formulas in Â§P10) + glslc recompile -> .spv;
 VALIDATE via llama.cpp parity on llama3.2-3b-Q2_K / -Q3_K_S (bounded cos ~0.99, cpu_calls=0). If parity
 fails, keep correct fail-closed CPU dequant (Â§ keep) and record G05 OPEN â€” never ship an unverified kernel.
Then: G06/G08 cross-arch + full parity (fix nemotron_h SSM divergence Â§D: cos 0.53 CPU / -0.18 GPU) â†’
G07 (671B, BLOCKED no model) â†’ G11/G12 (paged KV on RX 7800 XT + 4Kâ†’1M ladder) â†’ G15 (150 TPS, BLOCKED
~4.5 TPS) â†’ G16..G20 (IDE blocked by Qt v142/v143 ABI; agents/swarm/endurance/release).

## Blockers (record, never fake PASS)
G07 no 671B GGUF; G15 ~33x perf gap; G16/G18 Qt ABI; nemotron_h SSM parity broken; deepseek2 long-run unstable.

## Extracted source drops (assemble before wiring)
evidence/extern/{dual_gpu_bridge, modelpluscontext, hotpatch, hardware_pressure, nanoquant}.

## Rules honored
No PASS without nonempty full-logit parity + real GPU work + recorded exit/threshold + persisted receipt.
G05 PASS: four independent quant defects fixed. (1) block_q2_K/block_q3_K/block_q5_K field order in
QuantKernelRegistry.hpp did not match ggml-common.h — q2_K/q3_K/q5_K put the fp16 super-scales at
the END of the block, but Deep2 had them first, so every K-quant tensor read the scale bytes as a
float pair. (2) vec_dot_q2_K_q8_K_single applied one scale byte to all 32 elements of a group instead of
two (16+16). (3) its min term was paired with bsums[2n + j/2] instead of all 16 nibbles paired 1:1 with
bsums[0..15]. (4) vec_dot_q3_K_q8_K_single advanced q8 by 128 per super-block instead of 32 per group and
read hmask[32*n + l] past the 32-byte hmask. Also fixed a Q5_K stack buffer overrun. Parity criterion is
order-independent (Deep2 must be at least as accurate as ggml's own float32 accumulation, measured against
a double oracle), so a mathematical error cannot pass. Evidence in
evidence/gate5_head_repro_2026-10-14/g05_quant_parity/. Test: src/deep2/test_q2k_q3k_parity.cpp.

Next action: G06/G08 architecture parity (DeepSeek MLA, MoE, Nemotron SSM, token-by-token logits) using
llama.cpp as the independent reference. Blockers: nemotron_h SSM/hybrid parity broken, deepseek2
long-sustained GPU runs unstable, G07 has no real DeepSeek-671B GGUF.
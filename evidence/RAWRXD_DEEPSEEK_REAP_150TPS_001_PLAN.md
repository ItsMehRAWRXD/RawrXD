# RAWRXD_DEEPSEEK_REAP_150TPS_001

Status: EXPERIMENTAL / NOT CERTIFIED

## Objective
Benchmark REAP-derived DeepSeek-R1 671B variants on the R9700 32GB + RX 7800 XT 16GB. Goal: 150 single-stream decode tokens/s with measured reasoning-quality retention. Never equate total pruned parameter count with active parameters.

## Non-negotiable safeguards
- Original GGUF shards are read-only; no in-place rewrite.
- Preserve baseline branch and evidence; write new output under a separate destination.
- No Qt or new runtime dependencies; use in-repository C++20, Vulkan, Win32.
- Reject unsupported expert geometry, router maps, quantization, and checksum mismatches.
- Do not replace absent experts with arbitrary survivors.
- A router remap must be paired with real checkpoint repacking and shape validation.
- Never report a synthetic kernel rate as end-to-end TPS.

## Gates
G0: Snapshot repository state, hashes of 11 DeepSeek shards, GPU/driver inventory, existing decode receipts.
G1: Inspect Deep2 MoERouter, MoEWeightsLoader, GGUFLoader, and Vulkan execution; record exact interception callsites.
G2: Capture per-layer expert usage on representative prompts, with router scores and reference logits. No mutation.
G3: Implement REAP scoring and offline selection; keep shared/dense weights; validate per-layer expert counts.
G4: Repack to a new GGUF with updated expert tensors, metadata and routing indices. Reject incomplete mappings.
G5: Add runtime fail-closed intercept, mapping, residency and error counters. Preserve unpruned path.
G6: Compare deterministic token sequences and perplexity/task accuracy to unpruned reference.
G7: Sweep quantization, expert-retention and active-expert-count changes separately. Recalibrate routing if active counts change.
G8: Profile actual single-stream decode 128/256/512 tokens, first-token latency, GPU waits, PCIe traffic and peak memory.
G9: Soak, rollback, and publish full receipts with quality-vs-TPS Pareto frontier.

## Performance reality check
37B active parameters at 2 bits imply at least ~9.25GB of weights per token before overhead; 150 TPS would imply ~1.39TB/s without reuse. Expert inventory pruning alone does not change active path. A smaller active path, measured cache reuse, or successful speculative decoding is required to approach the target.

## Certification
PASS only if end-to-end single-stream measured >=150 decoded tokens/sec, output verified, no unexpected CPU fallbacks, memory within device limits, and explicitly declared quality threshold met.

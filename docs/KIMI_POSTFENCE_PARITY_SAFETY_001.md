# Kimi post-fence parity diagnostic safety — isolated incremental patch

**Canonical base:** `fix/deep2-multimodel-safety-20261025` at `499001b2af2c57cf2d0a14f633f97664571e41c9`.

This patch preserves the canonical fused GPU execution, scalar-input capture, aggregate post-fence analysis, and native build targets. It does not copy the divergent older `K2NativeMoEFfn_ExpertGpu.cpp` from draft PR #62 over the canonical file.

## Fail-closed changes

- Every expert must have CPU-accessible gate/up/down input slices for aggregate CPU/GPU diagnostic comparison. A pinned expert with unavailable host slices now causes `status=BLOCKED reason=CPU_EXPERT_INPUT_UNAVAILABLE` instead of silently comparing an incomplete CPU sum.
- Aggregate comparison reports `scope=DIAGNOSTIC_ONLY` and `status=DIAGNOSTIC` (or `NONFINITE`), never `status=OK` as if it were certified numerical parity.
- GPU scratch arena reads remain *after* fused/device completion. Multi-expert scratch attribution is blocked with `MULTI_EXPERT_SCRATCH_IDENTITY_UNPROVEN`. In a single-expert worklist the stage diagnostic remains available but explicitly says `DIAGNOSTIC_UNPROVEN_BUFFER_IDENTITY`, because a fence does not independently prove that EndDevice preserved ArenaDown/ArenaFFNAct values.
- Failed stage downloads now report zero finite elements rather than a misleading complete finite vector.

## Verification contract

Run `python tools/test_k2_postfence_parity_safety.py` or run the existing Windows offline suite in a new private evidence directory. These are source-regression checks, **not** executed GPU numeric parity or buffer-lifetime proof. Native MSVC and Vulkan regression results have not been executed or inspected for this new branch.

### Next required implementation

Implement a dedicated per-expert retained GPU output/activation snapshot with explicit command-buffer ownership and immutable expert/layer/stick metadata; submit and fence that snapshot before D2H; independently audit SHA-256 of the captured vector and inputs; compare complete post-SwiGLU and down-GEMV outputs against the scalar oracle. The current single-expert scratch download remains provisional and cannot certify G05/G06.

```ini
CANONICAL_BASE=499001b2af2c57cf2d0a14f633f97664571e41c9
NEW_BRANCH=cert/kimi-postfence-parity-safety-20261027
SOURCE_FIX=WIRED
OFFLINE_TEST=NOT_VERIFIED_THIS_BRANCH
GPU_EXPERT_BUFFER_IDENTITY=UNPROVEN
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
```

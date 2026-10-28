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

## Increment 2: paired completed aggregate vectors

Added `k2_parity_capture::CaptureAggregateComparison`, used only after
`K2MoEStickEndDevice` returns and the aggregate diagnostic has evaluated
**all** required CPU reference experts. It writes paired complete vectors
into a pre-existing private directory under
`DEEP2_MOE_PARITY_CAPTURE_DIR`:

- `k2_l<L>_s<S>_aggregate_comparison.gpu.txt`
- `k2_l<L>_s<S>_aggregate_comparison.cpu.txt`
- `k2_l<L>_s<S>_aggregate_comparison.manifest.txt`

The manifest records layer, stick, vector size, ordered routed expert IDs
and weights, provenance `POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE`,
`scope=AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY`, and `certified=0`.
Malformed input, nonfinite vectors or routing coefficients, duplicate
expert identities, incorrect dimensions, existing filenames, and missing
directories fail closed. Exclusive-create file writes preserve existing
evidence. On partial failure, only newly written files are cleaned up.

Enable `DEEP2_MOE_GPU_PARITY=1`, raise
`DEEP2_MOE_GPU_PARITY_LIMIT` to cover the entire worklist, and set a
new private capture directory before the native Kimi run. Pair outputs
are diagnostic evidence suitable for a later aggregate full-vector
numerical comparator, **not** a GPU expert activation/down witness.
The GPU scratch buffer identity limitation remains. In particular,
G05 and G06 cannot be promoted from this output.

Added standalone C++ capture smoke cases and a source regression check.
No new MSVC/Vulkan execution evidence has been collected for this PR.

```ini
POST_DEVICE_AGGREGATE_PAIR_CAPTURE=SOURCE_ADDED
REAL_MODEL_AGGREGATE_VECTOR_RECEIPT=NOT_RUN
PER_EXPERT_BUFFER_IDENTITY=UNPROVEN
G05_G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

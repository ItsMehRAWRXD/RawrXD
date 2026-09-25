# Token Beacon Ferris Wheel — Empirical Measurement Workflow

## Overview
This guide provides the repeatable, contamination-proof workflow for measuring the ABAB token ownership machine using per-token beacons and two AMD GPUs (R9700 + RX 7800 XT). All values must trace to measured receipts with full provenance.

## Experiment Classification (Five Orthogonal Core Scaling Axes)

This experiment belongs to **Axis 2 — IMPLEMENTATION_SCALING** (one of five orthogonal core scaling axes):
- Same exact model: Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
- Same exact model bytes: 19,851,336,672 (SIZE_X = 1, α undefined for model scaling)
- Different engine/config: TOKEN_BEACON_FERRIS ABAB ownership policy
- **NOT** a sixth scaling axis. See DEEP2_EMPIRICAL_SCALING_AUTHORITY_002 framework.
- **NOT** model scaling (Axis 1) — SIZE_X = 1, α is undefined; model scaling requires SIZE_X != 1
- **NOT** concurrency scaling (Axis 3) — genuine simultaneous requests require AGENT_COUNT=1,2,3 with wall aggregate TPS
- **NOT** residency scaling (Axis 4) — physical working set vs effective bytes is separate axis

The five orthogonal core scaling axes (from DEEP2_EMPIRICAL_SCALING_AUTHORITY_002):
  AXIS_1 = MODEL_SCALING        — distinct exact model-size scaling (α when SIZE_X != 1)
  AXIS_2 = IMPLEMENTATION_SCALING — same model, different engine/config (this experiment)
  AXIS_3 = CONCURRENCY_SCALING  — genuine simultaneous-stream scaling (AGENT_COUNT=1,2,3...)
  AXIS_4 = RESIDENCY_SCALING    — physical/effective working-set scaling
  AXIS_5 = SWARM_HEX_MAG_SCALING — orchestration rather than simultaneous inference

Token Beacon Ferris classification:
  PRIMARY: IMPLEMENTATION_SCALING (Axis 2)
  SECONDARY AUTHORITY: PLACEMENT_AUTHORITY, LATENCY_TAIL, RESOURCE_EFFICIENCY
  NOT a sixth axis. Hex Mag = orchestration scaling (Axis 5)
  Token Beacon Ferris = execution/placement implementation (Axis 2)
  Concurrency = simultaneous-stream scaling (Axis 3)
  Residency = physical/effective working-set scaling (Axis 4)
  Model scaling = distinct exact model-size scaling (Axis 1)

**Primary authority**: Tokens per second (TPS) under ABAB beacon policy
**Secondary authorities**: BEACON_OVERHEAD_RATIO, PREPARATION_HIDDEN_RATIO, active/standby GPU utilization

## Authority Workflow (8-Step, adapted from empirical dataset)

### Step 1: IDENTIFY
```
exact model: Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf
exact SHA-256: 8e2fd78ff55e7cdf577fda257bac2776feb7d73d922613caf35468073807e815
exact model bytes: 19851336672 (measured file length, NOT nominal "32B")
quant: Q4_K_M
shard count: 1 (replicated model on both GPUs)
two AMD GPUs: R9700 (32GB VRAM) + 7800 XT (16GB VRAM)
separate Vulkan device groups (no direct peer memory)
```

### Step 2: FREEZE TEST CONDITIONS
```
prompt hash: <fill per run>
context: <fill per run>
num_predict: 256
warmup: 32 tokens
GPU configuration: R9700 + 7800 XT, separate device groups, no peer memory
host configuration: <fill per run>
agent count: 1 (single-stream with TOKEN_BEACON_FERRIS policy)
execution policy: TOKEN_BEACON_FERRIS
token ownership: ABAB (A B A B A B alternating)
```

### Step 3: COLLECT RAW VALUES
Measure and record all fields listed in `receipt_token_beacon_ferris_001.txt`:
- TOKEN_OWNER[0..N] — which GPU computes each token
- TOKEN_COMPUTE_NS — time from beacon receive to token completion
- BEACON_CONTROL_NS — beacon transmission + synchronization time
- KV_DELTA_BYTES — should be ~256 KiB per token (2 × 64 × 8 × 128 × 2)
- KV_TRANSFER_NS — DMA transfer time for per-token KV delta
- FENCE_WAIT_NS — time waiting on synchronization fence
- NEXT_GPU_PREP_NS — time idle GPU spends preparing next revolution
- QUEUE_IDLE_NS — queue idle time between tokens
- INTER_TOKEN_NS — total time between consecutive token starts
- P50_TOKEN_NS, P95_TOKEN_NS, P99_TOKEN_NS — latency percentiles
- GPU0_BUSY, GPU1_BUSY — fraction of time each GPU is computing
- GPU0_PREFETCH_OVERLAP_NS, GPU1_PREFETCH_OVERLAP_NS — standby prep hidden by active compute
- TPS — tokens per second (primary authority)
- ACTIVE_GPU_COMPUTE_NS — pure compute time per token
- OTHER_GPU_PREP_NS — standby GPU preparation time

### Step 4: DERIVE
```
decode TPS per token = eval_count × 1e9 / eval_duration_ns
Aggregate TPS across all tokens in the sweep
```

### Step 5: CLASSIFY THE EXPERIMENT
```
Axis: IMPLEMENTATION_SCALING (Axis 2)
Same model, different engine/config: TOKEN_BEACON_FERRIS ABAB policy
NOT model scaling (SIZE_X = 1, α undefined)
NOT concurrency scaling (not genuine simultaneous requests)
NOT residency scaling (separate axis)
Primary authority: TPS under beacon policy
Secondary: BEACON_OVERHEAD_RATIO, PREPARATION_HIDDEN_RATIO
```

### Step 6: REJECT CONTAMINATION
**Never do these things:**
1. approximate model bytes → FAIL CLOSED (use exact 19851336672, NOT nominal "32B")
2. SIZE_X == 1 → no model-size α (this is implementation scaling only, not model scaling)
3. reported TPS without raw timing → non-authoritative (must use eval_count × 1e9 / eval_duration_ns)
4. different agent count → not implementation-only comparison (this is single-stream beacon policy)
5. different engine policy → not pure beacon policy comparison (keep prompt, quant, warmup identical)
6. single best run over median → always compare medians across ≥5 runs

### Step 7: REPEAT
```
≥5 runs with identical frozen conditions
retain all raw runs
compare medians, not best single run
flag any outliers per statistical norms
```

### Step 8: PROMOTE
```
only after provenance and classification checks pass
update empirical_tps_dataset.txt with new receipt
compute derived quantities:
  BEACON_OVERHEAD_RATIO = beacon_and_sync_time / total_decode_time
  PREPARATION_HIDDEN_RATIO = standby_preparation_hidden_by_active_compute / total_standby_preparation
  WEIGHTED_TOKEN_TPS = measured TPS with beacon policy
  R9700_ONLY_TPS = baseline solitary R9700 TPS (from DEEP2_32B_BASELINE_AUTHORITY_001)
promote only if: ABAB_TOKEN_TPS > R9700_ONLY_TPS without degrading output correctness, p95/p99 latency, stability
```

## Measurement Priority & Integration

### Phase Context
This experiment sits in the **practical order** after:

```
A. Nemotron 30B concurrent agent sweep (establish real scheduler/concurrency curve)
B. Cross-model single-stream sweep (compute model-size α exponent)
C. Effective-traffic instrumentation (EFFECTIVE_BYTES_TOTAL, EFFECTIVE_BYTES_PER_TOKEN)
D. Residency sweep (physical footprint vs exact model bytes)
E. Only then fit: alpha = model-size TPS exponent, beta = token-cost exponent
```

The token beacon ferris wheel is a **Phase D-adjacent** experiment — it's primarily Implementation Scaling (Axis 2) with PLACEMENT_AUTHORITY concerns, not Model Scaling (Axis 1) since SIZE_X = 1.

### Integration with DEEP2_MULTI_MODEL_AUTHORITY_SWEEP_001
- **Model scaling**: Not applicable (SIZE_X = 1, same model on both GPUs)
- **Implementation scaling**: This is the primary axis — beacon policy as engine/config variation
- **Concurrency scaling**: Not applicable (single-stream ABAB, not AGENT_COUNT=1,2,3 simultaneous requests)
- **Residency scaling**: Secondary — measure VRAM usage while beacon policy alternates ownership

**Expected output files** (from Measure-Deep2Concurrency.ps1 or equivalent):
- raw_runs.csv — all raw per-token measurements
- summary.csv — median, P50/P95/P99, means
- case_runs.csv — per-run classification and conditions
- metric_samples.csv — sampled values across runs
- DEEP2_CONCURRENCY_SCALE_001.txt — summary with derived quantities

### Comparison Baselines (Frozen from Empirical Dataset)
```
BASELINE_R9700_ONLY     → DEEP2_32B_BASELINE_AUTHORITY_001  (solitary R9700, ~47 TPS expected)
BASELINE_7800XT_ONLY    → DEEP2_32B_BASELINE_AUTHORITY_001  (solitary 7800XT, ~24 TPS expected due to 16GB limit)
BASELINE_DUAL_SPLIT     → DEEP2_32B_BASELINE_AUTHORITY_001  (ordinary dual-GPU layer split)
NEW_EXPERIMENT          → DEEP2_TOKEN_BEACON_FERRIS_001      (ABAB beacon policy, primary comparison)
```

**Primary success condition**:
```
ABAB_TOKEN_TPS > R9700_ONLY_TPS
without degrading: output correctness, p95/p99 latency, stability
```

**Revealing test** (compares hidden work vs compute flip-flop):
```
ACTIVE_GPU_COMPUTE + OTHER_GPU_PREP  vs  ACTIVE_GPU_COMPUTE + SAME_GPU_PREP
```

If standby hardware eliminates enough queue/cache/preparation dead time, beaconism is working.

### Derived Quantities (computed after runs complete)

```
BEACON_OVERHEAD_RATIO = beacon_and_sync_time / total_decode_time
  — Measures beacon+fence overhead as fraction of total time
  — Lower is better; ideally < 10-15%

PREPARATION_HIDDEN_RATIO = standby_preparation_hidden_by_active_compute / total_standby_preparation
  — Measures how much the standby GPU's preparation is hidden by active compute
  — Higher is better; if > 50%, the ferris wheel converts idle time into useful work

WEIGHTED_TOKEN_TPS = measured TPS with beacon policy
  — Primary authority; compare against R9700_ONLY_TPS

R9700_ONLY_TPS = baseline solitary R9700 TPS
  — From DEEP2_32B_BASELINE_AUTHORITY_001 (exact value from measured receipt)

SUCCESS_CONDITION = ABAB_TOKEN_TPS > R9700_ONLY_TPS
  without degrading: output correctness, p95/p99 latency, stability

FAILURE_INSIGHT = tells you to move from COMPUTE FLIP-FLOP →
  CONTROL FLIP-FLOP + CACHE/PREFETCH FLIP-FLOP + WEIGHTED COMPUTE OWNERSHIP
```

### MoE Version (Future Work)
For MoE models, the beacon can include router information:
- TOKEN_ID, POSITION, KV_EPOCH
- TOP_EXPERT_0, TOP_EXPERT_1, TOP_EXPERT_2, TOP_EXPERT_3
- EXPERT_CACHE_GENERATION

Then the device receiving the next turn knows what happened and can update its expert predictor/cache.

**Test configuration**:
```
token N router decision
    ↓
predict token N+1 hot expert set
    ↓
standby GPU stages experts
    ↓
token beacon
    ↓
ownership flip
    ↓
next GPU starts from hot state
```

This is substantially more novel than simple round-robin inference.

### Asymmetric GPU Adjustment (Weighted Token Ferris)
Your GPUs are asymmetric: R9700 (32GB) + 7800 XT (16GB).

The generalized beacon wheel should support weighted ownership:
```
A A B
A A B
```
or dynamically:
```
A A B A A A B A ...
```

based on measured service time.

**Controller learns**:
```
R9700 median token service = X
7800XT median token service = Y
```
and adjusts slot ownership accordingly.

**Call it**: WEIGHTED_TOKEN_FERRIS

"Every other" becomes the first falsifiable configuration, not an architectural restriction.

### Contamination Prevention Checklist (Specific to This Experiment)

**Never** do these contamination-invalidating things:

1. ✗ Use nominal model size "32B" instead of exact 19,851,336,672 measured bytes
2. ✗ Compute model-size α when SIZE_X = 1 (this is implementation scaling, Axis 2)
3. ✗ Use Ollama-reported TPS instead of eval_count × 1e9 / eval_duration_ns
4. ✗ Compare 1-agent vs 2-agent as "model scaling" — they're different axes (concurrency vs beacon)
5. ✗ Compare different engine policies (different quant, warmup, prompt) as model-size evidence
6. ✗ Use single best run over median across ≥5 runs
7. ✗ Abandon the literal ABAB ABAB ABAB first configuration — it produces clean evidence
8. ✗ Assume direct GPU peer memory between R9700 and 7800 XT (they're in separate device groups)
9. ✗ Abandon the experiment if naïve ABAB is slower — use insights to move to WEIGHTED_TOKEN_FERRIS
10. ✗ Skip the fence/synchronization measurement — BEACON_CONTROL_NS is primary authority

## Success Criteria & Interpretation

### Success Condition
```
ABAB_TOKEN_TPS > R9700_ONLY_TPS
without degrading: output correctness, p95/p99 latency, stability
```

If met: beaconism converts ownership flip into genuine TPS gain.

### Mixed Results (Expected First Result)
```
R9700_ONLY = 47 TPS
ABAB =
  27 TPS R9700-equivalent turn
  + 18 TPS 7800-equivalent turn
  + handoff penalty
```

**Interpretation**: Naïve 1:1 alternating ownership is worse. Move to:

```
CONTROL FLIP-FLOP + CACHE/PREFETCH FLIP-FLOP + WEIGHTED COMPUTE OWNERSHIP
```

### Failure is Useful Too
If ABAB underperforms, the derived quantities tell you the path forward:

```
BEACON_OVERHEAD_RATIO too high → optimize beacon/fence mechanism
PREPARATION_HIDDEN_RATIO too low → increase standby GPU pre-stage work
KV_DELTA_BYTES inconsistent → verify 256 KiB per-token delta (2 × 64 × 8 × 128 × 2 FP16)
QUEUE_IDLE_NS too high → increase preparation overlap with active compute
```

The most important number is **PREPARATION_HIDDEN_RATIO** — if the standby hardware eliminates enough queue/cache/preparation dead time, the ferris-wheel mechanism is doing genuine work.

## Quick Reference: Experiment Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Gate | DEEP2_TOKEN_BEACON_FERRIS_001 | ABAB token ownership machine |
| Model | Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf | 19,851,336,672 bytes, Q4_K_M |
| GPUs | R9700 (32GB) + 7800 XT (16GB) | Separate Vulkan device groups |
| Execution policy | TOKEN_BEACON_FERRIS | ABAB ABAB alternating ownership |
| KV delta per token | ~256 KiB | 2 × 64 layers × 8 KV heads × 128 head_dim × 2 bytes FP16 |
| Token ownership | ABAB | A B A B A B ... alternating |
| Synchronization | Per-token beacon + fence | Tiny control plane (< 32 bytes) |
| Minimum runs | 5 | Compare medians, not best single run |
| Primary authority | TPS (tokens/second) | Compare against R9700_ONLY_TPS |
| Derived quantities | BEACON_OVERHEAD_RATIO, PREPARATION_HIDDEN_RATIO | Key decision criteria |
| Contamination guard | SIZE_X = 1 → no α; exact model bytes only | Implementation scaling, Axis 2 |
| Success condition | ABAB_TOKEN_TPS > R9700_ONLY_TPS without degradation | Primary promotion criterion |

## Next Steps (When GPU/Endpoint Resources Available)

1. **Phase A complete**: Nemotron 30B concurrent agent sweep (establish scheduler curve)
2. **Phase B complete**: Cross-model single-stream sweep (compute α exponent)
3. **Phase C complete**: Effective-traffic instrumentation
4. **Phase D complete**: Residency sweep (physical footprint vs model bytes)
5. **Run Token Beacon Ferris**: Execute `receipt_token_beacon_ferris_001.txt` workflow
6. **Classify**: Axis 2 — Implementation Scaling, not model or concurrency scaling
7. **Promote or iterate**: Based on BEACON_OVERHEAD_RATIO and PREPARATION_HIDDEN_RATIO
8. **Update dataset**: Add new receipt to `empirical_tps_dataset.txt` if promoting

The token beacon ferris wheel is now fully integrated into the four-axes framework with contamination prevention, authority workflow, and success criteria all documented. Ready for execution when GPU/endpoint resources become available.
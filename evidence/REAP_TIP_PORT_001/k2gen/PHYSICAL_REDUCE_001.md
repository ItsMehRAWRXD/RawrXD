# REAP physical reduce (stream) — Tip15

## Audit verdict (prior tip)

`--reap A/B` on Tip14 was **residency/router injection only**:

- `injection_mode=STREAMER_HOTPATCH`
- `reason=NON_DESTRUCTIVE_RUNTIME_TARGET`
- `runtime.status=ACTIVE_RUNTIME_ROUTER_RESIDENCY`
- `writer_invoked=false`

That is **not** a physically reduced MoE representation. Full expert topology remained addressable; only working-set / top-k policy changed.

## Target (this tip)

| Mode | Meaning |
| ---- | ------- |
| Full | Original GGUF intact; all experts addressable |
| REAP physical stream | Retained expert set derived from working-set budget; pruned experts excluded from route + acquire |
| Sidecar persist | Optional GGUF rewrite via `transformMoEGGUF` (still gated; source immutable) |

## Implementation

- `src/reap/ReapPhysicalReduce.cpp` — budget → retained cardinality (`P_REAP` style)
- `src/deep2/ReapPhysicalBank.cpp` — process-local allowlist
- `KimiK2Router::Route` — choice logits outside retained → `-inf`
- `MoEWeightProxy::Acquire` — deny pruned expert IDs
- Receipt embeds `physical.{ORIGINAL_*,RETAINED_*,REPACKED_*,...}`

## Selection policy

`BUDGET_UNIFORM_UNCERTIFIED` — experts `[0, retained)` per MoE layer.
Not calibration-ranked. **PROMOTE=0 · CERTIFIED=0**.

## Distinction preserved

| Field | Residency-only | Physical stream |
| ----- | -------------- | --------------- |
| Pruned experts routeable | yes | **no** |
| Pruned experts acquirable | yes (budget permitting) | **no** |
| `REPACKED_MODEL_BYTES` | absent | estimated reduced size |
| Source GGUF | immutable | immutable |

## Smoke (host floor)

| Field | Observed (`physical_t2` / tip rebuild) |
| ----- | -------------------------------------- |
| `injection_mode` | `PHYSICAL_STREAM_EXPERT_REDUCE` |
| `physical_reduce` | true |
| `ORIGINAL_EXPERT_COUNT` | 384 |
| `RETAINED_EXPERT_COUNT` | 149 (budget-derived; ≥ TOP_K=8) |
| `REPACKED_MODEL_BYTES` | ~19.4e9 (near 30GB→WS target) |
| `writer_invoked` | false (source GGUF immutable) |
| `PROMOTE` | 0 |

## Next

1. Calibration-ranked selection + reference parity → unlock sidecar `writer_invoked` persist.
2. Contiguous on-disk repack for export reuse.
3. Independent llama.cpp token parity (separate gate).
4. Scale expert-byte inventory across all 13 shards (not shard-0 only).

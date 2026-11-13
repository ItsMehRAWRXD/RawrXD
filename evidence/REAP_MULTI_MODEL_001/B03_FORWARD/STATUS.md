# B03 MiniMax layer attention + MoE forward

`PROMOTE=0` · `CERTIFIED=0` · semantic stream quality **NOT_PASS**

Controlling smoke: `minimax_b03q.*` · EXE in `EXE_SHA256.txt`

## Observed (same EXE SHA)

| Gate | Result |
|------|--------|
| B03_LAYER_TENSORS_VALID | **62/62** |
| B03_ATTENTION_BIND_VALID | **1** |
| B03_FORWARD_ENTERED | **1** |
| B03_FORWARD_COMPLETED | **1** |
| TOKENS_COMMITTED | **4** |
| GENERATED_TOKENS | **4** |
| MOE_PLACE_CALLS | **1364** |
| EXPERTS_SELECTED | **10912** |
| EXPERTS_EXECUTED | **10560** |
| ACQUIRE_OK | **10560** (receipt also notes bank ACQUIRE_OK=10912) |
| HEAP_OK_AFTER_FORWARD_LAYERS | **1** (multi-token) |
| CURRENT_EXE_REBOUND | **1** |
| STREAM_CORRECTNESS (semantic) | **NOT_PASS** (output `其图-）` for prompt Hello) |
| STREAM_CORRECTNESS (acquire receipt) | PASS on ROUTE/ACQUIRE counters only — ≠ quality cert |
| PHYSICAL REAP success claim | **NOT_CLAIMED** |
| PROMOTE / CERTIFIED | **0 / 0** |

## Fixes that unblocked tokens

1. `ffnOutput` sized `max(ffnDim, hiddenSize)` — MiniMax 1536 &lt; 3072 overrun → HEAP_CORRUPT.
2. `computeExpertFFN` zeros gate/up/out before registry GEMV (`y[r] +=`).
3. Multi-shard `VirtualFree` on unload for mapped tensors.

## Still open

- Semantic / reference divergence (B03-C quality).
- Deterministic repetition witness.
- Physical REAP export (writer_invoked=false).

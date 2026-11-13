# B03 MiniMax layer-0 attention + forward (in progress)

`PROMOTE=0` · `CERTIFIED=0` · `NOT_RUN≠PASS`

## Observed (see `minimax_b03o.*` + `EXE_SHA256.txt`)

| Gate | Result |
|------|--------|
| B03_LAYER_TENSORS_VALID | **62/62** (metadata + fileBacking; on-demand materialize) |
| B03_ATTENTION_BIND_VALID | **1** |
| B03_MULTISHARD_TOPOLOGY | ready=1 blocked=NONE headDim=128 |
| B03_FORWARD_ENTERED | **1** |
| B03_FORWARD_COMPLETED | **1** (62/62 LAYER_EXIT; MoE ROUTE topk=8 each layer) |
| MoE ACQUIRE_OK | **observed** (L0 8/8; mixed Q4_K gate/up + Q6_K down) |
| TOKENS_COMMITTED | **0** (exit HEAP_CORRUPT `0xC0000374` after L61) |
| STREAM_CORRECTNESS | **NOT_PASS** (late norms ~1e28) |
| PHYSICAL REAP success | **NOT_CLAIMED** |
| PROMOTE / CERTIFIED | **0 / 0** |

## Constraints

- Root vs layer materialize headers remain distinct.
- Bind ≠ materialize; consumers materialize before use.
- Soft REAP bank retained=29 masked in `MoERouter::Route`.

## Next

1. Fix HEAP_CORRUPT on teardown / expert cache.
2. First divergent op vs reference.
3. `--max-tokens 4` until TOKENS_COMMITTED>0 on same EXE SHA.

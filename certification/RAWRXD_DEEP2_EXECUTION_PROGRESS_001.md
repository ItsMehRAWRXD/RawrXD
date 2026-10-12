# Deep2 Execution Progress — Real Model Evidence

**Model:** Nemotron-3.5-Lightning-30B Q4_K_M (25.4 GB, `nemotron_h_moe`)
**Harness:** 17/18 gates PASS · `VERDICT=FAIL`

---

## Committed progress (each verified on the real model)

| # | Fix | Before | After |
|---|---|---|---|
| 1 | Mamba2 `ssm_a` broadcast | `ssm: ssm_a too small` | SSM scan executes, block 0 completes |
| 2 | GQA attention geometry | `linear: x=256 n_in=4096` | All attention blocks pass |
| 3 | MoE router `n_exp` from `dims[1]` | `router: dequant short` | Router produces 128 expert scores |
| 4 | MoE expert tensors from `detail` | `moe: missing expert anchor slot` | Expert weights reached |

## Current blocker — captured with exit code and full log

```
EXIT=-1073740940   (0xC0000364, STATUS_HEAP_CORRUPTION)
ELAPSED=132.1s
```

Crash occurs in **stage [4] per-position parity**, inside expert execution.

Log evidence (`nemotron_runtime.log`, 440 lines):

```
total log lines      : 440
buffer allocations   : 189
distinct buffer sizes:
  6193152 bytes x 63
  17472 bytes  x 63
  10752 bytes  x 63
```

**63 = number of MoE blocks in this model.** Each block allocates exactly
three buffers (one large expert weight buffer + two small), totalling ~6.2 MiB
per block. The buffers are re-allocated inside the per-position decode loop
rather than once at model initialization, so the count grows with decode
length until the heap is corrupted.

### What this rules out

The crash is **not** a binding or resolution failure:

- `ops_total=271` `ops_bound=271` `ops_unbound=0`
- `weights_resolved=417`
- All 17 preceding harness gates pass, including graph binding

The MoE anchor is resolved and real expert weights are being accessed. The
failure is in buffer lifetime management during expert execution.

## Not claimed

- Decode does not complete
- No generated text
- No throughput measurement
- No reference parity

The next repair is the expert-execution buffer lifetime: the 6,193,152-byte
per-block buffer must be allocated once and reused, not re-allocated per
decode position.
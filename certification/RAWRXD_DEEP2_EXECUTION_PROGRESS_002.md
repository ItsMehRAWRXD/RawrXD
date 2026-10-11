# Deep2 Execution Progress — Real Model Evidence

**Model:** Nemotron-3.5-Lightning-30B Q4_K_M (25.4 GB, `nemotron_h_moe`)
**Commit:** `e885f47100`
**Harness:** 17/18 gates PASS · `VERDICT=FAIL`

---

## Committed progress

| # | Fix | Failure moved past |
|---|---|---|
| 1 | Mamba2 `ssm_a` broadcast | `ssm: ssm_a too small` |
| 2 | GQA attention geometry | `linear: x=256 n_in=4096` |
| 3 | MoE router `n_exp` from `dims[1]` | `router: dequant short` |
| 4 | MoE expert tensors from `detail` | `moe: missing expert anchor slot` |
| 5 | Selected-expert execution | `0xC0000364` heap corruption |

Each was found by tracing the actual failing operation.

## Fix 5 detail

The MoE path expanded every expert tensor to F32 per token — roughly 7.14 GiB
per MoE block. The tensors are `[in, out, expert]` with 128 experts each, but
only `expert_used` are selected per token, so about 95% were never needed.

Now only selected experts are dequantized, via `DequantRange()` reading just
the blocks an expert slice covers. Peak memory is one expert per tensor.

The expert count was also wrong: it divided a byte total by
`type_size / blck_size`, which is 0 for Q5_0, making the divisor 1 and
reporting ~439 million experts.

## Current blocker

```
0xC0000005  (access violation)
~30 of 53 blocks executed, 90 Vulkan buffers allocated
```

The crash is in the per-position parity stage, inside the GPU path, **before**
`OpMoEExecute` is entered — the `[moe]` trace never fires. It is not in the
expert-execution code, which now runs with bounded memory.

## Verified against the model's tensor directory

Block 52 ships `ffn_up_exps` and `ffn_down_exps` but no `ffn_gate_exps`.
`gate == up` is therefore the architecture, with `ffn_gate_inp` supplying
routing — not a binding defect.

## Repository incident

Pushing the previous fix used an empty source refspec, which **deleted the
remote branch**. It was restored immediately from local HEAD and the commit
re-created with a SHA-validated push. No work was lost: all changes were
still on disk.

## Not claimed

- Decode does not complete
- No generated text
- No throughput measurement
- No reference parity
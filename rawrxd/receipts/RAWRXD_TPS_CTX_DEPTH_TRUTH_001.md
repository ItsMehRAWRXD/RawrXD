# RAWRXD_TPS_CTX_DEPTH_TRUTH_001

Status: FIXED (recorded so the finding survives the harness that found it)
Date: 2026-09-30
Origin: `transformer_tps_bench.cpp:137-157`

## The defect

The decode sweep warmed the KV cache in **fixed 256-token chunks regardless of the
requested depth**. A request for `ctx=16` therefore executed a 256-token `Forward`, and a
request for `ctx=256` executed the same single 256-token chunk. The measured work was
**identical** for ctx 16, 64, and 256.

The printed `ctx` column described the *request*, not the depth the decode actually ran
at. The table therefore appeared to demonstrate that decode cost is context-independent
over that range — which was an artifact of the harness, not a measurement.

## Why it mattered

This is the exact shape of claim that contaminates a whole result set. A reader comparing
ctx 16 vs ctx 256 sees identical throughput and concludes context length does not affect
decode cost. The real relationship was masked until the fill was clamped, after which
throughput dropped monotonically with depth (428 → 93 → 42 tok/s at ctx 16 / 1024 / 4096),
which is the expected `O(context)` attention behavior.

## The fix

```cpp
// clamp the final chunk to the remaining depth, and print the depth actually
// reached alongside the requested one
std::printf("%10s %12s %10s %12s %14s\n",
            "ctx_req", "kv_depth", "ms/token", "tok/s", "mean_logit");
for (uint32_t base : {16u, 64u, 256u, 1024u, 4096u}) {
    for (uint32_t done = 0; done < base; done += kChunk) {
        const uint32_t n = std::min(kChunk, base - done);
        ...
    }
}
```

`ctx_req` and `kv_depth` are now separate columns. `kv_depth` is the count of tokens the
warmup actually pushed through the runtime — measured, not requested.

## Rule this establishes

A sweep parameter and the depth it produces are different quantities. Any harness that
prints a requested value as if it were a measured one creates evidence that looks like a
result. Where the two can diverge, **print both columns**.

Applies beyond this harness: any depth, batch size, or context length that a warmup
rounds up to a block boundary must report the effective value.

## Preservation note

This finding lived only in a source comment inside `transformer_tps_bench.cpp`, a file
with **no CMake target, no receipt, and no references**. A cleanup pass correctly refused
to delete it on the grounds that the finding was not receipt-preserved, which is the right
call. The file remains in the tree for the same reason.

`transformer_tps_bench.cpp` is otherwise superseded: its throughput output carries **no
correctness gate** (no argmax match, no determinism check), which is precisely why
`regime_sweep.cpp` exists. Once this receipt is the canonical record, the file may be
deleted or demoted to a smoke test — but that deletion must cite this receipt, not
supersedence.
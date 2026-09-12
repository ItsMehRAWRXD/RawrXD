# DEEP2_FULL_DECODE_TOKEN_REAL — x64 MASM / no third-party deps

This drop implements only the next correctness step:

```text
real full-forward logits
  -> deterministic greedy token selection
  -> real token commit callback
  -> autoregressive state/KV advance callback
  -> repeat N times
```

It **does not** contain a TPS estimator, benchmark authority, promotion switch, synthetic
logits, model fixture, or fallback token source.

## Authority boundary

The library may set `D2_FLAG_FULL_DECODE_OBSERVED` only after all requested iterations
completed and these independently observed counters are equal:

```text
GENERATED == TARGET_TOKENS
FORWARD_CALLS == TARGET_TOKENS
COMMIT_CALLS == TARGET_TOKENS
ADVANCE_CALLS == TARGET_TOKENS
```

A callback returning failure clears/withholds full-decode authority.

The forward callback is the integration seam. It must be wired to the already-evidenced
product path:

```text
61-block activation
 -> final RMSNorm
 -> real LM head
 -> logits pointer + vocab count
```

Do **not** wire it to block-0, abbreviated-chain, fixture, cached-logit, or host-generated
stand-ins.

## Callback ABI

See `deep2_decode_abi.inc` and `PRODUCT_BINDING_CONTRACT.inc`.

All callbacks use Microsoft x64 ABI and have at most four parameters.

### ForwardFn

```text
ForwardFn(user_ctx, absolute_position, &logits_f32, &vocab_count) -> 1/0
```

Success means the returned logits were actually produced for this decode position.

### CommitFn

```text
CommitFn(user_ctx, token_id, absolute_position, 0) -> 1/0
```

Return `1` only after the product token stream/state accepted the token.

### AdvanceFn

```text
AdvanceFn(user_ctx, token_id, next_position, 0) -> 1/0
```

Return `1` only after autoregressive input/KV state is ready for the next full forward.

## Public API

```text
Deep2DecodeInit(ctx, binding)                    -> bool
Deep2SelectArgmaxF32(logits, count, out_token)  -> bool
Deep2RunFullDecode(ctx, token_count)             -> bool
Deep2DecodeValidateWitness(ctx)                  -> bool
```

`Deep2SelectArgmaxF32` ignores NaNs and keeps the lower token id on exact ties.

## Build

From an x64 VS Developer Command Prompt:

```bat
build_x64_masm.bat
```

Output:

```text
build\deep2_full_decode_token_real.lib
```

No third-party libraries are linked by this source drop.

## Required gate mapping

For a product run, derive the gate from the actual context, not from a receipt template:

```text
DEEP2_FULL_DECODE_TOKEN_REAL=PASS
  iff Deep2RunFullDecode(...) == 1
  and Deep2DecodeValidateWitness(...) == 1

FULL_MODEL_FORWARD=1       # supplied by the already-sealed product path
FINAL_NORM_REAL=1          # supplied by the already-sealed product path
LM_HEAD_REAL=1             # supplied by the already-sealed product path

GENERATED_TOKENS = ctx.generated
FULL_MODEL_DECODE = witness_valid ? 1 : 0

TPS_SCOPE=NOT_MINTED_HERE
FULL_MODEL_TPS_AUTHORITY=0
PROMOTE=0
```

This module intentionally has no path capable of producing `20 TPS`, `30 TPS`,
`TPS_SCOPE=FULL_MODEL_DECODE`, or `PROMOTE=1`.

Only a later timed sustained decode run should create those observations.

## Next performance work after this gate seals

After real multi-token autoregressive decode is sealed, the next source drops should be:

1. GPU-only RoPE/KV/attention.
2. GPU-only MoE router/top-k/dispatch.
3. Grouped top-8 expert execution.
4. Direct Q4 dequant+GEMV consumption.
5. RMSNorm/projection and residual/next-norm fusion.
6. Activation ping-pong with zero-copy block handoff.
7. Persistent 61-block execution metadata.
8. Pump-owned N+1 exact-range readiness.
9. Expert hot-set residency reuse.
10. Decode fast path with certification/readback barriers removed from the timed path.

Only after those should `DEEP2_FULL_DECODE_050MS_001` be attempted.

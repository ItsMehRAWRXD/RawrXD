# Batch 2 live gate — Deep2Engine/SsVk product decode bind

## Upstream authority retained

This gate consumes, and must not re-mint:

```text
PRODUCT_LINKED=1
PACKED_Q2K_LIVE=1
MATERIAL_SAME_TOKEN_OVERLAP=1
AGGREGATE_BW_AUTHORITY=1
WINDOW material_pass=16/16
FINISH_BALANCE=PASS_PARTIAL
PROMOTE=0
```

## What Batch 2 proves

The previously certified packed-dual Q2_K operator is now called **inside the
real Deep2Engine autoregressive decode transaction**, rather than only by the
evidence harness.

For decode step N>0 the branch already performs:

```text
feed previously sampled token
-> embed
-> forwardTokenAllLayers
-> final norm
-> KV advance
-> computeLogits
-> sample next token
-> output token
```

Batch 2 preserves that ordering. It does not move KV advance behind sampling.

## First authority window

Run 16 decode steps after prefill with:

```text
RAWRXD_DEEP2_SSVK_PRODUCT_STRICT=1
RAWRXD_DEEP2_GPU_RESIDENT_STRICT=1
```

For all 16 N>0 tokens require:

```text
Q2K_OPS_SEEN > 0
Q2K_OPS_PRODUCT == Q2K_OPS_SEEN
ALL_Q2K_OPS_AUTHORITATIVE=1

FULL_MODEL_FORWARD=1
FINAL_NORM_REAL=1
LM_HEAD_REAL=1
SAMPLER_COMMIT_REAL=1
KV_ADVANCE_REAL=1

SEALED_LOGITS_REUSE=0
HOST_FORWARD_LAYER_CALLS=0
HOST_MATERIALIZATIONS=0
CPU_F32_EXPANDS=0
CRITICAL_PATH_NVME_READS=0
EXTERNAL_RUNTIME_CALLS=0
DEVICE_LOST=0
```

Then:

```text
DEEP2_ENGINE_SSVK_DECODE_BIND=PASS
```

This does not set PROMOTE.

## Q2_K geometry law

The live tensor already proved:

```text
rows=8192
cols=3072
bytes=8257536
```

and:

```text
8192 * (3072 / 256) * 84 = 8257536
```

Therefore the product bind hard-codes only the GGUF geometry invariant:

```text
Q2_K = 84 packed bytes / 256 weights
```

The legacy 72-byte pointer stride in `sovereign_q2_k_gemv.asm` is not a
compatible route for this gate.

## After this passes

Next live gates:

```text
DEEP2_PERSISTENT_DECODE_001
-> DEEP2_RESIDENCY_PRODUCT_001
-> DEEP2_DAILY_STREAMER_LIVE_001
-> DEEP2_INSTALLED_MODEL_ENDURANCE_001
```

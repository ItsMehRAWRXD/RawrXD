# DEEP2_ENGINE_SSVK_DECODE_TO_STREAMER_ENDURANCE_NODEP_20260912

This batch starts **after** the live packed dual-GPU aggregate gate.

Current input authority supplied by the live run:

```text
PRODUCT_LINKED=1
PACKED_Q2K_LIVE=1
MATERIAL_SAME_TOKEN_OVERLAP=1
AGGREGATE_BW_AUTHORITY=1
WINDOW=16/16
FINISH_BALANCE=PARTIAL
PROMOTE=0
```

The finish balancer remains a performance tuning gate because its current
critical-path average does not beat the frozen baseline. It is not an E2E
correctness blocker.

This drop closes the remaining architectural chain in four batches:

1. `d2_engine_ssvk_decode_bind.*`
   - full model forward → final norm → LM head → sampler → KV commit
   - same-token authority receipt
   - no evidence-binary subprocess trick

2. `d2_persistent_decode_gate.*`
   - 16-token consecutive persistent decode gate
   - command rebuild / KV host roundtrip / NVMe / host-forward counters are zero

3. `d2_daily_streamer_live.*`
   - open model → tokenize/prefill → decode/emit → reset/reuse → close

4. `d2_endurance_gate.*`
   - repeated generations and multi-model cases

## Build the portable source-state-machine self-test

MSVC:

```bat
build_msvc.bat
```

The self-test uses synthetic callbacks and **cannot mint live authority**.

## Live binding

Read `Deep2Engine_SsVk_BIND_POINTS.md`.

The product bind must call the already-live packed dual aggregate **inside**
Deep2Engine decode. It must not spawn the evidence executable, copy its receipt,
or manufacture flags.

## Governing result

```text
SOURCE_SELFTEST_PASS != LIVE_PRODUCT_PASS
PROMOTE=0
```

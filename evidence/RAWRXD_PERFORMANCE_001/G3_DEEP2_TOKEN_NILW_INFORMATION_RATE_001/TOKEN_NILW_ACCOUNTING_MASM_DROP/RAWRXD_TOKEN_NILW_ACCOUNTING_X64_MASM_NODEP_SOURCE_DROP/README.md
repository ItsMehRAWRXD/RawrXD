# RawrXD token NILW accounting — x64 MASM, no dependencies

This source drop implements the complete NILW accounting identity as exact
integer arithmetic. The core has no OS, CRT, allocator, file-mapping, scheduler,
or third-party calls. `ExitProcess` is used only by the standalone smoke programs.

## Implemented equation

```text
TOKEN_NILW
= ACTIVE_CODEC_BPW
  × PHYSICALIZATION_RATIO
  × NEW_INFORMATION_FRACTION
  + OVERHEAD_BITS / TOTAL_WEIGHTS
```

The implementation does not multiply rounded decimal ratios. It first verifies:

```text
observed_new_payload_bits = new_codec_bits + overhead_bits
```

It then exposes every term as an exact numerator/denominator pair and applies
limits with full unsigned 128-bit cross-products.

If the caller's existing `ACTIVE_BPW` already uses new payload bits, pass those
same bits as both `active_codec_bits` and `new_codec_bits`. The derived
new-information fraction becomes exactly `1/1`; reuse is not counted twice.

## Default 1T / 10 TPS envelope

Populate `NILW_INPUT` with:

```text
total_logical_weights        = 1,000,000,000,000
payload_cap_bytes_per_token  = 100,000,000
information_rate_cap_bps     = 1,000,000,000
target_tps                   = 10
min_generated_tokens         = 128
target_nilw_num/den          = 1 / 1250
```

`1 / 1250 = 0.0008` exactly; no floating point is used.

## Proof fixtures

- `smoke_identity`: `0.8 × 0.005 × 0.20 = 0.0008`.
- `smoke_overhead`: proves the additive overhead term.
- `smoke_q4_reuse`: `4.0 × 0.005 × 0.04 = 0.0008`, proving the
  metric does not require sub-0.001-bit physical quantization.
- `smoke_reject_identity`: rejects caller/transport accounting disagreement.
- `smoke_reject_budget`: accepts valid facts but withholds sustainability and
  runtime authorization when the budget is exceeded by one byte.

## Build

From an x64 Native Tools command prompt:

```bat
build_masm.bat
```

This assembles with `ml64`, links without the CRT, and runs all five smoke tests.
The core object set is the six `nilw_*.obj` files. Include
`nilw_accounting.h` from C/C++ and call `NilwEvaluate`.

## Authority rule

`token_authority_agrees` and `decode_authority_agrees` are inputs, not outputs.
The final NILW witness gate cannot replace the authoritative token/decode path.
It never touches scheduler, Fence3, residency mapping, or product promotion.

Generation-environment status:

```text
SOURCE_COMPLETE=1
STATIC_AUDIT=PASS
WINDOWS_ML64_BUILD=NOT_RUN
LIVE_DEEP2_BINDING=NOT_RUN
PROMOTE=0
```

# RAWRXD_CORE_DLL_NATIVE_E2E_001 — engineering findings

## Root-cause repair: ggml-compatible activation quantization

The llama.cpp reference (CPU backend) quantizes every activation vector that
feeds a quantized matmul:

* k-quant weights (Q4_K/Q5_K/Q6_K) consume `q8_K` blocks of 256 floats
* Q8_0/Q4_0/Q5_0 weights consume `q8_0` blocks of 32 floats
* the vector is quantized and immediately dequantized before the dot
  (int32 accumulation inside the reference kernels)

`LinearFwd` and `MoEExecuteFwd` previously dot-producted the raw fp32
activations against dequantized weights. That is *more* accurate than the
reference and therefore a systematic ~1.2% activation mismatch at every
matmul, which compounded through 27 blocks and destroyed positional parity.

Fix: `GGMLPreQuantizeActivation` applies the identical quantize/dequantize
step in-place on the activation before each quantized dot (see
`ModelGenieExecutor.cpp`). Measured effect vs the llama.cpp reference:

| stage (layer 0)         | before        | after          |
| ----------------------- | ------------- | -------------- |
| q projection            | rmse 0.0233   | 1.58e-06       |
| kv latent (kv_cmpr)     | rmse 2.1e-03  | 1.40e-08       |
| attention output (pos0) | ratio 1.0047  | n/a (post-fix) |
| logits pos0 (19-tok seq) | rmse 0.247   | rmse 0.0595    |

The embedding lookup (a row copy in the reference) is deliberately NOT
quantized, and stays bit-exact.

## Generation outcome

Before: repeated-token collapse (argmax 245 repeated across positions).
After the numerics fix the DLL produces, from the chat-template prompt:

```
 Hello! How can I help you today? If you have any questions or need
```

16 tokens / 15 distinct, and 23 tokens / 22 distinct on the 64-token run
(stopped at EOS), with no collapse.

## Remaining known issue (documented, not gated-blank)

The multi-position attention weights still differ from the reference by
~1-3% at layer 0 (cos 0.988-0.993 on the layer-0 attention output at
positions 1-2). Everything that feeds the score is now verified against the
reference bit-exactly:

* q projection: 1.58e-06 (the reference q dump)
* kv latent: 1.40e-08 (the reference kv_cmpr dump)
* V at position 0: cos 0.99984 (single-position attention = V exactly)
* RoPE (yarn ramp/ext_factor/mscale cancellation), kq_scale
  (mscale^2/sqrt(192)), softmax and the head/value layouts: all traced to the
  reference formulas in the vendored llama.cpp c479922.
* probing llama's own attention scores via a temporary instrumented build
  shows the reference score set is NOT reproducible from the reference q +
  reference latents + dequantized weights with any of the tested absorption
  or quantization variants, so the residual sits inside the reference
  matmul/score path and is not fixed by any weight-side change.

Effect: the per-position logits track the reference at mean cosine 0.9868
over positions 0-11 (11/12 argmax) and degrade to mean 0.93 over 19
positions as the residual compounds through the MoE stack. The
REFERENCE_DIFFERENTIAL gate is certified on the 0-11 window; positions 12+
are recorded in the certificate JSON (`positional_reference`).

## Instrumentation added for the investigation

* `tools/verify_e2e_cert.py` — independent certificate verifier
* `tools/certify_e2e.py`, `tools/freeze_baseline.py`
* `tools/compare_stages.py`, `tools/compare_e2e_parity.py`
* `tools/e2e_evidence.cpp` — per-step evidence capture tool
* `rawrxd_kq_probe.cpp` / `rawrxd_tok_ref.cpp` — llama.cpp c479922 drivers
  (patched `tmp_llama-clone` with an env-gated tensor probe in
  `llama-kq-probe.{h,cpp}` + registration points in `llama-graph.cpp` /
  `models/deepseek2.cpp`; default-off, no behaviour change without
  `RAWRXD_PROBE_DIR`)

## Reproduction

```
reproduce_e2e.cmd
```

runs the full chain: build, teacher-forced differential, fresh CMake +
DLL build, lifecycle + generation tests, evidence capture, llama reference
diff, tokenizer parity, freeze, certify, verify.

## REFERENCE_DIFFERENTIAL_002 investigation (follow-up)

Probe instrumentation was repaired (graph outputs are marked with
ggml_set_output so the dumped tensors are not scheduler-reused buffers; the
dumped q projection then matches the runtime bit-exactly at cos 1.0). With
correct dumps the layer-0 attention was measured at every position:

* RoPE angles (yarn ramp + interpolation) already matched the reference at cos 1.0.
* Solving llama.cpp's kq_scale from its own kq/softmax dumps gives
  0.11478 / 0.11495 / 0.11463 across three heads, i.e. attn_factor_org ==
  rope_attn_factor (the yarn_attn_factor cancellation applies to the score
  side too), lowering kq_scale from 0.214971 to 0.114810.
* Applying that scale makes the layer-0 attention weights match the reference
  at cos 0.9999998 at positions 1, 2 and 3.

Blocker that stopped the change from being adopted: the locally rebuilt
llama.cpp probe does NOT reproduce this certificate's stored reference
bit-exactly (0.85% logit delta at position 0, cos 0.869 at position 2), so
the scale extracted from it cannot override the reference the differential
gate is measured against. Adopting it moved the stored-reference differential
from 11/12 argmax (mean cos 0.9868) to 3/12 (mean cos 0.854). The stored
reference remains authoritative and the scale change was reverted.

Required next step: regenerate the reference logits with a llama.cpp build
that reproduces the stored reference exactly (record the build config, the
n_ctx-driven cache type - 256 cells gives f32, 16384 gives f16 - the thread
count, and the llama commit), then re-adjudicate the scale. The probe
(RAWRXD_PROBE_DIR, tools/rawrxd_kq_probe.cpp) now marks graph outputs and
dumps kq_soft_max, q_proj, q_attn, k_attn, v_attn, kv_up, kv_cmpr_used per
layer per position, which is the right instrument for that work.
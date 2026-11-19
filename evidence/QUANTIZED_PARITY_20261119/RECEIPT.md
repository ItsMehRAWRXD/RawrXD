# Quantized parity — TinyLlama 1.1B Chat Q4_K_M vs llama.cpp — 2026-11-19

Sprint gate: **does reference parity generalise beyond the dense Qwen2.5-Coder-1.5B model?**

## Verdict

```
QUANTIZED_REFERENCE_COMPARISON=COMPLETED
ARGMAX_AGREEMENT=17/18
BOUNDED_REFERENCE_ACCEPTANCE=17/18 (certifier FAIL_REFERENCE_PARITY at pos14)
STRICT_NUMERICAL_PARITY=OPEN
NEAR_TIE_ARGMAX_FLIP=POS14
FIRST_DIVERGENCE_POS0=blk2 v  cos 0.999386
FIRST_DIVERGENCE_POS14=blk1 swiglu cos 0.999873
```

## Model / binaries

```
MODEL F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
MODEL_SHA256 9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0
REFERENCE F:\rawrxd\wp01_reference\harness-build\Release\llama_dump_intermediate.exe (llama.cpp, CPU)
DEEP2     F:\rawrxd\build\bin\Release\deep2_gpu_certify.exe
TOKENS    1 450 4996 17354 1701 29916 12500 29879 975 278 17366 11203 29889 1987 372 6350 3448 29889
```

## Commands

```
llama_dump_intermediate.exe <gguf> tokens.txt ref --no-hidden
deep2_gpu_certify.exe --model <gguf> --tokens "<18 ids>" --reference-dir ref_logits --dump certify_tinyllama_q4k
```

`ref_logits/ref_logits_pos<N>.bin` are the raw f32 `pos<N>/logits.bin` from the reference dump.

## Observed

Per-position GPU-vs-reference (certifier thresholds cos >= 0.99, max_abs < 2.0, argmax equality):

* 17/18 positions PASS; **pos14 FAIL** on argmax equality only
  (`cos=0.9998468`, `max_abs=0.4494` — both inside tolerance).
* cos range across 18 positions: 0.9994356 … 0.9999074.

pos14 is a three-way near tie, not a systematic error:

```
reference : top1 10.260036 (tok 30010)  top2 10.140090 (tok 29915)  margin 0.119946
Deep2 GPU : top1 10.264118 (tok 432)    top2 10.232905 (tok 30010)  margin 0.031213
reference value of Deep2's pick (tok 432) = 10.125875
```

Deep2 places token 432 ~0.134 above the reference; the reference's own top-2 gap is 0.120.
A sub-0.14 logit shift on a 0.12-margin tie flips the argmax.

## Op-level comparison (Deep2 trace vs llama.cpp boundaries, best variant match)

| position | compared ops | first op < cos 0.9999 | cos |
|---|---|---|---|
| 0 | 307 | op33 blk2 `v` | 0.999386 |
| 14 | 307 | op26 blk1 `swiglu` | 0.999873 |

Deep2's own GPU-vs-CPU trace check reports first divergence at
`pos=12 block=2 v (cos 0.997335)` — worse than the dense Qwen model
(`pos=1 block=2 v, cos 0.999871`).

## Interpretation

Quantised weights amplify divergence relative to the dense model: op-level cosine at
block 2 `v` is 0.999386 (Q4_K_M) vs 1.000000 (Qwen2.5-Coder-1.5B dense). The pattern is
consistent with quant-dot dequantisation/accumulation-order differences, not a wrong
operator: every op before the reported index matches at cos >= 0.9999, and drift grows
with depth.

## Caveats

* Bounded-error acceptance, **not** strict logit parity.
* One prompt, 18 positions, single model.
* No kernel change was made; the divergence is characterised, not fixed.

## Next blocker

Quant-dot accumulation order (GPU) vs f32 reference accumulation is the dominant error
source; closing strict parity needs fp64/fp32-ordered accumulation in the quant-dot path
or a reference that reproduces Deep2's accumulation order.
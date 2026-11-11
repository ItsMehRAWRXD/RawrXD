# Deep2 Qwen2.5-Coder / DeepSeek parity — investigation closure record

Date: 2026-10-13
Model under test: `F:\rawrxd\models\qwen2.5-coder_1.5b-base.gguf`
  (sha256 `ee1ca8b716933587127f6feb9ff5a247f1e4460e72dcf6293331b9617f8a8aa2`)
Secondary model: `F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf`
Reference: real llama.cpp, two independent entry paths
Binary built from current tree: `build_rt\deep2_agentic_loop.exe` (BUILD_OK)

--------------------------------------------------------------------------
## 1. The "L2 = 60,677,402" embedding anomaly — RESOLVED

`ref_multitoken.py` (the unpatched reference) computed the embedding row
stride with **Q4_K block math for a Q6_K tensor**:

```python
row_bytes = nb_per_row * BLOCK_BYTES[TYPE_Q4_K]      # 6*144 = 864 bytes
return dequant_q4_k_vec(np.frombuffer(raw, np.uint8).reshape(nb_per_row, 144))
```

`token_embd.weight` is **Q6_K** (verified via `gguf.GGUFReader`: shape
[1536, 151936], type Q6_K, abs_offset 5950976), so the correct stride is
`6 * 210 = 1260` bytes. Reading the same row with the wrong stride/type
reproduces the reported anomaly **exactly**:

```
Q4_K read of the Q6_K row  : FIRST8=-205.40625,-856.640625,-929,-784.28125,...
                             MIN=-5783760  MAX=7382340  L2=60677402.3
bad trace STEP=0 CP=EMBED  : FIRST8=-205.40625,-856.640625,-929,-784.28125,...
                             MIN=-5783760  MAX=7382340  L2=60677402.3   (identical)
```

`ref_multitoken_tied.py` already carried the type-aware fix but had **never
been executed**; the corrupted traces came from the unpatched sibling.

After running the patched reference:
```
STEP=0 CP=EMBED L2=0.69449961 FIRST8=0.00820696354,-0.012896657,...
```

## 2. Reference decoders and offsets — VERIFIED BIT-EXACT

Against the authoritative `gguf` package dequantizer, on real tensors
(`blk.0/1/27.attn_q/k/v`, `attn_output`, `ffn_gate/up/down`, `output_norm`,
`token_embd`):

```
maxabs = 0   for Q4_K, Q6_K and F32 on every tensor tested
OFFSET_MISMATCH_COUNT = 0   (reference data_start/toff arithmetic is exact)
general.alignment = 32, general.quantization_version = 2
```

The reference's `dequant_q4_k_vec` / `dequant_q6_k_vec` are correct for this
file. The earlier "README.q4_k" and "README.q6_k" documentation claims also
match.

## 3. LM-head indexing — repaired (latent hazard)

`logits_top10_from` hardcoded the Q6_K row stride:
`lm_row_bytes = lm_nb_per_row * BLOCK_BYTES[TYPE_Q6_K]`.
Correct only because this GGUF happens to have a Q6_K tied head. Replaced
with type-aware dispatch on `lm_ttype` plus a `_lm_decode()` helper, so a
Q4_K/F16/F32 head or a separate `output.weight` cannot silently misread rows.
`output.weight` is absent -> tied embeddings, `lm_rows = 151936`.

## 4. The llama.cpp vs reference position-0 mismatch — RESOLVED

Two independent llama.cpp entry paths agree **bit-exactly**:

```
custom dump tool            : max=10.9391  min=-14.6762  argmax=304
llama-cpp-python binding    : max=10.9391  min=-14.6762  argmax=304
1-token run vs 7-token run  : maxabs = 0.000000, argmax 304 both
```

A fully independent clean-room forward (gguf-package decoders only, no code
shared with the reference) reproduced the numpy reference exactly (argmax
5290). So the disagreement was never a reference bug.

**Cause found and proven:** llama.cpp's K-quant `ggml_mul_mat` quantizes the
f32 activation vector to **Q8_K** (256-element blocks, fp16 scale
`amax/127`, int8 values) before the integer dot product. Emulating that
protocol exactly in numpy:

```
token   exact_cos   q8k-emulated_cos   llama_argmax   exact_argmax   q8k_argmax
750       0.80406        0.99949            304           5290           304
220       0.67624        0.99954             15          113799           15
1887      0.54041        0.99890             15          117612           15
...      (all 12 tokens: exact ~0.52-0.80, emulated 0.9985-0.9996, argmax 12/12 match)
```

Conclusion: the numpy reference is arithmetically correct. The remaining
difference is llama.cpp's quantized-activation protocol, not an arithmetic
defect.

## 5. Deep2 Q/K/V attention-bias repair — VERIFIED

Built from the current tree (uncommitted fix in
`src/deep2/runtime_graph_executor.cpp`, lines ~2374-2420).

```
                                    pre-fix            post-fix CPU     post-fix GPU
cosine vs real llama.cpp          -0.129375            0.999578          0.999592
relative L2                        1.498410             0.029663          0.029048
RMSE                                   4.2405              0.08395          0.08221
max abs diff                           21.74               0.4511           0.4054
argmax                                73756   DIFFER         304 MATCH        304 MATCH
gpu_calls / cpu_calls              197 / 0             197 / 0          197 / 0
```

All 28 model layers carry non-zero `attn_q/k/v.bias` (57,344 non-zero F32
values). Positions 1-6 of the bias-policy scan confirm llama.cpp applies
all three biases (only `all(q,k,v)` reached cosine >= 0.995 and 5/7 argmax).

Teacher-forced 7 positions (Qwen, token 750, 220, 1887, 3932, 262, 1173, 445):

```
pos  d2_argmax  llama_argmax   cosine     relL2    verdict
 0        304           304   0.999592   0.029048   MATCH
 1     151661           374   0.997959   0.063872   DIFFER (near-tie)
 2       3932          3932   0.999008   0.051110   MATCH
 3        262           262   0.998756   0.051202   MATCH
 4        671          1173   0.997476   0.071162   DIFFER (near-tie)
 5        445           445   0.997343   0.072862   MATCH
 6       1986          1986   0.997373   0.072500   MATCH
```

No regression on a bias-free architecture (`llama3.2-3b-Q2_K.gguf`, token
128000, empty KV):

```
post-bias-fix Deep2: argmax=14924 logits=128256 nonfinite=0
                     gpu_calls=0 cpu_calls=197
                     top10=[14924,2,791,475,16309,1757,3936,755,7778,1527]
baseline            : identical (argmax, top-10 order, counters)
```
The bias dispatch is a strict no-op when no `.bias` tensor exists.

## 6. Remaining Deep2 gap (NOT closed)

DeepSeek-V2-Lite-Chat, 67-position teacher-forced parity vs real llama.cpp
(post-bias-fix build, CPU path):

```
ARGMAX_MATCHES = 57/67
WORST_COSINE   = 0.994433
WORST_REL_L2   = 0.110743
WORST_MAXABS   = 4.002051
FIRST_ARGMAX_MISMATCH = position 1
```

All 10 mismatches are narrow-margin ranking flips, not catastrophic errors.
Position 15 detail (reference top-1 token 15 @ 13.038329 vs token 17
@ 12.528111; Deep2 ranks 17 @ 12.875107 above 15 @ 12.801093 — a 0.24-logit
reference margin and a 0.07-logit Deep2 margin).

Interpretation: Deep2's remaining error is a quantized-activation protocol
difference from llama.cpp, larger on DeepSeek's path than on Qwen's. It is
not an attention-bias, RoPE, GQA, RMSNorm or embedding defect — those are
now proven at cosine 0.9996 on Qwen and exact on the reference decoders.

--------------------------------------------------------------------------
## What is established

PASS  reference embedding decode (root cause + fix)
PASS  reference Q4_K/Q6_K decoders bit-exact vs gguf package
PASS  reference GGUF offset arithmetic exact
PASS  LM-head type-aware stride (latent hazard removed)
PASS  llama.cpp self-consistency at position 0 (two entry paths, bit-exact)
PASS  llama.cpp-vs-reference mismatch explained (Q8_K activation protocol,
      emulated to cosine 0.9995 and 12/12 argmax)
PASS  Deep2 attention-bias repair vs real llama.cpp on Qwen (cos 0.9996,
      argmax 304, no nonfinite values)
PASS  no regression on bias-free llama3.2
FAIL  DeepSeek 67-position strict argmax parity (57/67, near-tie flips)

## Next single gate

Reduce DeepSeek's remaining relL2 (worst 0.111) to llama.cpp's protocol
level by replicating llama.cpp's activation quantization exactly on Deep2's
quantized GEMV path, then re-run the 67-position gate and require
67/67 argmax. Do not change RMSNorm, RoPE, GQA, residuals or FFN layout —
they are no longer implicated.

---

## APPENDIX (added 2026-10-13, later session) � residual-gap localization

### A. Error is position-independent: it is not attention / RoPE / KV

Per-position relative-L2 of Deep2 vs real llama.cpp, DeepSeek-V2-Lite
teacher-forced positions 0-66:

    mean relL2 positions 0-3    = 0.055884
    mean relL2 positions 60-66  = 0.037148

The error does not accumulate with context, and it fluctuates per token
(0.027 at pos 60 vs 0.111 at pos 31). That signature rules out attention,
RoPE, GQA, the KV cache and residual accumulation, and points at the
per-projection quantized-GEMV protocol. This matches the earlier PyTorch
observation that the error tracks the token's activation magnitudes, not
its position.

### B. Both quantized dot paths verified as using the same protocol

KQuantRowDotQ8() was factored out and the MoE helper now routes through it,
so the dense-linear and MoE-expert K-quant paths cannot drift apart. Verified
numerically neutral: DeepSeek 67-position logits are byte-identical before
and after (md5 B5A50C5ECD66C4231747FF8F88AB12DD on pos0, and all 67
positions), and the GPU/CPU parity gate still holds.

This is a robustness fix, not the closure: it makes the two paths agree with
each other, not with llama.cpp. The remaining difference is elsewhere.

### C. What the QUANT_TRACE dispatch actually shows for DeepSeek-V2-Lite

    path                       tensors taking it                        protocol
    [quant]      kind 0/1      attn_q, attn_output, ffn_gate, ffn_up,      ggml int-MAC
                  Q4_K/Q6_K    ffn_*_shexp, expert up/gate, LM head        vs Q8_K act
    [quant-legacy] kind 2/3     blk.0.ffn_down.weight (Q8_0, n_in=10944)   ggml int-MAC
                  Q5_0/Q8_0                                                     vs Q8_K act
    float fallback              none reached in this run                 exact f64

All three legislate correct stride arithmetic (wbytes == need for every
tensor, including the mixed Q4_K/Q6_K shared-expert down projections where
adjacent layers differ: blk.1 kind=1 rb=2310, blk.3 kind=0 rb=1584). The
float fallback is not reached for DeepSeek, so it is not the source.

### D. Why this run is still not llama.cpp-exact

Deep2's CPU dots reproduce ggml_vec_dot_q4_K_q8_K_generic /
ggml_vec_dot_q6_K_q8_K_generic symbolically (integer products first, 8 int32
lanes, fp16 scales last, Q4_K min term via 16 half-block sums), and the
activation is Q8_K quantised at d = amax/127 with lround, bsums at 257..272.
The residual difference is in *quantisation detail*, not arithmetic
structure. The two remaining candidates, in order of likelihood:

  1. ggml rounds the Q8_K block scale d through FP16
     (ggml_fp32_to_fp16(d) then back) before dividing; Deep2 keeps the
     FP32 d. That alone is a per-block scale error of up to 2^-11 relative.
  2. ggml uses 
earbyint/clamp semantics that differ from std::lround at
     exact .5 boundaries, and clamps to [-127, 127] explicitly.

Because the error is position-independent and tracks activation magnitude,
these are the right suspects. 67/67 closure requires matching them exactly
(plus whatever the GPU shader does), then re-running the same gate.

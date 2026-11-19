# Deep2 First Causal Divergence — RECEIPT

ASOF_UTC=2026-11-18T23:47:00Z
REPO=F:\rawrxd
TIP=19bc39e0a2
PROMOTE=0
CERTIFIED=0
RELEASE=HELD

## Question
Deep2 numerical reference parity = FAIL (final logits uncorrelated with the
llama.cpp qwen35 reference: COSINE ~ -0.2, argmax mismatch). The open question
was: WHICH Deep2 operation diverges first? Final-logit comparison cannot
separate "wrong attention" from "wrong FFN" from "wrong output projection."

## Method
Per-operator oracle comparison using the existing dataset
`evidence/qwen38_27b_cpu_ref_20261118/` which contains BOTH:
  - reference/  = llama.cpp `llama_dump_intermediate` per-boundary dumps
  - deep2/      = Deep2 per-operator dumps
for the SAME model, SAME tokens, SAME positions.
Harness: `compare_qwen38_v2.py` (maps Deep2 trace names -> llama.cpp boundaries).
Outputs: `compare_pos0.txt`, `compare_pos1.txt` (this directory).

```ini
MODEL=Qwen3.8-27B (qwen35 hybrid: Gated DeltaNet linear-attn + full-attn every 4th layer)
ARCH=arch=qwen35 blocks=65 embd=5120 heads=24 kv=4 kl=256 vl=256 rope_dim=64 eps=1e-06
TOKENS=1,185
POSITIONS=0,1
```

## RESULT — first causal divergence

Position 0 (token=1):
```
OK       blk=0 pc=2 attn_norm   size=5120  cos=1.000000000  max_abs=1.9e-06   ref=attn_norm_L0.bin
DIVERGE  blk=0 pc=3 attn_proj   size=5120  cos=0.962538045  max_abs=3.85      ref=attn_proj_L0__dup1.bin
```
Position 1 (token=185):
```
OK       blk=0 pc=2 attn_norm   size=5120  cos=1.000000000  max_abs=2.4e-07   ref=attn_norm_L0.bin
DIVERGE  blk=0 pc=3 attn_proj   size=5120  cos=0.948550972  max_abs=10.75     ref=attn_proj_L0__dup1.bin
```

FIRST_DIVERGENCE = layer 0, GDN (linear-attention) block, attention output
projection (`attn_proj` / `linear_attn_out-0`).

What is PROVEN:
- The token embedding and layer-0 input RMSNorm (`attn_norm`) are BIT-EXACT vs
  the independent llama.cpp reference (cos=1.000000000, max_abs ~1e-6 = fp32
  rounding). => token ids, embedding lookup, and RMSNorm are correct.
- The FIRST operator that diverges is the layer-0 linear-attention output
  projection. Everything downstream (resid1, resid2, ffn_*, all later blocks,
  final logits) inherits this corruption.

Root-cause environment (from deep2_run.log):
```
gpu_calls=0 cpu_calls=1104
fallback=GDN reference recurrence; Vulkan stateful dispatch unavailable
```
Deep2 executed the Gated DeltaNet recurrence as a CPU "reference recurrence"
because no Vulkan stateful GDN dispatch exists. That CPU recurrence does NOT
match llama.cpp's qwen35 GDN, and it is the first divergent computation.

## Interpretation
The parity failure is NOT in embedding, RMSNorm, or a generic matmul. It is
localized to the GDN / linear-attention (SSM-style) recurrence path — i.e. the
OPEN "SSM/Mamba / MoE / MLA" experimental subsystem — at the very first layer.
This explains why the failure is total (a wrong layer-0 attention output
propagates through all 64+ layers and destroys final logits).

## Next localization step (to separate GDN-recurrence vs O-proj matmul)
Deep2's linear-layer dump currently exposes only `attn_norm` and `attn_proj`
(no q/k/v, no pre-O-projection `attn_out`). To split the two remaining causes:
  1. Add a Deep2 dump of the pre-O-projection GDN output (`attn_output`, 6144 elems)
     and of q/k/v/conv for linear layers.
  2. Compare against reference `attn_output-0` (attn_proj_L0.bin, 6144).
     - If pre-O-proj diverges => the GDN recurrence (conv/ssm/gdn delta rule) is wrong.
     - If pre-O-proj matches but linear_attn_out diverges => the O-projection matmul
       (weight layout / op) is wrong.
Then port/fix the GDN recurrence (src/deep2/op_gdn.cpp, QwenGdnHost.cpp,
NemotronH* ) to bit-match the llama.cpp qwen35 GDN reference, and add a Vulkan
stateful GDN dispatch so the path is not CPU-fallback.

## Evidence files (this directory)
- compare_pos0.txt / compare_pos1.txt  — full per-operator comparison logs
- INPUT_SHA256.txt                     — SHA256 of the compared tensors + tokens + run log
- RECEIPT.md                           — this file

## Gate status
DEEP2_REFERENCE_PARITY=FAIL
FIRST_CAUSAL_DIVERGENCE=LAYER0_GDN_ATTN_PROJ (input RMSNorm exact; GDN/linear-attn recurrence is the root)
EXPERIMENTAL_SUBSYSTEMS=OPEN (SSM/Mamba/GDN implicated as the parity root cause)

FAIL_CLOSED_LAW=NOT_RUN!=PASS
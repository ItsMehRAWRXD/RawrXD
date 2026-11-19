# S004 reference tensor variant mapping

Source evidence: `first_divergence_pos4.json`, `ref/pos4`, and `deep2_op_trace.csv`.

## Established mapping

The operation trace uses the following llama.cpp reference boundaries:

```text
attn_norm -> attn_norm_L<N>.bin
q         -> q_L<N>__dup1.bin
k         -> k_L<N>__dup1.bin
v         -> v_L<N>__dup1.bin
attn_out  -> attn_preproj_L<N>.bin
resid1    -> attn_resid_L<N>.bin
ffn_norm  -> ffn_norm_L<N>.bin
gate      -> ffn_gate_L<N>.bin
up        -> ffn_up_L<N>.bin
swiglu    -> ffn_swiglu_L<N>.bin
ffn_out   -> ffn_down_L<N>.bin
resid2    -> resid2_L<N>.bin
```

The reference JSON records the complete variant set for Q/K/V. For layer 0, Q/K/V variants are 6,144/1,024/1,024 bytes respectively. `__dup1` and `__dup2` are byte-identical within each tensor family; the un-suffixed and `__dup3` variants are distinct. The selected `__dup1` boundary is therefore not interchangeable with the base or `__dup3` tensor.

## Coverage

- Compared boundaries have explicit element counts, cosine, max-absolute error, RMS, and reference RMS.
- `token_embd.weight` and `resid_in` are intentionally `NO_REFERENCE_BOUNDARY`.
- `attn_proj` is explicitly `REFERENCE_MISSING`; it is not treated as a match.
- At position 4, the recorded first CPU divergence is operation 11, block 0, `up`, cosine `0.9998673514384594`, after operations 2–10 were compared.

```ini
REFERENCE_VARIANT_MAPPING=ESTABLISHED
QKV_LAYOUT=EXPLICIT_DUP1_BOUNDARIES
MISSING_REFERENCE_BOUNDARIES=attn_proj
FIRST_REPORTED_CPU_DIVERGENCE=POS4_BLOCK0_UP
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

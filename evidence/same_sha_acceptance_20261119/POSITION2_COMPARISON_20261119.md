# Position 2 operation comparison

Artifact: `first_divergence_pos2.json`, backend `cpu`.

- Operation records: `395`
- Comparable boundaries: `363`
- Cosine threshold: `0.9999`
- First threshold crossing: block 2 `attn_out`, op 34
- Reference boundary: `attn_preproj_L2.bin`
- First crossing cosine: `0.9998488579467929`
- First crossing maximum absolute error: `0.014291971921920776`
- First crossing RMSE: `0.0026410415837960876`
- Lowest comparable cosine: `0.99654311677592`, block 12 `ffn_out`, op 181
- Missing coverage includes `attn_proj`; output norm and logits are unmapped.

This is the first reported threshold crossing, not proof of the causal defect.
No kernel was changed from this receipt.

`S007=COMPARISON_COMPLETE_FIRST_THRESHOLD_CROSSING=BLOCK2_ATTN_OUT_OP34`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

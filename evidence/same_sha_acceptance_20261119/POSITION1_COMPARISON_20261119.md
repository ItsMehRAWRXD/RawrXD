# Position 1 operation comparison

Artifact: `first_divergence_pos1.json`, backend `cpu`.

- Operation records: `395`
- Comparable boundaries: `363`
- Cosine threshold: `0.9999`
- First threshold crossing: block 2 `v`, op 33
- Reference boundary: `v_L2__dup1.bin`
- First crossing cosine: `0.99987098758696`
- First crossing maximum absolute error: `0.02573797106742859`
- First crossing RMSE: `0.007737101712146897`
- Lowest comparable cosine: `0.99596769826647`, block 15 `v`, op 215
- Missing coverage includes `attn_proj`; output norm and logits are unmapped.

This identifies the first reported threshold crossing, not necessarily the
causal defect. No kernel was changed based on this result.

`S006=COMPARISON_COMPLETE_FIRST_THRESHOLD_CROSSING=BLOCK2_V_OP33`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

# Position 0 operation comparison

Artifact: `first_divergence_pos0.json`, backend `cpu`.

- Operation records: `395`
- Comparable boundaries: `363`
- Cosine threshold: `0.9999`
- First threshold-crossing field: unset (`null`)
- Lowest comparable cosine: `0.999976888482667`, block 27 `ffn_out`, op 391
- That boundary: max absolute error `0.226669788360596`, RMSE `0.0537376842301688`
- Next residual boundary: block 27 `resid2`, op 392, cosine `0.999994842758291`, max absolute error `0.226631641387939`
- Missing coverage includes `attn_proj`; output norm and logits are unmapped.

Position 0 has no recorded first divergence under the comparator's threshold
field, but its late-layer FFN output is measurably different. This is a
diagnostic result, not strict parity.

`S005=COMPARISON_COMPLETE_FIRST_THRESHOLD_CROSSING_UNSET`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

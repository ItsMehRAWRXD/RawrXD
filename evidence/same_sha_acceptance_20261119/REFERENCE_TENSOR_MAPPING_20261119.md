# Reference tensor variant mapping

Source artifact: `first_divergence_pos0.json`, backend `cpu`, position `0`.

- Q boundaries resolve to `q_L<N>__dup1.bin`.
- K boundaries resolve to `k_L<N>__dup1.bin`.
- V boundaries resolve to `v_L<N>__dup1.bin`.
- The retained variant lists include the unqualified and alternate duplicate
  names, but the selected boundary is consistently `__dup1` for all 28
  transformer layers.
- `attn_proj` has no reference boundary in the retained artifact (28 rows).
- Summary: 363 `COMPARED`, 28 `REFERENCE_MISSING`, 2 `NO_REFERENCE_BOUNDARY`,
  2 `UNMAPPED` rows out of 395.

This establishes the Q/K/V variant mapping for the available comparison data;
it does not close missing `attn_proj` coverage or strict parity.

`S004=REFERENCE_QKV_MAPPING_ESTABLISHED`
`S009=FIRST_DIVERGENCE_OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

# Deep2 Q6 Packed-Byte Optimization

The Q6_K batch shader now decodes each four-column lane with two packed byte
loads instead of decoding every element through separate byte reads. The
quantization layout, scale index, high-bit mask, signed scale, and `-32`
offset are unchanged.

## Certification receipt

- Candidate: `rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp`
- Generated artifact: `rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv`
- Route: `LAYER_SPLIT`, Q4 hot, Q6 hot, tile 8, no trace, GPU weights `100/0.01`
- Baseline control: `28.444 TPS`
- Candidate runs: `17.705`, `30.101`, `35.269 TPS`
- Candidate median: `30.101 TPS` (`1.0583x` control)
- Gate margin: `0.5%`
- SPIR-V validation: PASS
- `ctest`: `24/24 PASS`

The first measured run was cold, so this is a certified improvement over the
fresh control used by the gate, not a claim that every run sustains the median.
The earlier `35.897 TPS` historical result remains a separate reference and
is not overwritten by this receipt.

The mutation controller remains fail-closed. A rejected candidate restores the
declared shader files, verifies their hashes, and rebuilds the baseline binary
before another benchmark can run.

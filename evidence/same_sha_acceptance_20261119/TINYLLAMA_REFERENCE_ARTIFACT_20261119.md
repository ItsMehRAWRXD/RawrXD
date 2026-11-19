# TinyLlama Q4_K reference artifact

- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Model SHA-256: `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0`
- Reference root: `evidence/QUANTIZED_PARITY_20261119/ref`
- Position directories: `18` (`pos0` through `pos17`)
- Binary tensor files: `7524`
- Position manifests: `18`
- Manifest schema: boundary name, source layer, dimensions, element count, byte count
- Q/K/V variants include raw and reshaped forms; the comparison mapping selects
  the reshaped `__dup1` Q/K/V variants where applicable.

This confirms a complete retained reference artifact set for the recorded
positions. It does not by itself establish GPU parity.

`S012=REFERENCE_ARTIFACT_INVENTORY_COMPLETE`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

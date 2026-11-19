# TinyLlama Q4_K GPU parity

Executable: `build_sprint_20261119/bin/Release/deep2_gpu_certify.exe`

- Executable SHA-256: `88CB2AE5D1C34C1BDAFE0B8F35C514601D22971F9648ED2912B9D2A67F2D18AC`
- Model SHA-256: `9FECC3B3CD76BBA89D504F29B616EEDF7DA85B96540E490CA5824D3F7D2776A0`
- Input tokens: `1 185`
- GPU calls: `310`
- CPU calls/fallbacks: `0`
- Non-finite logits: `0`
- Position 0: cosine `0.9996452`, max abs `0.3656`, argmax match, internal PASS
- Position 1: cosine `0.9965125`, max abs `1.104`, argmax match, internal FAIL
- Process exit: `2`
- Cleanup: reported successful

The run proves GPU execution without CPU fallback and finite output, but fails
the internal GPU-versus-CPU diagnostic at position 1. No independent llama.cpp
logits were supplied to this run, so strict reference parity is unverified and
not claimed.

`S013=GPU_EXECUTION_PASS_PARITY_FAIL`
`STRICT_PARITY=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

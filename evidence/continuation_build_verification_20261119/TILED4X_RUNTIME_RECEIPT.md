# Tiled Q4K runtime verification

## Build

- Target: `deep2_gpu_certify`
- Configuration: `Release`
- Command: `cmake --build build_sprint_20261119 --target deep2_gpu_certify --config Release --parallel 4`
- Exit: `0`
- Executable: `build_sprint_20261119/bin/Release/deep2_gpu_certify.exe`
- Executable SHA-256: `88CB2AE5D1C34C1BDAFE0B8F35C514601D22971F9648ED2912B9D2A67F2D18AC`
- Shader SPIR-V SHA-256: `DB342B90D313799821E574C5BFE11987C7B7BE5962664C8A5039601EB23CD274`

## Runtime

- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Command: `deep2_gpu_certify.exe --model models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf --tokens "1 185" --dump evidence/continuation_build_verification_20261119/tiled_runtime`
- Shader directory: `src/deep2/shaders`
- Exit: `2` (internal diagnostic failure)
- GPU calls: `310`
- CPU calls/fallbacks: `0`
- Finite logits: `32000/32000` at both positions
- Position 0: cosine `0.9996452`, max abs `0.3656`, internal PASS
- Position 1: cosine `0.9965125`, max abs `1.104`, internal FAIL
- Resource cleanup: reported successful

## Tiled selection

The runtime log contains pipeline creation for the regular quantized path, but no
`[Q4K_TILED4X_DISPATCH]` record. Therefore tiled-pipeline execution is **not
verified** by this run. No performance or parity claim is made for the tiled
shader. The raw console log is `console.log` in this directory and the certifier
receipt is `tiled_runtime/full_model_receipt.json`.

`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`

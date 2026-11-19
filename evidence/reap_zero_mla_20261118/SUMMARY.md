# REAP-ZERO MLA GPU-attention evidence

Source revision before commit: `434d7f76d0`.

## Implementation

`DispatchAttnDecodeMLA()` now validates buffer sizes and supported geometry, updates all five storage-buffer descriptors, pushes the shader-compatible 40-byte constant block, records the dispatch, and waits for completion for non-fused execution. The shader performs explicit sequence-major K/V attention with partial RoPE and writes the output buffer. Latent-KV reconstruction is intentionally excluded and must use its dedicated path.

## Runtime acceptance

Device: AMD Radeon AI PRO R9700 (Vulkan ordinal 0)

Executable: `build/bin-msvc/Release/reap_zero_mla_test.exe`

Executable SHA-256: `6E973D62CC377CC2E11C9DC7F86F8D5498ABED2F0E798EBC7E8A3471261749F2`

Shader: `src/deep2/shaders/attn_decode_mla.spv`

Shader SHA-256: `A20F9469B63F1B6E73DE10830300277B04745207AB0208B396BAD42CD33BB9DE`

```ini
GEOMETRY=heads=16 qkDim=192 nope=128 rope=64 vDim=128 position=1
ROPE_THETA=10000000
ROPE_SCALE=1
TOLERANCE_MAX_ABS=0.0002
GPU_OUTPUT_WRITE=PASS
CPU_GPU_MAX_ABS=2.98023224e-8
CPU_GPU_RMS=1.04002007e-8
REPEATED_DISPATCH=PASS
INVALID_GEOMETRY_REJECTION=PASS
PROCESS_EXIT=0
RESULT=PASS
```

The test uses deterministic Q/K/V/K-pe inputs and an independent CPU MLA calculation. It verifies two consecutive dispatches and downloads the produced output after each dispatch.

## Scope limits

This certifies the explicit sequence-major MLA tile only. Latent-KV reconstruction, model-wide Qwen/DeepSeek integration, fused command-buffer execution, and full-model numerical parity remain separate gates.

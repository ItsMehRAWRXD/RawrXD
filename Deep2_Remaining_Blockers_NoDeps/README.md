# Deep2 remaining blockers — no-dependency source drop

This drop addresses the remaining Deep2 numerical-certification blockers without
linking llama.cpp, ggml, Ollama, curl, WinHTTP, or any other inference runtime.

Files:
- `Deep2CorrectnessCert.hpp` — header-only scalar/reference implementation:
  - ggml-compatible Q4_0 dequantization and GEMV
  - FP16 conversion
  - stable softmax
  - correct grouped-query attention mapping (`kv_head = q_head / group_size`)
  - RMSNorm
  - RoPE reference (interleaved and NeoX split layouts)
  - SwiGLU
  - finite/explosion statistics
  - tensor parity checks
- `Deep2CertBridge.hpp` — zero-dependency stage hooks for `Deep2Engine.cpp`
- `deep2_cert_main.cpp` — standalone self-tests
- `cert_deep2.ps1` — MSVC/g++ build-and-run
- `CMakeLists.txt` — optional CMake build

## Required certification order

1. Build/run `deep2_cert_main.cpp`.
2. Add `Deep2CertBridge.hpp` stage hooks to layer 0.
3. Capture `ATTN_OUT` immediately before the O projection.
4. Compare the engine O projection with `gemv_q4_0_f32`.
5. If `ATTN_OUT` is already bad, compare Q/K/V, RoPE, GQA, and softmax.
6. If `ATTN_OUT` is sane but `ATTN_O` is bad, fix O-weight tensor routing,
   stride/orientation, Q4_0 block indexing, or optimized GEMV.
7. Repeat parity through FFN and residual output.
8. Only then move from one-token parity to 32-token agentic generation.

## Build

PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\cert_deep2.ps1
```

or:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

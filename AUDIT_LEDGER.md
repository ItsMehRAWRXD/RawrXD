# RawrXD / Deep2 Audit Ledger

| ID | Component | Issue | Impact | Risk | Effort | Blocking | Dependency | Status |
|---|---|---|---|---|:---:|:---:|:---|:---|
| A001 | Inference authority | Multiple generate paths (`generate()`, `generateUnified()`, server paths) may diverge | Critical | Correctness / Maintainability | M | Yes | — | Open |
| A002 | Fallbacks | Fallback after partial GPU/hybrid execution (merged with A015). Fixed in `forwardTokenAllLayers` for all four lanes; other strict-only sites unaudited | Critical | Correctness | M | Yes | A001 | Source fixed + compiles; runtime NOT_RUN |
| A003 | RMSNorm GPU | Resident RMS dispatch fails at layer 55 (`rms_ffn`) and layer 1 (`rms_attn`) on retry | Critical | Correctness / Performance | L | Yes | A001 | Open; not reproduced in audit sessions 1-2 |
| A004 | Q2_K decode | Dequantized weight range is implausible (±3.6M); scale/min decoding suspect | Critical | Correctness | L | Yes | A001 | Open; not reproduced in audit sessions 1-2 |
| A005 | Q4_K Vulkan GEMV | Needs GPU oracle parity vs CPU reference | Critical | Correctness | L | Yes | A003 | Open |
| A006 | Q6_K Vulkan GEMV | Needs GPU oracle parity vs CPU reference | Critical | Correctness | L | Yes | A003 | Open |
| A007 | Config flags | 40+ env vars (`DEEP2_*`, `RAWRXD_*`) with overlapping semantics; strict/fallback conflicts possible | High | Maintainability | M | No | A001 | Open |
| A008 | Duplicate math | RMSNorm exists in `Deep2Engine.cpp` (CPU), `vulkan_compute.cpp` (GPU), `Deep2Engine_Speculative.cpp` (batch) | High | Maintainability / Correctness | M | No | A001 | Open |
| A009 | Duplicate math | GEMV kernels exist in `QuantKernelRegistry.cpp`, `vulkan_compute.cpp`, MASM stubs | High | Maintainability / Correctness | L | No | A001 | Open |
| A010 | Duplicate math | Tokenizer may exist in both Deep2 and Sovereign/IDE paths | Medium | Maintainability | S | No | A001 | Open |
| A011 | Test coverage | No dedicated RMSNorm GPU parity test | High | Correctness | S | No | A003 | Open |
| A012 | Test coverage | No dedicated Q4_K GPU GEMV parity oracle | High | Correctness | S | No | A005 | Open |
| A013 | Test coverage | No dedicated Q6_K GPU GEMV parity oracle | High | Correctness | S | No | A006 | Open |
| A014 | Logging | Debug and certification logs mixed; no structured receipt format | Medium | Maintainability | S | No | — | Open |
| A015 | GPU fallback | Duplicate of A002 | — | — | — | — | A002 | Merged into A002 |
| A016 | Struct layout | `block_q2_K` in `QuantKernelRegistry.hpp` (84 bytes) vs `gguf_dml_bridge.cpp` layout (scales[16]+qs[64]+d+dmin) — need `pragma pack` verification | High | Correctness | S | No | A004 | Open |
| A017 | Build targets | `QuantKernelRegistry_out.cpp`: unbuilt, older, non-identical copy | Low | Maintainability | S | No | — | Closed (deleted, Session 2) |
| A018 | Dead code | `vulkan_compute_tmp.cpp`: unbuilt Sep 16 snapshot | Low | Maintainability | S | No | — | Closed (deleted, Session 2) |
| A019 | Legacy paths | IDE benchmark may route through `SimpleEngine` or `LegacyEngine` instead of `Deep2Engine` | High | Correctness | M | No | A001 | Open |
| A020 | Agentic loop | Agent layer stub cleanup (A01–A10) deferred until GPU correctness proven | Medium | Maintainability | M | No | A003 | Open |
| A021 | Q2_K MASM | 72-byte `sovereign_q2_k_gemv.asm` vs 84-byte GGUF block | High | Correctness | S | No | — | Closed (removed from build, wrapper deleted, `static_assert(84)`, Session 2) |
| A022 | Q2_K shader | `gemv_q2k.spv` required by the 84-byte product route does not exist; CMake builds no Deep2 shaders (25 `.comp` never compiled) | High | Correctness | M | Yes (Q2_K) | — | Open |
| A023 | Build | `InferenceEngine` and every target linking it fail. Session 2 fixed the Deep2-side causes (missing `forwardTokenAllLayers` decl, `VulkanCompute` alias clash, missing `rawrxd_filter_missing_sources` function, wrong std includes). 195 errors remain in non-Deep2 sources | Critical | Build | M | Yes | A001 | Open (Session 2B) |
| A024 | CLI | `rawr` target omits `rawrxd_run_modelname_001.cpp` (link error); option off by default; no EOS stop, per-token debug prints, success reported on 0 tokens, no chat template/manifest lookup/REPL | High | Product | M | No | A023 | Open (Session 3) |
| A025 | Stale copies | `src/deep2/Q.txt`, `Deep2Engine*.bak`, `vulkan_compute*.h` variants | Low | Maintainability | S | No | — | Open (candidates only) |
| A026 | Dead code | 55 non-vendored `#if 0` blocks | Low | Maintainability | S | No | — | Closed (Session 2; `ssot_handlers_ext.cpp` not compile-verified) |

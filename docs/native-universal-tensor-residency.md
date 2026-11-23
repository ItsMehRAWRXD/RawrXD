# Native Universal Tensor Residency

## Design contract

RawrXD does not rewrite a model's GGUF payload to obtain runtime memory savings. GGUF remains the interchange/source format. The Deep2 runtime keeps source tensors paged, optionally admits profitable private compressed representations into bounded residency caches, and materializes only requested inference tiles.

The runtime must never select an encoding unless its decoder is implemented and the required error contract is satisfied. Unsupported GGUF type IDs fail closed; no byte stride or bit layout is inferred from a name.

## Storage paths

| Source type | Resident representation | Inference materialization |
|---|---|---|
| F32 | Bounded chunked adaptive representation (lossless RLE/LZ4 by default; optional error-bounded F16/BF16) | Requested F32 chunk/tile |
| F16, BF16, F64 | Original encoded bytes in the bounded ROM pager; optional lossless RLE/LZ4 byte residency when a chunk wins | Requested F32 tile |
| Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1, IQ4_NL, IQ4_XS, MXFP4 | Canonical GGML blocks; optional lossless RLE byte residency only when smaller | Requested block-aligned F32 tile |
| Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K | Canonical GGML super-blocks; optional lossless RLE byte residency only when smaller | Requested 256-value-block-aligned F32 tile |
| I8, I16, I32, I64 | Original exact integer bytes; optional lossless RLE byte residency when smaller | Requested F32 tile for current floating-point inference kernels |

The encoded-byte residency cache uses lossless RLE/LZ4 chunks and is deliberately lossless: a quantized payload is never quantized a second time merely to make it smaller. Chunks that do not produce a net saving stay on the source pager path. After successful cache admission, corresponding unleased source pages are evicted to avoid retaining a duplicate raw copy.

## Configuration

- `DEEP2_ROM_CACHE_BYTES`: source-page cache capacity.
- `DEEP2_F32_MAX_ABS_ERROR`: optional finite, nonnegative absolute error allowance for F32-to-F16/BF16 private residency. Default is `0` (lossless only). This setting does not alter GGUF files.
- F32 and encoded-byte residency budgets are selected from currently available physical RAM at engine initialization (F32: one eighth, capped at 2 GiB; encoded bytes: one thirty-second, capped at 512 MiB, with conservative minimums).
- `DEEP2_F32_RESIDENCY_MB` and `DEEP2_ENCODED_RESIDENCY_MB` override the respective budgets in MiB. Invalid or overflowing values are ignored in favor of the computed default.
- `DEEP2_F32_CACHE_BYTES` and `DEEP2_ENCODED_CACHE_BYTES` provide exact byte-count overrides and take precedence over the MiB settings. Invalid values fail initialization rather than silently selecting an unexpected memory budget.

The engine exposes `GetTensorResidencySnapshot()` for compressed/logical bytes, source-pager resident bytes and capacity, tensor counts, cache hits/misses, decoded bytes and evictions. The snapshot's total-resident value counts compressed cache bytes plus source-pager resident bytes once.

## Current kernel integration

ROM F32, floating and supported quantized 2-D projection weights use bounded row tiles. For Vulkan, each requested tile is decoded on the CPU, uploaded as F32, and dispatched through the existing Vulkan GEMV path. This avoids a full-matrix F32 allocation but is **not** GPU-native decompression.

## Deliberate limitations / remaining certification

- IQ-family, TQ-family, MXFP4, NVFP4, and other GGUF formats not listed above remain unsupported by this Deep2 ROM decoder. The loader rejects unknown type IDs rather than guessing.
- GPU-side decode kernels and persistent compressed GPU weight residency are not implemented by this change.
- Every production operator must be audited for use of the tiled ROM path; this document does not claim universal operator coverage.
- CI must pass on Windows and Linux, followed by reference-logit parity, peak host/VRAM measurement, and multi-agent stress tests before release certification.

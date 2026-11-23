# Native compressed weight residency

## Goal

The runtime compression path is distinct from writing a smaller GGUF file. A loaded tensor can remain in the compressed-weight store for the lifetime of a model request or model session. Readers request byte ranges; the store decodes only the blocks intersecting that range and enforces its decoded-cache budget.

## Ownership and lifecycle

1. The GGUF loader validates tensor metadata and exposes mapped tensor bytes.
2. The compressed model owner admits tensors into the compressed store transactionally. A failed admission does not replace the previously published model.
3. The store retains compressed blocks and their integrity metadata. A bounded `readRange` reconstructs only the requested logical byte interval.
4. The model owner can release the original GGUF mapping after all tensor data needed by the compressed model has been admitted.
5. Inference obtains temporary row/vector windows. Those windows are request-scoped and are not retained as full decoded tensors.

Lossless byte-preserving storage is the default. F32-to-F16 conversion is a separate, explicitly opt-in admission policy controlled by `RAWRXD_COMPRESSED_WEIGHT_F32_TO_F16=1`; it is lossy and must be validated against the model's numerical acceptance thresholds.

## CPU and GPU execution

- CPU row matvec consumes bounded tensor ranges and stages only the requested rows.
- RMSNorm reads only its required scale vector.
- The legacy linear projection path uses bounded 32-row windows for compressed-backed tensors.
- The canonical Vulkan forward path (`Deep2Engine_GpuForward.cpp`) now streams compressed-only packed, F32, and F16 weights in 32-row windows.
- Packed tiles are sent to the quantized GEMV shader without first expanding the whole tensor to F32.
- F32 tiles are uploaded as one-shot F32 windows. F16 tiles are decoded to F32 one tile at a time because the current canonical forward kernels consume F32 activations/weights for this path.
- Each one-shot weight dispatch is fence-completed before its temporary device weight allocation is reclaimed. The forward path stages tile outputs and publishes the full activation only after every tile succeeds.
- The fused layer command buffer is completed before the tiled projection begins and reopened afterward. Compressed streaming is rejected when the caller does not own the fused recording; it must not silently fall back to a full-tensor GPU staging allocation.

The tile size is currently 32 output rows. This is a correctness-oriented bounded default, not a claim that 32 is optimal for every GPU. Future tuning must preserve a hard memory ceiling and be validated on each backend.

## Decoder-only compressed runtime and grouped-query attention

The synthetic CompressedTransformerRuntime executes a complete decoder-only token path using only compressed-store range reads and bounded matrix projections: token embedding, pre-attention RMSNorm, Q/K/V, RoPE, causal attention, attention output projection, residual, pre-FFN RMSNorm, SwiGLU, down projection, final RMSNorm, and vocabulary logits. Autoregressive generation owns its KV state per request and checks context and cache-byte limits before allocating it.

The runtime now supports grouped-query attention (GQA) as well as ordinary multi-head attention. Config::kv_heads == 0 preserves the multi-head default; otherwise the KV-head count must evenly divide the query-head count. K/V projection geometry is kv_heads * head_dim, while Q and attention output remain heads * head_dim. Query heads map to a KV head by their contiguous group index. RoPE is applied to Q and K using their respective head counts.

The KV-cache budget is calculated from the actual K/V width (layers * tokens * kv_heads * head_dim * 2 * sizeof(float)), rather than charging GQA as if every query head had a separate K/V state. The synthetic regression exercises two query heads sharing one KV head, validates compact-cache admission at the exact byte budget, rejects a one-byte-under budget, and rejects a KV-head count that does not divide the query-head count.

This is a deterministic architectural execution contract, not proof that every production GGUF architecture has been mapped correctly. Architecture-specific tensor names, RoPE variants/scaling, sliding-window policies, MLA, MoE, quantized K/V caches, and the production Vulkan lane remain separate integration and parity gates.

## What is not yet certified

- The CI suite must compile the canonical GPU forward translation unit on Windows and Linux.
- Vulkan numerical parity must be independently measured on actual supported hardware, including the user's Radeon devices.
- Peak host memory, peak device memory, temporary staging, and KV-cache usage must be measured during a real multi-token model run.
- Device-loss recovery, cancellation, concurrent model requests, and multi-agent inference require sustained end-to-end tests.
- Not every architecture or tensor type is covered by the synthetic decoder fixture. Unsupported shapes/types must reject the GPU path and use the independently validated fallback rather than guessing at geometry.

## Validation contract

A release claim requires all of the following:
1. Exact byte roundtrips and corruption/bounds tests for the compressed store.
2. Synthetic GGUF load, source-map release, and inference tests.
3. Row-tile tests that assert requested offsets and maximum decoded window size.
4. Independent CPU reference comparisons for F32, F16, and each supported quant type.
5. Vulkan tests that confirm no full compressed tensor is uploaded or retained for a one-shot compressed projection.
6. Peak-memory measurements demonstrating the intended reduction.
7. Full native IDE/inference build, regression suite, and release certification.

Passing the storage and synthetic tests alone does not establish production parity.

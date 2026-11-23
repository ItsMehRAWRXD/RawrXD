# Compressed Weight Residency in Deep2

## Runtime activation

Compressed matrix residency is opt-in:

```powershell
$env:RAWRXD_COMPRESSED_WEIGHT_RESIDENCY = "1"
$env:RAWRXD_COMPRESSED_WEIGHT_BUDGET_MB = "4096"
```

Unset `RAWRXD_COMPRESSED_WEIGHT_RESIDENCY` to preserve the existing mapped-weight execution path.

The budget is the maximum encoded host-resident payload admitted by the single-shard loader. The default is 4096 MiB. A tensor is admitted only when its exact packed GGML row geometry is known and the encoded representation is smaller than the source. Failed admission leaves the original mapped view active.

## Optional F32-to-F16 reduction

A separate, explicitly lossy conversion can halve eligible F32 projection payloads before block compression:

```powershell
$env:RAWRXD_COMPRESSED_WEIGHT_F32_TO_F16 = "1"
```

This setting has no effect unless compressed residency is enabled. It applies to eligible F32 linear projections and single-shard token embeddings, plus projections in the standard multi-shard binding path, with validated row geometry. Conversion is performed in bounded reader blocks using round-to-nearest-even, stores the resulting tensor as GGML F16, and updates the runtime weight type and byte geometry before kernel dispatch. If conversion admission fails, the loader retries the byte-preserving F32 path.

F32-to-F16 can change model outputs. It is disabled by default and must be validated with teacher-forced logits and task-quality tests before production use. Byte-preserving compression remains the default.

## What is compressed

The single-shard path selects two-dimensional linear projections routed through `LinearW` (attention/FFN projections and output projection) plus token embeddings. Token lookup decodes only the requested packed embedding row. The standard multi-shard binding path uses the same opt-in admission rules for compatible matrix projections; its token embeddings continue through the existing shard-row reader.

The default payload is stored byte-exactly. GGML type IDs and quantized block layouts are retained. Only when `RAWRXD_COMPRESSED_WEIGHT_F32_TO_F16=1` is explicitly set are eligible F32 linear matrices and token embeddings converted to F16; other supported formats remain byte-exact.

The following are deliberately not admitted by the single-shard path yet:

- Token embeddings, whose lookup path still requires direct mapped access.
- Norms, biases, and other vectors whose scalar consumers still dereference the raw pointer.
- Three-dimensional expert tensors and unsupported/ambiguous row geometries.
- Any tensor whose compression does not produce actual byte savings.

## Inference behavior

For an admitted linear matrix, `WeightTensor` retains a shared compressed-store/key pair and has no raw data pointer. `LinearW_Range` calculates the packed bytes per row from the GGML type and decodes only the worker's requested output-row range into bounded temporary storage. Token embedding lookup similarly decodes only the selected token row. The quantized kernel receives the stored packed bytes; byte-preserving mode therefore leaves numerical semantics unchanged.

The existing Vulkan GEMV upload interface consumes a full contiguous tensor. To prevent a hidden full-tensor decompression from defeating compressed residency, compressed weights use the bounded CPU row-slice path by default. Full-tensor Vulkan staging is an explicit opt-in:

```powershell
$env:RAWRXD_COMPRESSED_WEIGHT_GPU_STAGING = "1"
```

That override restores the existing full-tensor GPU staging behavior and should be used only when the temporary expansion is acceptable. It is not the memory-minimizing mode.

Elastic residency does not replace an admitted compressed backing with a raw pointer. Other uncompressed tensors continue through their existing residency paths.

## Lifecycle

The compressed store is shared by model weight views. Model unload first clears all `WeightTensor` aliases, then resets the compressed store and releases the GGUF loader. GGUF tensor payload pointers alias the loader's mapped shard; they are not individual allocations and must not be passed to `GGUFLoader::FreeTensorData`. The loader owns the mapping and closes it through RAII.

The GGUF mapping remains alive during the loaded model because vectors/norms and the tokenizer/metadata compatibility path still use mapped views. Compressed matrix views do not use their original raw pointer during inference. Consequently, the current implementation reduces active matrix-weight decode working sets and can leave unused mapped pages reclaimable by the OS, but it does not yet unmap the entire GGUF source while a model is loaded.

## Validation gates

The compressed store has focused tests for byte-exact roundtrips, F16/F32/Q8_0 resident matvec, cross-block reads, bounded reader ingestion, failure rollback, admission budgets, and decoded-cache behavior. The zlib core has a separate roundtrip/corruption/output-ceiling smoke test.

Still required on the target Windows toolchain and actual model corpus:

1. Build with ZLIB detected and with ZLIB unavailable.
2. Run the full CTest suite.
3. Run single-shard Qwen/Llama/Gemma inference with compression enabled and compare teacher-forced logits against the uncompressed path.
4. Measure peak private bytes, working set, mapped-file residency, encoded bytes, decoded cache bytes, and per-layer latency.
5. Validate GPU staging separately with `RAWRXD_COMPRESSED_WEIGHT_GPU_STAGING=1`.
6. Extend compressed access to token embeddings, vector/norm consumers, expert tensors, and Vulkan block/range upload before claiming full model residency coverage.

No production certification or full-GPU-parity claim is made by this implementation.

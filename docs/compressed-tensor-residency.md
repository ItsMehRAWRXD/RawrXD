# Compressed tensor residency

`TensorROMCompressedView` adds an opt-in compressed host-residency layer over an existing `TensorROM` tensor. It does not rewrite GGUF files and does not change tensor types, quantization metadata, or arithmetic.

## Example

```cpp
#include "TensorROMCompressedView.hpp"

const deep2::TensorEntry* weight = rom.findTensor("blk.0.attn_q.weight");
if (!weight) { /* handle missing tensor */ }

deep2::TensorROMCompressedView view(rom, *weight, 256 * 1024, 64 * 1024 * 1024);
std::vector<uint8_t> staging(requestedBytes);
if (!view.readRange(tensorOffset, staging.size(), staging.data())) {
    // Treat as a hard weight-read failure; do not submit partial data.
}
```

The `TensorROM`, its tensor entry, and referenced shard files must remain alive while the view is used. The caller owns the staging allocation and must retain it until its GPU transfer fence completes.

## Memory and correctness properties

- Source ranges are fetched on cache misses. Pages are retained compressed when zlib makes them smaller; incompressible pages remain raw.
- The resident budget accounts for encoded page payloads. Temporary source and decompression buffers are bounded by page size.
- Reads validate the entire logical range before fetching data.
- Failed source reads or inflate operations return `false`; callers must not submit partial data as valid weights.
- This is lossless byte compression. It does not convert F32 to FP16 or alter quantized tensor encodings. Precision-changing transforms require tensor-type-aware conversion and independent numerical acceptance tests.
- This adapter is opt-in. Inference code must explicitly use the view and route staging bytes to its CPU/GPU consumer. It does not yet replace all TensorROM reads or modify Vulkan buffer ownership.

## Standalone regression target

```powershell
cmake -S tests/compressed_tensor_pager -B build/compressed-tensor-pager
cmake --build build/compressed-tensor-pager --config Release
ctest --test-dir build/compressed-tensor-pager -C Release --output-on-failure
```

A passing standalone test does not establish full-model parity, Vulkan synchronization correctness, or end-to-end RAM/VRAM savings. Measure those separately on the target runtime.

## Vulkan staging bridge

`VulkanStagingPipeline::populate_staging_buffer` accepts an exact-range reader and fills an acquired mapped staging slot. A compressed tensor view can be supplied without changing tensor encodings:

```cpp
auto slot = StagingSlot{};
if (!pipeline.acquire_staging_buffer(bytes, slot)) return false;
const bool populated = pipeline.populate_staging_buffer(slot, bytes,
    [&](uint8_t* dst, size_t count) {
        return compressedView.readRange(tensorOffset, count, dst);
    });
if (!populated) { pipeline.release_staging_buffer(slot); return false; }
if (!pipeline.enqueue_asynchronous_dma(queue, commandBuffer, slot, deviceBuffer, bytes)) {
    pipeline.release_staging_buffer(slot);
    return false;
}
// IMPORTANT: retain the slot until the submission is known complete. The current
// API does not create/return a fence; the caller must synchronize using its own
// fence or queue-idle policy before release_staging_buffer().
```

The bridge only fills the host-visible upload buffer. It does not make compressed bytes directly consumable by shader kernels: bytes are expanded into the upload slot before DMA, then copied to the destination GPU buffer. To keep GPU VRAM compressed, a shader-side codec and kernel integration would be required. This path can reduce host-side weight residency; it does not yet prove lower VRAM residency.

## Deep2Engine adoption

The ROM-mode `Deep2Engine::dequantTensor` path now obtains a persistent `TensorROMCompressedView` per recently used tensor. The view reads exact byte ranges directly from the shard file, bypassing `PageCache` so the same pages are not intentionally retained both raw and compressed. The engine maintains an eight-entry LRU; each view has an 8 MiB encoded-page budget (64 MiB maximum encoded cache payload across the eight retained views). View creation/eviction is synchronized, and a local shared reference protects a view during concurrent use. Shutdown clears views before the ROM is torn down.

The current dequantization API still materializes the complete encoded tensor into a temporary staging vector before converting it to F32. Therefore this integration establishes persistent compressed host-side page residency and removes the duplicate raw PageCache path for this operation, but it does **not** yet provide per-kernel sub-tensor decompression or eliminate the full-tensor transient allocation. That requires block-aware quantization/dequantization consumers.

`TensorROM::readShardRange` now serializes access to the shared `ifstream` and rejects short/out-of-range reads instead of zero-padding them. This is required because the compressed pager's source callback must be exact.

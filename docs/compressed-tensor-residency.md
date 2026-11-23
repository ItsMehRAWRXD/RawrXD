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

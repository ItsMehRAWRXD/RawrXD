# Bounded compressed-source tensor dequantization

## What changed

The ROM-mode Deep2 path now exposes `Deep2Engine::dequantTensorRange(entry, firstElement, elementCount, output)`. It reads only the byte intervals needed for the requested logical element range through the persistent `TensorROMCompressedView`, then dequantizes bounded chunks. The existing `dequantTensor` convenience API now uses this range path for a full-tensor result, avoiding a full encoded-tensor staging allocation.

The lower-level `deep2::dequantizeTensorRange` accepts a byte-range reader, so CPU/GPU consumers can request a row, tile, or block-aligned segment without first materializing the entire encoded tensor.

## Alignment and supported formats

- F32 and F16 accept arbitrary element offsets.
- Q8_0 requires 32-value alignment.
- Existing implemented K-quant formats require 256-value alignment.
- The decoder delegates each chunk to the existing `dequantizeTensor` implementation. It therefore supports only formats that implementation currently supports; unsupported GGUF quant types fail closed.
- The default staging chunk is 4096 values and is rounded down to a whole quantization block.

The reader callback receives exact byte offsets and byte counts. Failed or incomplete reads fail the operation; no zero-filled substitute data is returned.

## Memory behavior

The encoded staging allocation is bounded by the configured chunk size (plus one compressed pager page expansion at a time). The persistent compressed pager remains bounded by its configured per-view cache budget and the engine's eight-entry view LRU. The returned `output` vector is still proportional to the requested number of F32 values; callers seeking true tile-level memory bounds must request a tile/range rather than the full tensor.

This is a CPU-side range-dequantization primitive. It does not yet implement a Vulkan-native compressed GEMV kernel, device-side decompression, or zero-copy compressed GPU residency. GPU consumers must explicitly stage the returned decoded range.

## Regression test

`test_compressed_range_dequant` validates:
- exact bounded F32 source reads across multiple chunks;
- Q8_0 block-aligned partial decoding;
- rejection of misaligned quantized ranges;
- rejection of out-of-range requests and reader failures.

Build and run with the normal project CMake configuration:

```sh
cmake -S . -B build
cmake --build build --target test_compressed_range_dequant
ctest --test-dir build -R compressed_range_dequant --output-on-failure
``

The repository update itself does not constitute a successful local C++ build; run the commands above on the target Windows/MSVC and Vulkan environment before promoting this path.

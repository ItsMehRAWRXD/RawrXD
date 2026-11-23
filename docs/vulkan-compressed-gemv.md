# Tiled Vulkan GEMV over compressed ROM weights

## Runtime path

`Deep2Engine::vulkanGemvCompressed` connects the compressed TensorROM range reader to the existing F32 Vulkan GEMV shader:

1. Validate logical matrix geometry and quantization-block row alignment.
2. Allocate reusable host-visible Vulkan storage buffers sized for one bounded row tile, the input vector, and tile output.
3. Request only the selected row range through `dequantTensorRange`.
4. Expand that range to F32, copy it into the mapped weight tile, and dispatch the existing `shaders/gemv_f32.spv` compute program.
5. Copy tile output into the result vector and reuse the same bounded buffers for the next tile.
6. Release buffers and mapped memory when complete.

The default tile is 16 rows. Maximum tile rows are additionally capped by the device's `maxStorageBufferRange`. The full encoded weight matrix is never staged in host memory by this API. The full result vector and input vector are still resident.

## Integration

The ROM execution smoke path now computes a CPU reference from only the first 16 rows, then runs tiled compressed Vulkan GEMV over the complete matrix and compares the matching leading outputs with a tolerance of `1e-3 + 1e-3 * abs(reference)`.

The Vulkan buffer creation path now fails closed on bind/map errors. GEMV command recording, submission, and fence completion errors propagate as failure rather than reporting a successful dispatch.

## Constraints

- This path uses the existing F32 GEMV SPIR-V shader. Decompression and quantized decoding remain CPU-side; this is not a Vulkan-native quantized/decompression kernel.
- The encoded row width must be aligned to the quantization block size. Misaligned row geometry is rejected instead of reading across incorrect block boundaries.
- Only quantization formats already supported by `dequantizeTensorRange` work here.
- The F32 decoded weight working set is bounded by one tile, but the returned output vector remains proportional to matrix rows.
- This implementation uses synchronous dispatch and host-visible coherent memory. Device-local staging, transfer queues, async overlap, and multi-device scheduling remain follow-on optimizations.
- The shader binary must exist at `shaders/gemv_f32.spv` beside the executable.

## Validation required on target hardware

Run the native Release build and ROM execution smoke on the AMD Vulkan devices. Confirm:
- each tile dispatch completes without Vulkan errors;
- CPU/GPU leading-row parity passes;
- peak transient host decoded weight memory does not exceed the configured tile size;
- full matrix output matches an independent reference on representative F16 and supported quantized GGUF tensors.

No hardware build or runtime test was executed by the GitHub editing environment; this PR must remain unpromoted until those checks pass.

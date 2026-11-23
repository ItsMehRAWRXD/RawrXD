# Native compressed-residency primitives

This change adds a dependency-free C++17 compressed-weight storage path. It is a runtime storage primitive, not a GGUF wire-format rewrite.

## Data flow

1. `FileTensorReader` opens a bounded byte range inside a GGUF/model file and streams it in fixed-size blocks.
2. `encode` selects byte RLE only when the encoded block is strictly smaller; otherwise it retains the exact raw bytes.
3. `ResidentCompressedTensor` retains encoded blocks and releases each temporary source block after admission. It does not retain a full uncompressed tensor.
4. `read(offset, destination, length)` reconstructs only the requested range. RLE ranges are expanded directly into the destination without materializing a full block.
5. `BoundedWeightStager` limits each kernel-facing decode to a caller-selected scratch budget.
6. Typed resident GEMV consumes F32, F16, Q4_0, or Q8_0 matrices row-by-row using bounded staging; quantized blocks are decoded directly into the accumulator and never expanded into a full F32 matrix.

## Correctness and safety contracts

- RLE is lossless. Raw fallback is always exact.
- Invalid ranges are rejected before destination writes.
- RLE run counts, decoded lengths, file bounds, and matrix geometry are checked.
- Incompressible blocks remain raw; no expansion is retained as a "compressed" representation.
- The cache returns caller-owned bytes and does not expose pointers that can outlive an eviction.
- The file reader serializes seek/read through its owned stream; do not share one reader concurrently without external synchronization.
- Asynchronous GPU transfers must copy into an owned staging allocation and retain it until the completion fence signals. The synchronous stager callback's pointer is ephemeral.

## Scope boundary

The ROM forward path now routes 2-D QKV, FFN up/down, and output projections of type F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, and Q8_1 through the shared compressed-resident store and bounded CPU GEMV. Its token embedding lookup now reads only the selected byte range from the GGUF shard, compresses/caches that row under the same bounded LRU budget, and decodes that row for F32/F16/Q4_0/Q4_1/Q5_0/Q5_1/Q8_0/Q8_1. A large vocabulary matrix is never loaded or compressed in full merely to fetch one embedding row. The independent dequantization reference now implements the standard GGML Q4_0 layout and standard Q8_0 layout (fp16 scale first, followed by signed int8 values), plus standard Q4_1/Q5_0/Q5_1/Q8_1 block layouts (including the 36-byte Q8_1 block), and converts binary16 subnormals without exponent underflow. F32/F16 decode only the requested row fragments; Q4_0/Q4_1/Q5_0/Q5_1/Q8_0/Q8_1 decode only packed quant blocks. Unsupported types retain the explicit dequantization fallback. This is not universal operator coverage: attention/state vectors, embeddings, MoE expert routing, other quantized types, and Vulkan shaders still need typed integration and independent parity tests.

It also does not claim a fixed memory reduction ratio. Incompressible data remains raw, metadata and vector capacity count toward residency, and the source file mapping may still occupy the OS page cache. Measure compressed payload, retained allocation, process working set, and GPU allocations separately.

## Build and test

The root CMake project now registers eight regression targets, including the quant-kernel reference test:
- `native_compressed_residency_test`
- `native_compressed_tensor_test`
- `native_file_tensor_reader_test`
- `native_resident_compressed_tensor_test`
- `native_bounded_weight_stager_test`
- `native_resident_f32_matvec_test`
- `native_resident_typed_matvec_test` (F16/Q4_0/Q4_1/Q5_0/Q5_1/Q8_0/Q8_1 plus GGUF byte-geometry checks)
- `native_quantized_dequant_test` (independent Q4_0/Q8_0 known answers, F16 subnormal, truncated block, and overflow rejection)

They compile as C++17 and do not require Vulkan, Qt, or model downloads. The dedicated GitHub Actions workflow compiles and runs the header-only residency tests plus the linked quant-kernel reference test directly on Linux and Windows.

## Next integration gates

1. Wire `ResidentCompressedTensor` into the real GGUF tensor owner with stable shard/tensor identity and lifetime control.
2. Extend typed quantized readers to Q4_1/Q5_0/Q5_1, K-quants and other GGML types, each with independent known-answer fixtures.
3. Migrate embeddings, norms, attention/state vectors, and MoE expert consumers to bounded typed range reads.
4. Add Vulkan upload ownership with completion-backed staging and device-local cache eviction for each supported quant type.
5. Add independent teacher-forced logits parity, multi-agent concurrency, cancellation, corruption, and measured host/VRAM tests before promoting the path.

# Native compressed-residency primitives

This change adds a dependency-free C++17 compressed-weight storage path. It is a runtime storage primitive, not a GGUF wire-format rewrite.

## Data flow

1. `FileTensorReader` opens a bounded byte range inside a GGUF/model file and streams it in fixed-size blocks.
2. `encode` selects byte RLE only when the encoded block is strictly smaller; otherwise it retains the exact raw bytes.
3. `ResidentCompressedTensor` retains encoded blocks and releases each temporary source block after admission. It does not retain a full uncompressed tensor.
4. `read(offset, destination, length)` reconstructs only the requested range. RLE ranges are expanded directly into the destination without materializing a full block.
5. `BoundedWeightStager` limits each kernel-facing decode to a caller-selected scratch budget.
6. `resident_f32_matvec` consumes an F32 matrix row-by-row using bounded staging; accumulation is in double and the output is F32.

## Correctness and safety contracts

- RLE is lossless. Raw fallback is always exact.
- Invalid ranges are rejected before destination writes.
- RLE run counts, decoded lengths, file bounds, and matrix geometry are checked.
- Incompressible blocks remain raw; no expansion is retained as a "compressed" representation.
- The cache returns caller-owned bytes and does not expose pointers that can outlive an eviction.
- The file reader serializes seek/read through its owned stream; do not share one reader concurrently without external synchronization.
- Asynchronous GPU transfers must copy into an owned staging allocation and retain it until the completion fence signals. The synchronous stager callback's pointer is ephemeral.

## Scope boundary

This first integration batch supplies file-backed compressed residency, bounded range reconstruction, and a CPU F32 matvec reference path. It does **not** claim that every Deep2 operator, attention path, embedding lookup, MoE expert route, or Vulkan shader has been switched to this storage representation. The existing GGUF mapping and inference paths remain authoritative until each operator is integrated and parity-tested.

It also does not claim a fixed memory reduction ratio. Incompressible data remains raw, metadata and vector capacity count toward residency, and the source file mapping may still occupy the OS page cache. Measure compressed payload, retained allocation, process working set, and GPU allocations separately.

## Build and test

The root CMake project now registers six dependency-free regression targets:
- `native_compressed_residency_test`
- `native_compressed_tensor_test`
- `native_file_tensor_reader_test`
- `native_resident_compressed_tensor_test`
- `native_bounded_weight_stager_test`
- `native_resident_f32_matvec_test`

They compile as C++17 and do not require Vulkan, Qt, or model downloads. The dedicated GitHub Actions workflow compiles and runs them directly on Linux and Windows.

## Next integration gates

1. Wire `ResidentCompressedTensor` into the real GGUF tensor owner with stable shard/tensor identity and lifetime control.
2. Replace F32 full-tensor materialization in CPU projection/embedding paths with bounded range reads.
3. Add typed quantized block readers; never reinterpret GGUF quantized bytes as F32.
4. Add Vulkan upload ownership with completion-backed staging and device-local cache eviction.
5. Add independent teacher-forced logits parity, multi-agent concurrency, cancellation, corruption, and measured host/VRAM tests before promoting the path.

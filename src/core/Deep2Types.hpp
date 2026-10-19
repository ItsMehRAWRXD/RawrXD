#pragma once
#include <windows.h>
#include <stdint.h>

#ifndef ALIGN_64
#define ALIGN_64 __declspec(align(64))
#endif

namespace Deep2Rom {
    enum class ModelArch : uint32_t {
        Phi3 = 0,
        DeepSeekMoE_671B = 1,
        Kimi_K2 = 2
    };

    #pragma pack(push, 1)
    struct alignas(64) RomHeaderMultiShard {
        uint8_t  magic[8];           // "RAWRXD2\0" Magic bytes signature
        uint32_t engine_version;     // Deep2Engine minimum required version
        uint32_t architecture_id;    // 1 = DeepSeek-R1 671B, 2 = Kimi K2, 3 = Test/Stub
        uint64_t total_rom_size;     // Total size of the flat binary footprint in bytes
        uint32_t num_layers;         // Total transformer/MoE layers count
        uint32_t num_experts;        // Total MoE experts per layer
        uint32_t top_k_experts;      // Active experts routed per token
        uint32_t hidden_dimension;   // Model hidden dimension sizing
        uint32_t kv_heads;           // Number of Key-Value attention heads
        uint64_t metadata_offset;    // Absolute binary offset to tensor lookup table
        uint32_t metadata_count;     // Total number of discrete tensors tracked
        uint32_t total_shards;       // Number of shard files in this model
        uint8_t  reserved[12];       // Pad to retain pristine 64-byte structural spacing
    };

    struct TensorDescriptorMultiShard {
        char     tensor_name[64];    // Clean identifier (e.g. "blk.0.attn_q.weight")
        uint32_t shard_id;           // Which shard file this tensor lives in (0..total_shards-1)
        uint64_t absolute_offset;    // File-backed offset to tensor data payload within its shard
        uint64_t tensor_bytes;       // Accurate size of the raw compressed block
        uint32_t dimensions[4];      // Tensor shape tracking parameters
        uint16_t quantization_type;  // Type matching masm_core dequant types (e.g. Q2_K)
        uint8_t  target_device_id;   // 0 = Host RAM, 1 = W7900 (32GB), 2 = 7800 XT (16GB)
        uint8_t  reserved[5];        // Structural padding
    };
    #pragma pack(pop)

    // The ROM container layout is a file format, not an implementation
    // detail: the writer (gguf2rom), the multi-shard converter
    // (gguf2rom_ms), the zero-copy loader (Win32RomEmulator) and the
    // multi-shard manager (MultiShardFlickerManager) all have to agree on
    // it byte for byte.
    //
    // These structs used to be defined twice, in this header and in
    // Win32RomEmulator.hpp, with different field orders and different
    // sizes. A descriptor written with one layout and read with the other
    // drifts by the size difference on every entry, so the tensor table
    // is misparsed from the second descriptor onwards and the
    // absolute_offset values read back are garbage.
    //
    // The guards below make a future divergence a compile error rather
    // than a silently corrupt ROM.
    static_assert(sizeof(RomHeaderMultiShard) == 128,
                  "RomHeaderMultiShard must be exactly 128 bytes; the ROM header layout is a file format");
    static_assert(sizeof(TensorDescriptorMultiShard) == 108,
                  "TensorDescriptorMultiShard must be exactly 108 bytes; the ROM tensor table layout is a file format");
    static_assert(offsetof(RomHeaderMultiShard, metadata_offset) == 44,
                  "metadata_offset must sit at byte 44 of the ROM header");
    static_assert(offsetof(RomHeaderMultiShard, metadata_count) == 52,
                  "metadata_count must sit at byte 52 of the ROM header");

    // The layout of DeepSeek's fused attn_kv_b matrix.
    //
    // Multi-head Latent Attention keeps the compressed latent c_kv (kvLora
    // wide) and expands it into the per-head keys and values with a single
    // up-projection matrix. llama.cpp's deepseek2.cpp expands the fused
    // matrix one row block per head: head h owns qkNope + vHead consecutive
    // rows, the first qkNope of which are that head's key and the remaining
    // vHead its value.
    //
    // The MLA absorption optimization, which projects the query through the
    // key up-projection instead and keeps the cache kvLora wide, needs the
    // *split* attn_k_b and attn_v_b tensors. A GGUF that carries the fused
    // attn_kv_b has to be expanded the interleaved way. Treating the rows as
    // if they were grouped by projection gives every head the wrong weights
    // and the attention produces NaN hidden states.
    //
    // This is a layout contract, not an implementation detail, so it lives
    // here next to the ROM layout and is covered by a regression test.
    struct MlaKvBLayout {
        uint32_t numHeads = 0;
        uint32_t qkNope   = 0;
        uint32_t vHead    = 0;
        uint32_t kvLora   = 0;

        // Rows of the fused matrix that belong to one head.
        uint32_t rowsPerHead() const { return qkNope + vHead; }
        uint32_t totalRows() const { return numHeads * rowsPerHead(); }

        // First row of head h's key, and of head h's value.
        uint32_t keyRow(uint32_t head) const { return head * rowsPerHead(); }
        uint32_t valueRow(uint32_t head) const { return head * rowsPerHead() + qkNope; }

        // Element offsets into the row-major matrix.
        uint64_t keyOffset(uint32_t head) const { return (uint64_t)keyRow(head) * kvLora; }
        uint64_t valueOffset(uint32_t head) const { return (uint64_t)valueRow(head) * kvLora; }
    };
}
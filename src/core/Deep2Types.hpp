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
        uint8_t  magic[8];       // "RAWRXD2\0"
        uint32_t engine_version;   // 100
        uint32_t architecture_id;  // ModelArch
        uint32_t total_shards;     // Total disk shards
        uint64_t total_rom_size;   // Flattened bytes size
        uint32_t num_layers;       // Total layers
        uint64_t metadata_offset;  // Offsets layout tracker
        uint32_t metadata_count;   // Total tensors
        uint8_t  reserved[20];     // Padded to hit strict 64-byte structural boundary
    };

    struct TensorDescriptorMultiShard {
        char     tensor_name[64]; // Unique string signature key
        uint32_t shard_id;         // Split identifier path index
        uint64_t absolute_offset;  // 64-bit disk address pointer
        uint64_t tensor_bytes;     // Size on disk
        uint32_t dimensions[4];    // Geometry shapes matrix
        uint16_t quantization_type;// Quant flag type (e.g., Q2_K)
        uint8_t  target_device_id; // Mapping destination tracker
        uint8_t  reserved[9];      // Padding boundary to hit strict 112-byte footprint
    };
    #pragma pack(pop)
}
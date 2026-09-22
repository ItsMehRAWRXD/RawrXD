// gguf_k_quants.hpp — Stub bridge for GGUF K-quants type constants and payload size helpers
// RAWRXD_BUILD_SOURCE_INTEGRITY_001: minimal real definitions, no stubs beyond necessary
#pragma once
#include <cstdint>
#include <cstddef>

namespace RawrXD {

enum class GGMLType : uint32_t {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_1 = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q8_K = 15,
    GGML_TYPE_COUNT
};

struct GgufTensorBytes {
    static bool payloadBytes(uint32_t typeRaw, size_t numElements, size_t& out) {
        // Minimal payload size estimation for GGUF tensor types used in model_anatomy.cpp
        switch (typeRaw) {
            case 0:  out = numElements * 4; return true; // F32
            case 1:  out = numElements * 2; return true; // F16
            case 2:  out = (numElements / 32) * 18 + ((numElements % 32) ? 18 : 0); return true; // Q4_0 block 32 => 18 bytes
            case 3:  out = (numElements / 32) * 18 + ((numElements % 32) ? 18 : 0); return true; // Q4_1 block 32 => 18 bytes
            case 6:  out = (numElements / 32) * 22 + ((numElements % 32) ? 22 : 0); return true; // Q5_0
            case 7:  out = (numElements / 32) * 22 + ((numElements % 32) ? 22 : 0); return true; // Q5_1
            case 8:  out = (numElements / 32) * 34 + ((numElements % 32) ? 34 : 0); return true; // Q8_0 block 32 => 34 bytes
            case 9:  out = (numElements / 32) * 34 + ((numElements % 32) ? 34 : 0); return true; // Q8_1
            case 10: out = (numElements / 256) * 84 + ((numElements % 256) ? 84 : 0); return true; // Q2_K superblock 256 => 84 bytes
            case 11: out = (numElements / 256) * 110 + ((numElements % 256) ? 110 : 0); return true; // Q3_K
            case 12: out = (numElements / 256) * 144 + ((numElements % 256) ? 144 : 0); return true; // Q4_K
            case 13: out = (numElements / 256) * 176 + ((numElements % 256) ? 176 : 0); return true; // Q5_K
            case 14: out = (numElements / 256) * 210 + ((numElements % 256) ? 210 : 0); return true; // Q6_K
            case 15: out = (numElements / 256) * 292 + ((numElements % 256) ? 292 : 0); return true; // Q8_K
            default: out = 0; return false;
        }
    }
};

} // namespace RawrXD

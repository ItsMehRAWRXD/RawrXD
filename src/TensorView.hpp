#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <limits>

namespace deep2 {

// GGUF quantization type codes (match the GGUF/ggml enum: F32=0, F16=1, Q4_0=2 ... Q6_K=18).
enum class TensorType : uint32_t {
    F32   = 0,
    F16   = 1,
    Q4_0  = 2,
    Q4_1  = 3,
    Q5_0  = 6,
    Q5_1  = 7,
    Q8_0  = 8,
    Q8_1  = 9,
    Q2_K  = 10,
    Q3_K_S= 11,
    Q3_K_M= 12,
    Q3_K_L= 13,
    Q4_K_S= 14,
    Q4_K_M= 15,
    Q5_K_S= 16,
    Q5_K_M= 17,
    Q6_K  = 18,
};

inline const char* tensorTypeName(TensorType t) {
    switch (t) {
        case TensorType::F32:   return "F32";
        case TensorType::F16:   return "F16";
        case TensorType::Q4_0:  return "Q4_0";
        case TensorType::Q4_1:  return "Q4_1";
        case TensorType::Q5_0:  return "Q5_0";
        case TensorType::Q5_1:  return "Q5_1";
        case TensorType::Q8_0:  return "Q8_0";
        case TensorType::Q8_1:  return "Q8_1";
        case TensorType::Q2_K:  return "Q2_K";
        case TensorType::Q3_K_S:return "Q3_K_S";
        case TensorType::Q3_K_M:return "Q3_K_M";
        case TensorType::Q3_K_L:return "Q3_K_L";
        case TensorType::Q4_K_S:return "Q4_K_S";
        case TensorType::Q4_K_M:return "Q4_K_M";
        case TensorType::Q5_K_S:return "Q5_K_S";
        case TensorType::Q5_K_M:return "Q5_K_M";
        case TensorType::Q6_K:  return "Q6_K";
        default:                return "UNKNOWN";
    }
}

// Bytes of storage per single value for fixed-width types; quantized K-types return the
// block-average (e.g. Q4_K_S ~ 0.56 bytes/value including overhead).
inline double tensorTypeBytesPerValue(TensorType t) {
    switch (t) {
        case TensorType::F32: return 4.0;
        case TensorType::F16: return 2.0;
        case TensorType::Q8_0: return 1.0;
        case TensorType::Q8_1: return 1.25;
        case TensorType::Q4_0:
        case TensorType::Q4_1: return 0.5;
        case TensorType::Q2_K: return 0.25;
        case TensorType::Q3_K_S:
        case TensorType::Q3_K_M:
        case TensorType::Q3_K_L: return 0.375;
        case TensorType::Q4_K_S:
        case TensorType::Q4_K_M: return 0.5;
        case TensorType::Q5_K_S:
        case TensorType::Q5_K_M: return 0.625;
        case TensorType::Q6_K: return 0.75;
        default: return 1.0;
    }
}

// Quantized block size (values per quant block) for K-quants and Q8_0.
inline std::size_t quantBlockSize(TensorType t) {
    switch (t) {
        case TensorType::Q4_0:
        case TensorType::Q4_1:
        case TensorType::Q5_0:
        case TensorType::Q5_1:
        case TensorType::Q8_0:
        case TensorType::Q8_1: return 32;
        case TensorType::Q2_K:
        case TensorType::Q3_K_S:
        case TensorType::Q3_K_M:
        case TensorType::Q3_K_L:
        case TensorType::Q4_K_S:
        case TensorType::Q4_K_M:
        case TensorType::Q5_K_S:
        case TensorType::Q5_K_M:
        case TensorType::Q6_K: return 256;
        default: return 1;
    }
}

inline bool isQuantized(TensorType t) {
    return t != TensorType::F32 && t != TensorType::F16;
}

// Storage bytes required for a tensor of `numValues` values of type `t` (block-aligned).
inline std::uint64_t tensorStorageBytes(std::uint64_t numValues, TensorType t) {
    const auto max = (std::numeric_limits<std::uint64_t>::max)();
    if (t == TensorType::F32) return numValues > max / 4u ? max : numValues * 4u;
    if (t == TensorType::F16) return numValues > max / 2u ? max : numValues * 2u;

    const std::size_t valuesPerBlock = quantBlockSize(t);
    if (!valuesPerBlock || numValues > max - (valuesPerBlock - 1u)) return max;
    const std::uint64_t blocks =
        (numValues + static_cast<std::uint64_t>(valuesPerBlock) - 1u) /
        static_cast<std::uint64_t>(valuesPerBlock);
    std::uint64_t bytesPerBlock = 0;
    switch (t) {
        case TensorType::Q4_0:   bytesPerBlock = 18;  break;
        case TensorType::Q4_1:   bytesPerBlock = 20;  break;
        case TensorType::Q5_0:   bytesPerBlock = 22;  break;
        case TensorType::Q5_1:   bytesPerBlock = 24;  break;
        case TensorType::Q8_0:   bytesPerBlock = 34;  break;
        case TensorType::Q8_1:   bytesPerBlock = 40;  break;
        case TensorType::Q2_K:   bytesPerBlock = 82;  break;
        case TensorType::Q3_K_S:
        case TensorType::Q3_K_M:
        case TensorType::Q3_K_L: bytesPerBlock = 114; break;
        case TensorType::Q4_K_S:
        case TensorType::Q4_K_M: bytesPerBlock = 146; break;
        case TensorType::Q5_K_S:
        case TensorType::Q5_K_M: bytesPerBlock = 178; break;
        case TensorType::Q6_K:   bytesPerBlock = 210; break;
        default: return numValues;
    }
    return blocks > max / bytesPerBlock ? max : blocks * bytesPerBlock;
}
// Non-owning view over raw tensor storage (quantized, f16 or f32). The backing memory
// is owned by the ROM pager; a TensorView is only valid while its TensorLease is alive.
struct TensorView {
    TensorType type = TensorType::F32;
    const std::uint8_t* data = nullptr;
    std::size_t byteSize = 0;
    std::vector<std::uint64_t> dims;   // GGUF on-disk order (logical shape = reverse(dims))
    bool contiguous = true;

    std::size_t rank() const { return dims.size(); }
    std::uint64_t totalElements() const {
        std::uint64_t n = 1;
        for (auto d : dims) n *= d;
        return n;
    }
};

// Result of dequantizing a TensorView into contiguous f32 memory.
struct DequantizedTensor {
    std::vector<float> data;
    std::vector<std::uint64_t> dims;   // logical shape (reverse of GGUF storage order)
    std::uint64_t rows = 0;            // for 2-D weight matrices: logical rows
    std::uint64_t cols = 0;            // logical columns
};

} // namespace deep2

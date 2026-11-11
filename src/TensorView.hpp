#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

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
        case TensorType::Q8_0: return 32;
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
    if (!isQuantized(t)) {
        return numValues * static_cast<std::uint64_t>(tensorTypeBytesPerValue(t));
    }
    const std::size_t bsz = quantBlockSize(t);
    const std::uint64_t blocks = (numValues + bsz - 1) / bsz;
    // storage bytes per block (includes scales/super-scale; block-aligned in GGUF)
    switch (t) {
        case TensorType::Q8_0:   return blocks * 34;   // 32 x int8 + fp16 d
        case TensorType::Q2_K:   return blocks * 82;   // 64 qs + 16 scales + fp16 d
        case TensorType::Q3_K_S:
        case TensorType::Q3_K_M:
        case TensorType::Q3_K_L: return blocks * 114;  // 96 qs + 16 scales + fp16 d
        case TensorType::Q4_K_S:
        case TensorType::Q4_K_M: return blocks * 146;  // 128 qs + 16 scales + fp16 d
        case TensorType::Q5_K_S:
        case TensorType::Q5_K_M: return blocks * 178;  // 160 qs + 16 scales + fp16 d
        case TensorType::Q6_K:   return blocks * 210;  // 192 qs + 16 scales + fp16 d
        default: return numValues;
    }
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

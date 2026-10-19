#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace deep2 {

// GGUF quantization type codes.
//
// These are the on-disk ggml type ids exactly as they appear in a GGUF
// tensor directory, so a raw type id from the file can be used directly.
//   ggml: GGML_TYPE_F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7,
//         Q8_0 = 8, Q8_1 = 9, Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13,
//         Q6_K = 14, Q8_K = 15
// Ids 4 and 5 (Q4_2 / Q4_3) were removed from the format and are not reused.
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
    Q3_K  = 11,
    Q4_K  = 12,
    Q5_K  = 13,
    Q6_K  = 14,
    Q8_K  = 15,
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
        case TensorType::Q3_K:  return "Q3_K";
        case TensorType::Q4_K:  return "Q4_K";
        case TensorType::Q5_K:  return "Q5_K";
        case TensorType::Q6_K:  return "Q6_K";
        case TensorType::Q8_K:  return "Q8_K";
        default:                return "UNKNOWN";
    }
}

// Bytes of storage per single value for fixed-width types; quantized K-types return the
// block-average (e.g. Q4_K ~ 0.56 bytes/value including overhead).
inline double tensorTypeBytesPerValue(TensorType t) {
    switch (t) {
        case TensorType::F32: return 4.0;
        case TensorType::F16: return 2.0;
        case TensorType::Q8_0: return 1.0;
        case TensorType::Q8_1: return 1.0625;
        case TensorType::Q4_0:
        case TensorType::Q4_1: return 0.5;
        case TensorType::Q5_0:
        case TensorType::Q5_1: return 0.5625;
        case TensorType::Q2_K: return 0.328125;   // 2.625 bits/weight
        case TensorType::Q3_K: return 0.4296875;  // 3.4375 bits/weight
        case TensorType::Q4_K: return 0.5625;     // 4.5 bits/weight
        case TensorType::Q5_K: return 0.6875;     // 5.5 bits/weight
        case TensorType::Q6_K: return 0.8203125;  // 6.5625 bits/weight
        case TensorType::Q8_K: return 1.140625;   // 9.125 bits/weight
        default: return 1.0;
    }
}

// Quantized block size (values per quant block) for K-quants and Q8_0.
inline std::size_t quantBlockSize(TensorType t) {
    switch (t) {
        case TensorType::Q8_0: return 32;
        case TensorType::Q8_1: return 32;
        case TensorType::Q4_0: return 32;
        case TensorType::Q4_1: return 32;
        case TensorType::Q5_0: return 32;
        case TensorType::Q5_1: return 32;
        case TensorType::Q2_K:
        case TensorType::Q3_K:
        case TensorType::Q4_K:
        case TensorType::Q5_K:
        case TensorType::Q6_K:
        case TensorType::Q8_K: return 256;
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
    // Storage bytes per block. Sizes match ggml's block_*_K structures:
    //   q2_K: scales[16] + qs[64]  + d + dmin            =  84
    //   q3_K: hmask[32] + qs[64]   + scales[12] + d       = 110
    //   q4_K: d + dmin + scales[12] + qs[128]              = 144
    //   q5_K: d + dmin + scales[12] + qh[32] + qs[128]    = 176
    //   q6_K: ql[128] + qh[64]     + scales[16] + d       = 210
    //   q8_K: d + qs[256] + bsums[16]                     = 292
    switch (t) {
        case TensorType::Q4_0:   return blocks * 18;   // 16 nibbles + fp16 d
        case TensorType::Q4_1:   return blocks * 20;   // 16 nibbles + fp16 d + fp16 m
        case TensorType::Q5_0:   return blocks * 22;   // 16 nibbles + fp16 d
        case TensorType::Q5_1:   return blocks * 24;   // 16 nibbles + fp16 d + fp16 m
        case TensorType::Q8_0:   return blocks * 34;   // 32 x int8 + fp16 d
        case TensorType::Q8_1:   return blocks * 36;   // 32 x int8 + fp16 d + fp16 s
        case TensorType::Q2_K:   return blocks * 84;
        case TensorType::Q3_K:   return blocks * 110;
        case TensorType::Q4_K:   return blocks * 144;
        case TensorType::Q5_K:   return blocks * 176;
        case TensorType::Q6_K:   return blocks * 210;
        case TensorType::Q8_K:   return blocks * 292;
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

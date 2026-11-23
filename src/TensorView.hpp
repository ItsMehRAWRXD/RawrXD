#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <limits>

namespace deep2 {

// GGUF quantization type codes. These numeric values are the on-disk
// ggml_type identifiers; never assign application-specific aliases to them.
enum class TensorType : uint32_t {
    F32 = 0, F16 = 1,
    Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7, Q8_0 = 8, Q8_1 = 9,
    Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14, Q8_K = 15,
    IQ2_XXS = 16, IQ2_XS = 17, IQ3_XXS = 18, IQ1_S = 19, IQ4_NL = 20,
    IQ3_S = 21, IQ2_S = 22, IQ4_XS = 23,
    I8 = 24, I16 = 25, I32 = 26, I64 = 27, F64 = 28,
    IQ1_M = 29, BF16 = 30, TQ1_0 = 34, TQ2_0 = 35, MXFP4 = 39
};

inline const char* tensorTypeName(TensorType t) {
    switch (t) {
        case TensorType::F32: return "F32";
        case TensorType::F16: return "F16";
        case TensorType::Q4_0: return "Q4_0";
        case TensorType::Q4_1: return "Q4_1";
        case TensorType::Q5_0: return "Q5_0";
        case TensorType::Q5_1: return "Q5_1";
        case TensorType::Q8_0: return "Q8_0";
        case TensorType::Q8_1: return "Q8_1";
        case TensorType::Q2_K: return "Q2_K";
        case TensorType::Q3_K: return "Q3_K";
        case TensorType::Q4_K: return "Q4_K";
        case TensorType::Q5_K: return "Q5_K";
        case TensorType::Q6_K: return "Q6_K";
        case TensorType::Q8_K: return "Q8_K";
        case TensorType::IQ2_XXS: return "IQ2_XXS";
        case TensorType::IQ2_XS: return "IQ2_XS";
        case TensorType::IQ3_XXS: return "IQ3_XXS";
        case TensorType::IQ1_S: return "IQ1_S";
        case TensorType::IQ4_NL: return "IQ4_NL";
        case TensorType::IQ3_S: return "IQ3_S";
        case TensorType::IQ2_S: return "IQ2_S";
        case TensorType::IQ4_XS: return "IQ4_XS";
        case TensorType::I8: return "I8";
        case TensorType::I16: return "I16";
        case TensorType::I32: return "I32";
        case TensorType::I64: return "I64";
        case TensorType::F64: return "F64";
        case TensorType::IQ1_M: return "IQ1_M";
        case TensorType::BF16: return "BF16";
        case TensorType::TQ1_0: return "TQ1_0";
        case TensorType::TQ2_0: return "TQ2_0";
        case TensorType::MXFP4: return "MXFP4";
        default: return "UNKNOWN";
    }
}

// Storage ratio includes each format's per-block scale/minimum metadata.
inline double tensorTypeBytesPerValue(TensorType t) {
    switch (t) {
        case TensorType::F32: return 4.0;
        case TensorType::F16: return 2.0;
        case TensorType::Q4_0: return 18.0 / 32.0;
        case TensorType::Q4_1: return 20.0 / 32.0;
        case TensorType::Q5_0: return 22.0 / 32.0;
        case TensorType::Q5_1: return 24.0 / 32.0;
        case TensorType::Q8_0: return 34.0 / 32.0;
        case TensorType::Q8_1: return 36.0 / 32.0;
        case TensorType::Q2_K: return 84.0 / 256.0;
        case TensorType::Q3_K: return 110.0 / 256.0;
        case TensorType::Q4_K: return 144.0 / 256.0;
        case TensorType::Q5_K: return 176.0 / 256.0;
        case TensorType::Q6_K: return 210.0 / 256.0;
        case TensorType::Q8_K: return 292.0 / 256.0;
        case TensorType::IQ2_XXS: return 66.0 / 256.0;
        case TensorType::IQ2_XS: return 74.0 / 256.0;
        case TensorType::IQ3_XXS: return 98.0 / 256.0;
        case TensorType::IQ1_S: return 50.0 / 256.0;
        case TensorType::IQ4_NL: return 18.0 / 32.0;
        case TensorType::IQ3_S: return 110.0 / 256.0;
        case TensorType::IQ2_S: return 82.0 / 256.0;
        case TensorType::IQ4_XS: return 136.0 / 256.0;
        case TensorType::IQ1_M: return 56.0 / 256.0;
        case TensorType::TQ1_0: return 54.0 / 256.0;
        case TensorType::TQ2_0: return 66.0 / 256.0;
        case TensorType::MXFP4: return 17.0 / 32.0;
        case TensorType::BF16: return 2.0;
        case TensorType::I8: return 1.0;
        case TensorType::I16: return 2.0;
        case TensorType::I32: return 4.0;
        case TensorType::I64: case TensorType::F64: return 8.0;
        default: return 1.0;
    }
}

inline std::size_t quantBlockSize(TensorType t) {
    switch (t) {
        case TensorType::Q4_0: case TensorType::Q4_1:
        case TensorType::Q5_0: case TensorType::Q5_1:
        case TensorType::Q8_0: case TensorType::Q8_1:
            return 32;
        case TensorType::Q2_K: case TensorType::Q3_K:
        case TensorType::Q4_K: case TensorType::Q5_K:
        case TensorType::Q6_K: case TensorType::Q8_K:
        case TensorType::IQ2_XXS: case TensorType::IQ2_XS:
        case TensorType::IQ3_XXS: case TensorType::IQ1_S:
        case TensorType::IQ3_S: case TensorType::IQ2_S:
        case TensorType::IQ4_XS: case TensorType::IQ1_M:
        case TensorType::TQ1_0: case TensorType::TQ2_0:
            return 256;
        case TensorType::IQ4_NL: case TensorType::MXFP4:
            return 32;
        default: return 1;
    }
}

inline bool isQuantized(TensorType t) {
    return quantBlockSize(t) > 1;
}

// Standard GGML packed storage geometry. Unknown identifiers return UINT64_MAX
// so a reader fails closed instead of guessing a byte size and crossing tensor bounds.
inline std::uint64_t tensorStorageBytes(std::uint64_t numValues, TensorType t) {
    const auto max = (std::numeric_limits<std::uint64_t>::max)();
    if (t == TensorType::F32) return numValues > max / 4u ? max : numValues * 4u;
    if (t == TensorType::F16 || t == TensorType::BF16)
        return numValues > max / 2u ? max : numValues * 2u;
    if (t == TensorType::F64 || t == TensorType::I64)
        return numValues > max / 8u ? max : numValues * 8u;
    if (t == TensorType::I32)
        return numValues > max / 4u ? max : numValues * 4u;
    if (t == TensorType::I16)
        return numValues > max / 2u ? max : numValues * 2u;
    if (t == TensorType::I8) return numValues;
    const std::size_t valuesPerBlock = quantBlockSize(t);
    if (!valuesPerBlock || numValues > max - (valuesPerBlock - 1u)) return max;
    const std::uint64_t blocks =
        (numValues + static_cast<std::uint64_t>(valuesPerBlock) - 1u) /
        static_cast<std::uint64_t>(valuesPerBlock);
    std::uint64_t bytesPerBlock = 0;
    switch (t) {
        case TensorType::Q4_0: bytesPerBlock = 18; break;
        case TensorType::Q4_1: bytesPerBlock = 20; break;
        case TensorType::Q5_0: bytesPerBlock = 22; break;
        case TensorType::Q5_1: bytesPerBlock = 24; break;
        case TensorType::Q8_0: bytesPerBlock = 34; break;
        case TensorType::Q8_1: bytesPerBlock = 36; break;
        case TensorType::Q2_K: bytesPerBlock = 84; break;
        case TensorType::Q3_K: bytesPerBlock = 110; break;
        case TensorType::Q4_K: bytesPerBlock = 144; break;
        case TensorType::Q5_K: bytesPerBlock = 176; break;
        case TensorType::Q6_K: bytesPerBlock = 210; break;
        case TensorType::Q8_K: bytesPerBlock = 292; break;
        case TensorType::IQ2_XXS: bytesPerBlock = 66; break;
        case TensorType::IQ2_XS: bytesPerBlock = 74; break;
        case TensorType::IQ3_XXS: bytesPerBlock = 98; break;
        case TensorType::IQ1_S: bytesPerBlock = 50; break;
        case TensorType::IQ4_NL: bytesPerBlock = 18; break;
        case TensorType::IQ3_S: bytesPerBlock = 110; break;
        case TensorType::IQ2_S: bytesPerBlock = 82; break;
        case TensorType::IQ4_XS: bytesPerBlock = 136; break;
        case TensorType::IQ1_M: bytesPerBlock = 56; break;
        case TensorType::TQ1_0: bytesPerBlock = 54; break;
        case TensorType::TQ2_0: bytesPerBlock = 66; break;
        case TensorType::MXFP4: bytesPerBlock = 17; break;
        default: return max;
    }
    return blocks > max / bytesPerBlock ? max : blocks * bytesPerBlock;
}

// Compute GGML tensor storage from its actual dimensions. Quantized row padding
// is applied to ne[0] for every outer row; flattening all elements first is wrong
// whenever the fastest dimension is not block-aligned.
inline std::uint64_t tensorStorageBytesForShape(
    const std::vector<std::uint64_t>& dims, TensorType t) {
    if (dims.empty()) return tensorStorageBytes(1, t);
    const auto max = (std::numeric_limits<std::uint64_t>::max)();
    const auto rowBytes = tensorStorageBytes(dims[0], t);
    if (rowBytes == max) return max;
    std::uint64_t rows = 1;
    for (std::size_t i = 1; i < dims.size(); ++i) {
        if (dims[i] && rows > max / dims[i]) return max;
        rows *= dims[i];
    }
    if (rowBytes && rows > max / rowBytes) return max;
    return rows * rowBytes;
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
        const auto max = (std::numeric_limits<std::uint64_t>::max)();
        for (auto d : dims) {
            if (d && n > max / d) return max;
            n *= d;
        }
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

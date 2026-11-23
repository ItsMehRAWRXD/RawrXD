#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace deep2 {

// Canonical GGML/GGUF tensor type IDs. Legacy *_S/_M/_L names remain aliases
// for source compatibility; a GGUF type ID does not encode a model-specific
// "small/medium/large" K-quant layout.
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
    Q3_K_S = Q3_K,
    Q3_K_M = Q3_K,
    Q3_K_L = Q3_K,
    Q4_K  = 12,
    Q4_K_S = Q4_K,
    Q4_K_M = Q4_K,
    Q5_K  = 13,
    Q5_K_S = Q5_K,
    Q5_K_M = Q5_K,
    Q6_K  = 14,
    Q8_K  = 15,
    I8    = 24,
    I16   = 25,
    I32   = 26,
    I64   = 27,
    F64   = 28,
    BF16  = 30,
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
        case TensorType::I8: return "I8";
        case TensorType::I16: return "I16";
        case TensorType::I32: return "I32";
        case TensorType::I64: return "I64";
        case TensorType::F64: return "F64";
        case TensorType::BF16: return "BF16";
        default: return "UNKNOWN";
    }
}

inline bool isQuantized(TensorType t) {
    switch (t) {
        case TensorType::Q4_0:
        case TensorType::Q4_1:
        case TensorType::Q5_0:
        case TensorType::Q5_1:
        case TensorType::Q8_0:
        case TensorType::Q8_1:
        case TensorType::Q2_K:
        case TensorType::Q3_K:
        case TensorType::Q4_K:
        case TensorType::Q5_K:
        case TensorType::Q6_K:
        case TensorType::Q8_K:
            return true;
        default:
            return false;
    }
}

// Exact average storage bytes per logical value, including per-block scales.
inline double tensorTypeBytesPerValue(TensorType t) {
    switch (t) {
        case TensorType::F32: return 4.0;
        case TensorType::F16:
        case TensorType::BF16: return 2.0;
        case TensorType::F64:
        case TensorType::I64: return 8.0;
        case TensorType::I32: return 4.0;
        case TensorType::I16: return 2.0;
        case TensorType::I8: return 1.0;
        case TensorType::Q4_0: return 18.0 / 32.0;
        case TensorType::Q4_1: return 20.0 / 32.0;
        case TensorType::Q5_0: return 22.0 / 32.0;
        case TensorType::Q5_1: return 24.0 / 32.0;
        case TensorType::Q8_0: return 34.0 / 32.0;
        case TensorType::Q8_1: return 40.0 / 32.0;
        case TensorType::Q2_K: return 84.0 / 256.0;
        case TensorType::Q3_K: return 110.0 / 256.0;
        case TensorType::Q4_K: return 144.0 / 256.0;
        case TensorType::Q5_K: return 176.0 / 256.0;
        case TensorType::Q6_K: return 210.0 / 256.0;
        case TensorType::Q8_K: return 292.0 / 256.0;
        default: return 0.0;
    }
}

inline std::size_t quantBlockSize(TensorType t) {
    switch (t) {
        case TensorType::Q4_0:
        case TensorType::Q4_1:
        case TensorType::Q5_0:
        case TensorType::Q5_1:
        case TensorType::Q8_0:
        case TensorType::Q8_1:
            return 32;
        case TensorType::Q2_K:
        case TensorType::Q3_K:
        case TensorType::Q4_K:
        case TensorType::Q5_K:
        case TensorType::Q6_K:
        case TensorType::Q8_K:
            return 256;
        default:
            return 1;
    }
}

// Storage bytes for GGUF tensor payloads. Quantized rows must be block aligned;
// the GGUF loader validates that condition before calling this helper.
inline std::uint64_t tensorStorageBytes(std::uint64_t numValues, TensorType t) {
    const std::size_t blockValues = quantBlockSize(t);
    const std::uint64_t blocks = (numValues + blockValues - 1) / blockValues;
    switch (t) {
        case TensorType::Q4_0: return blocks * 18;
        case TensorType::Q4_1: return blocks * 20;
        case TensorType::Q5_0: return blocks * 22;
        case TensorType::Q5_1: return blocks * 24;
        case TensorType::Q8_0: return blocks * 34;
        case TensorType::Q8_1: return blocks * 40;
        case TensorType::Q2_K: return blocks * 84;
        case TensorType::Q3_K: return blocks * 110;
        case TensorType::Q4_K: return blocks * 144;
        case TensorType::Q5_K: return blocks * 176;
        case TensorType::Q6_K: return blocks * 210;
        case TensorType::Q8_K: return blocks * 292;
        default: return numValues * static_cast<std::uint64_t>(tensorTypeBytesPerValue(t));
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
    std::uint64_t rows = 0;
    std::uint64_t cols = 0;
};

} // namespace deep2

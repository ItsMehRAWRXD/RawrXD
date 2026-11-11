/*===========================================================================
 * Deep2_Quantized.hpp
 *
 * Unified multi-format quantization interface for Deep2Bridge
 *
 * Supports: Q4_K_M, Q5_K_M, Q6_K, Q8_0
 *
 * Architecture:
 *   QuantType enum identifies format
 *   QuantKernel struct holds format-specific functions
 *   KernelRegistry resolves (quantType, cpuFeatures) -> implementation
 *
 * Usage:
 *   auto kernel = KernelRegistry::Resolve(QuantType::Q5_K_M, CPUFeature::AVX512);
 *   kernel.dequant(blocks, dest, numBlocks);
 *===========================================================================*/

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <unordered_map>
#include <string>

namespace RawrXD {
namespace Deep2 {

/*===========================================================================
 * Quantization Type Enumeration
 * GGUF-compatible quantization formats
 *===========================================================================*/
enum class QuantType : uint32_t {
    Unknown = 0,
    Q4_0    = 2,   // GGML legacy 4-bit
    Q4_1    = 3,
    Q5_0    = 8,
    Q5_1    = 9,
    Q8_0    = 7,
    Q2_K    = 10,  // K-quants
    Q3_K_S  = 11,
    Q3_K_M  = 12,
    Q3_K_L  = 13,
    Q4_K_S  = 14,  // K-quants with super-blocks
    Q4_K_M  = 15,  // Primary target - best speed/compression
    Q5_K_S  = 16,
    Q5_K_M  = 17,  // Higher quality for 30B+ models
    Q6_K    = 18,  // Near-FP16 quality for 70B models
    FP16    = 100, // Native formats
    FP32    = 101
};

/*===========================================================================
 * Block Structure Constants
 *===========================================================================*/
struct QuantBlockInfo {
    QuantType type;
    size_t blockSize;      // Values per block
    size_t bytesPerBlock;  // Bytes per block
    size_t scaleBits;      // Bits for scale
    size_t minBits;        // Bits for minimum
    size_t valueBits;      // Bits per quantized value
    const char* name;
};

constexpr QuantBlockInfo Q4KM_BLOCK_INFO = {
    QuantType::Q4_K_M, 256, 144, 6, 6, 4, "Q4_K_M"
};

constexpr QuantBlockInfo Q5KM_BLOCK_INFO = {
    QuantType::Q5_K_M, 256, 176, 6, 6, 5, "Q5_K_M"
};

constexpr QuantBlockInfo Q6K_BLOCK_INFO = {
    QuantType::Q6_K, 256, 210, 8, 8, 6, "Q6_K"
};

constexpr QuantBlockInfo Q8_0_BLOCK_INFO = {
    QuantType::Q8_0, 32, 34, 32, 0, 8, "Q8_0"
};

inline const QuantBlockInfo* GetBlockInfo(QuantType type) {
    switch (type) {
        case QuantType::Q4_K_M: return &Q4KM_BLOCK_INFO;
        case QuantType::Q5_K_M: return &Q5KM_BLOCK_INFO;
        case QuantType::Q6_K:   return &Q6K_BLOCK_INFO;
        case QuantType::Q8_0:   return &Q8_0_BLOCK_INFO;
        default: return nullptr;
    }
}

/*===========================================================================
 * Kernel Function Types
 *===========================================================================*/
using DequantFunc = uint64_t (*)(const uint8_t* blocks, float* dest, uint64_t numBlocks);
using MatVecFunc = void (*)(const uint8_t* weights, const float* x, float* y, size_t rows, size_t cols, QuantType type);
using QuantizeFunc = void (*)(const float* src, uint8_t* dest, size_t count, QuantType type);

/*===========================================================================
 * Quant Kernel Descriptor
 *===========================================================================*/
struct QuantKernel {
    QuantType type;
    uint32_t blockSize;
    DequantFunc dequant;
    MatVecFunc matvec;
    QuantizeFunc quantize;  // Optional - for training/fine-tuning
    const char* version;
    bool isOptimized;
};

/*===========================================================================
 * CPU Feature Flags (mirrors KernelRegistry)
 *===========================================================================*/
enum class CPUFeature : uint32_t {
    None    = 0,
    SSE2    = 1 << 0,
    AVX     = 1 << 1,
    AVX2    = 1 << 2,
    AVX512F = 1 << 3,
    AVX512VL = 1 << 4,
    AVX512DQ = 1 << 5,
    AMX     = 1 << 6
};

inline CPUFeature operator|(CPUFeature a, CPUFeature b) {
    return static_cast<CPUFeature>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline bool HasFeature(CPUFeature features, CPUFeature check) {
    return (static_cast<uint32_t>(features) & static_cast<uint32_t>(check)) != 0;
}

/*===========================================================================
 * Quantized Tensor View
 * Non-owning view into GGUF-mapped quantized data
 *===========================================================================*/
class QuantizedTensorView {
public:
    QuantizedTensorView() = default;
    QuantizedTensorView(const uint8_t* data, QuantType type, size_t numBlocks, size_t rows, size_t cols)
        : data_(data), type_(type), numBlocks_(numBlocks), rows_(rows), cols_(cols) {}

    const uint8_t* Data() const { return data_; }
    QuantType Type() const { return type_; }
    size_t NumBlocks() const { return numBlocks_; }
    size_t Rows() const { return rows_; }
    size_t Cols() const { return cols_; }
    bool IsValid() const { return data_ != nullptr && type_ != QuantType::Unknown; }

    const QuantBlockInfo* GetBlockInfo() const { return Deep2::GetBlockInfo(type_); }

private:
    const uint8_t* data_ = nullptr;
    QuantType type_ = QuantType::Unknown;
    size_t numBlocks_ = 0;
    size_t rows_ = 0;
    size_t cols_ = 0;
};

/*===========================================================================
 * Unified Quantized Linear Layer
 * Replaces Q4KMLinear with multi-format support
 *===========================================================================*/
class QuantizedLinear {
public:
    QuantizedLinear() = default;

    // Initialize with quantized weights
    bool Initialize(const uint8_t* weightData, QuantType type, size_t inFeatures, size_t outFeatures);

    // Matrix-vector multiplication: y = weights * x
    bool Forward(const float* x, float* y);

    // Getters
    QuantType GetType() const { return type_; }
    size_t InFeatures() const { return inFeatures_; }
    size_t OutFeatures() const { return outFeatures_; }
    bool IsInitialized() const { return initialized_; }

    // Performance stats
    struct Stats {
        uint64_t forwardCalls = 0;
        uint64_t totalCycles = 0;
        double avgCyclesPerCall = 0.0;
        QuantType lastUsedType = QuantType::Unknown;
    };
    Stats GetStats() const { return stats_; }
    void ResetStats() { stats_ = Stats{}; }

private:
    QuantizedTensorView weights_;
    QuantType type_ = QuantType::Unknown;
    size_t inFeatures_ = 0;
    size_t outFeatures_ = 0;
    bool initialized_ = false;
    Stats stats_ = {};

    // Scratch buffer for dequantized row
    float* scratchBuffer_ = nullptr;
    size_t scratchSize_ = 0;
};

/*===========================================================================
 * Quantization Router
 * Central dispatch for all quantization formats
 *===========================================================================*/
class QuantizationRouter {
public:
    static QuantizationRouter& Instance();

    // Initialize with detected CPU features
    void Initialize(CPUFeature features);

    // Resolve kernel for quant type
    const QuantKernel* Resolve(QuantType type) const;

    // Resolve with fallback chain
    const QuantKernel* ResolveWithFallback(QuantType type) const;

    // Register a kernel
    void RegisterKernel(const QuantKernel& kernel);

    // Check if format is supported
    bool IsSupported(QuantType type) const;

    // Get best available format for model size
    static QuantType RecommendFormat(size_t modelParams, size_t availableVRAM_MB);

    // List supported formats
    void ListSupportedFormats(void (*callback)(QuantType type, const char* name)) const;

private:
    QuantizationRouter() = default;

    std::unordered_map<QuantType, QuantKernel, std::hash<std::underlying_type_t<QuantType>>> kernels_;
    CPUFeature cpuFeatures_ = CPUFeature::None;
    bool initialized_ = false;
};

/*===========================================================================
 * GGUF Integration Helpers
 *===========================================================================*/

// Convert GGUF file_type to QuantType
inline QuantType GGUFFileTypeToQuantType(uint32_t fileType) {
    switch (fileType) {
        case 2:  return QuantType::Q4_0;
        case 3:  return QuantType::Q4_1;
        case 7:  return QuantType::Q8_0;
        case 8:  return QuantType::Q5_0;
        case 9:  return QuantType::Q5_1;
        case 10: return QuantType::Q2_K;
        case 11: return QuantType::Q3_K_S;
        case 12: return QuantType::Q3_K_M;
        case 13: return QuantType::Q3_K_L;
        case 14: return QuantType::Q4_K_S;
        case 15: return QuantType::Q4_K_M;
        case 16: return QuantType::Q5_K_S;
        case 17: return QuantType::Q5_K_M;
        case 18: return QuantType::Q6_K;
        default: return QuantType::Unknown;
    }
}

// Convert QuantType to string
inline const char* QuantTypeToString(QuantType type) {
    switch (type) {
        case QuantType::Q4_K_M: return "Q4_K_M";
        case QuantType::Q5_K_M: return "Q5_K_M";
        case QuantType::Q6_K:   return "Q6_K";
        case QuantType::Q8_0:   return "Q8_0";
        case QuantType::FP16:   return "FP16";
        case QuantType::FP32:   return "FP32";
        default: return "Unknown";
    }
}

// Check if quantization type is supported by Deep2 kernels
inline bool IsQuantizationSupported(QuantType type) {
    switch (type) {
        case QuantType::Q4_K_M:
        case QuantType::Q5_K_M:
        case QuantType::Q6_K:
        case QuantType::Q8_0:
        case QuantType::FP16:
        case QuantType::FP32:
            return true;
        default:
            return false;
    }
}

} // namespace Deep2
} // namespace RawrXD

/*===========================================================================
 * C API for MASM Integration
 *===========================================================================*/

extern "C" {

// Get block info for quant type
__declspec(dllexport)
const RawrXD::Deep2::QuantBlockInfo* Deep2_GetBlockInfo(int quantType);

// Resolve kernel for quant type
__declspec(dllexport)
const RawrXD::Deep2::QuantKernel* Deep2_ResolveKernel(int quantType);

// Check if quant type is supported
__declspec(dllexport)
int Deep2_IsQuantSupported(int quantType);

// Get recommended quant format for model
__declspec(dllexport)
int Deep2_RecommendQuantFormat(uint64_t modelParams, uint32_t vramMB);

} // extern "C"

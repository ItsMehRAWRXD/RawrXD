// ============================================================================
// UniversalTensorDescriptor.hpp
// ============================================================================
// Format-agnostic tensor metadata. No GGUF/Q4_K/DeepSeek assumptions.
// The runtime never branches on format - it resolves kernels via descriptors.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <array>

namespace RawrXD {

// ============================================================================
// Quantization Type Enum (extensible - new formats just add entries)
// ============================================================================
enum class QuantType : uint16_t {
    // Uncompressed
    F32     = 0,
    F16     = 1,
    BF16    = 2,
    F8_E4M3 = 3,
    F8_E5M2 = 4,

    // Integer types
    I32     = 5,
    I16     = 6,
    I8      = 7,
    U8      = 8,
    I64     = 9,

    // GGUF quantizations (treated as compression, not format)
    Q4_0    = 10,
    Q4_1    = 11,
    Q5_0    = 12,
    Q5_1    = 13,
    Q8_0    = 14,
    Q8_1    = 15,
    Q2_K    = 20,
    Q3_K    = 21,
    Q4_K    = 22,
    Q5_K    = 23,
    Q6_K    = 24,
    IQ2_XXS = 30,
    IQ2_XS  = 31,
    IQ3_XXS = 32,
    IQ4_NL  = 33,
    IQ4_XS  = 34,

    // Custom RawrXD formats
    NU_FUSED = 40,    // NU-Fused compression
    NF4      = 41,    // NormalFloat 4-bit
    XVA      = 42,    // XVA packed

    // Future formats
    UNKNOWN  = 0xFFFF
};

// ============================================================================
// Tensor Layout
// ============================================================================
enum class TensorLayout : uint8_t {
    DENSE       = 0,   // Contiguous
    STRIDED     = 1,   // Custom strides
    BLOCKED     = 2,   // Block-quantized (Q4_K, etc.)
    SPARSE      = 3,   // Sparse (tree attention)
    MOE_EXPERT  = 4,   // MoE expert shard
    STREAMED    = 5,   // NVMe-paged
    WARMUP      = 6,   // Warm-up cache
};

// ============================================================================
// Tensor Role (semantic purpose in transformer)
// ============================================================================
enum class TensorRole : uint8_t {
    WEIGHT      = 0,
    ACTIVATION  = 1,
    KV_CACHE    = 2,
    EXPERT      = 3,
    ROUTER      = 4,
    NORM        = 5,
    EMBEDDING   = 6,
    OUTPUT      = 7,
};

// ============================================================================
// Universal Tensor Descriptor
// ============================================================================
// This is the ONLY thing the runtime sees. No format-specific code.
// ============================================================================
struct UniversalTensorDescriptor {
    // Shape (max 8 dims)
    std::array<uint64_t, 8> shape;
    uint8_t  numDims;

    // Data type
    QuantType quantType;
    TensorLayout layout;
    TensorRole role;

    // Block structure (for quantized tensors)
    uint32_t blockSize;       // Elements per block (e.g., 32 for Q4_K)
    uint32_t blockSizeBytes;  // Bytes per block (e.g., 18 for Q4_0)
    uint32_t elementsPerWeight; // How many elements per stored value (1 for dense, 2 for 4-bit)

    // Strides (bytes) - for STRIDED layout
    std::array<uint64_t, 8> strides;

    // Memory location
    enum class MemorySpace : uint8_t {
        HOST      = 0,   // System RAM
        DEVICE    = 1,   // GPU VRAM
        NVME      = 2,   // NVMe-paged (not resident)
        MAPPED    = 3,   // Memory-mapped file
        STREAMED  = 4,   // Streaming (not fully loaded)
    } memorySpace;

    // Raw data pointer (may be null for STREAMED/NVME)
    void* data;

    // Total element count
    uint64_t numElements() const {
        uint64_t total = 1;
        for (uint8_t i = 0; i < numDims; ++i) {
            total *= shape[i];
        }
        return total;
    }

    // Total byte size
    uint64_t byteSize() const {
        if (layout == TensorLayout::BLOCKED) {
            uint64_t numBlocks = numElements() / blockSize;
            return numBlocks * blockSizeBytes;
        }
        // Dense: elements * sizeof(element)
        uint32_t elementBytes = quantElementBytes();
        return numElements() * elementBytes;
    }

    // Bytes per element (for dense types)
    uint32_t quantElementBytes() const {
        switch (quantType) {
            case QuantType::F32:     return 4;
            case QuantType::F16:     return 2;
            case QuantType::BF16:    return 2;
            case QuantType::F8_E4M3: return 1;
            case QuantType::F8_E5M2: return 1;
            default:                 return 0; // Quantized - use blockSizeBytes
        }
    }

    // Is this a quantized (compressed) tensor?
    bool isQuantized() const {
        return quantType >= QuantType::Q4_0 && quantType <= QuantType::XVA;
    }

    // Is this tensor resident in memory?
    bool isResident() const {
        return memorySpace == MemorySpace::HOST ||
               memorySpace == MemorySpace::DEVICE ||
               memorySpace == MemorySpace::MAPPED;
    }

    // Default constructor
    UniversalTensorDescriptor() : numDims(0), quantType(QuantType::UNKNOWN),
        layout(TensorLayout::DENSE), role(TensorRole::WEIGHT),
        blockSize(0), blockSizeBytes(0), elementsPerWeight(1),
        memorySpace(MemorySpace::HOST), data(nullptr) {
        shape.fill(0);
        strides.fill(0);
    }
};

// ============================================================================
// Tensor Descriptor Builder (fluent API)
// ============================================================================
class TensorDescriptorBuilder {
public:
    TensorDescriptorBuilder& shape(std::initializer_list<uint64_t> dims) {
        desc_.numDims = static_cast<uint8_t>(dims.size());
        uint8_t i = 0;
        for (auto d : dims) desc_.shape[i++] = d;
        return *this;
    }

    TensorDescriptorBuilder& quant(QuantType q) {
        desc_.quantType = q;
        return *this;
    }

    TensorDescriptorBuilder& layout(TensorLayout l) {
        desc_.layout = l;
        return *this;
    }

    TensorDescriptorBuilder& role(TensorRole r) {
        desc_.role = r;
        return *this;
    }

    TensorDescriptorBuilder& block(uint32_t size, uint32_t sizeBytes) {
        desc_.blockSize = size;
        desc_.blockSizeBytes = sizeBytes;
        desc_.layout = TensorLayout::BLOCKED;
        return *this;
    }

    TensorDescriptorBuilder& data(void* ptr) {
        desc_.data = ptr;
        return *this;
    }

    TensorDescriptorBuilder& memory(UniversalTensorDescriptor::MemorySpace space) {
        desc_.memorySpace = space;
        return *this;
    }

    UniversalTensorDescriptor build() const {
        return desc_;
    }

private:
    UniversalTensorDescriptor desc_;
};

// ============================================================================
// Quant type name helpers (for logging/debugging only - never for dispatch)
// ============================================================================
inline const char* quantTypeName(QuantType q) {
    switch (q) {
        case QuantType::F32:     return "F32";
        case QuantType::F16:     return "F16";
        case QuantType::BF16:    return "BF16";
        case QuantType::F8_E4M3: return "F8_E4M3";
        case QuantType::F8_E5M2: return "F8_E5M2";
        case QuantType::Q4_0:    return "Q4_0";
        case QuantType::Q4_1:    return "Q4_1";
        case QuantType::Q5_0:    return "Q5_0";
        case QuantType::Q5_1:    return "Q5_1";
        case QuantType::Q8_0:    return "Q8_0";
        case QuantType::Q8_1:    return "Q8_1";
        case QuantType::Q2_K:    return "Q2_K";
        case QuantType::Q3_K:    return "Q3_K";
        case QuantType::Q4_K:    return "Q4_K";
        case QuantType::Q5_K:    return "Q5_K";
        case QuantType::Q6_K:    return "Q6_K";
        case QuantType::IQ2_XXS: return "IQ2_XXS";
        case QuantType::IQ2_XS:  return "IQ2_XS";
        case QuantType::IQ3_XXS: return "IQ3_XXS";
        case QuantType::IQ4_NL:  return "IQ4_NL";
        case QuantType::IQ4_XS:  return "IQ4_XS";
        case QuantType::NU_FUSED: return "NU_FUSED";
        case QuantType::NF4:     return "NF4";
        case QuantType::XVA:     return "XVA";
        default:                 return "UNKNOWN";
    }
}

} // namespace RawrXD

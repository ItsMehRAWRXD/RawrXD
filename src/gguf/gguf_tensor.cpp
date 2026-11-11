// Production implementation for gguf_tensor.cpp
// GGUF tensor management for RawrXD inference
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include "core_runtime/gguf_tensor.h"
#include <cstring>
#include <cstdint>
#include <vector>
#include <algorithm>

namespace RawrXD { namespace Core {

// GGUF tensor types
enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    IQ2_XXS = 16,
    IQ2_XS  = 17,
    IQ3_XXS = 18,
    IQ1_S   = 19,
    IQ4_NL  = 20,
    IQ3_S   = 21,
    IQ4_XS  = 22,
    IQ1_M   = 23,
    BF16    = 30,
    COUNT
};

// Type information
struct TypeInfo {
    size_t blockSize;
    size_t typeSize;
    bool isQuantized;
};

static const TypeInfo s_typeInfo[] = {
    [0]  = {1, 4, false},   // F32
    [1]  = {1, 2, false},   // F16
    [2]  = {32, 18, true},  // Q4_0
    [3]  = {32, 20, true},  // Q4_1
    [6]  = {32, 22, true},  // Q5_0
    [7]  = {32, 24, true},  // Q5_1
    [8]  = {32, 34, true},  // Q8_0
    [9]  = {32, 36, true},  // Q8_1
    [10] = {256, 2 + 256/16 + 256/32, true},  // Q2_K
    [11] = {256, 3 + 256/32 + 256/64 + 256/16, true},  // Q3_K
    [12] = {256, 3 + 256/64 + 256/16, true},  // Q4_K
    [13] = {256, 3 + 256/64 + 256/16 + 8, true},  // Q5_K
    [14] = {256, 3 + 256/64 + 256/32, true},  // Q6_K
    [15] = {256, 3 + 256/4, true},  // Q8_K
};

class GGUFTensor::Impl {
public:
    std::string name;
    GGMLType type = GGMLType::F32;
    std::vector<uint32_t> dimensions;
    std::vector<uint8_t> data;
    size_t dataOffset = 0;  // Offset in original file
    
    // Memory-mapped data (if using mmap)
    const uint8_t* mappedData = nullptr;
    size_t mappedSize = 0;
    
    // Calculate total number of elements
    size_t GetElementCount() const {
        size_t count = 1;
        for (auto dim : dimensions) {
            count *= dim;
        }
        return count;
    }
    
    // Calculate size in bytes
    size_t GetSizeInBytes() const {
        size_t typeIdx = static_cast<size_t>(type);
        if (typeIdx >= sizeof(s_typeInfo) / sizeof(s_typeInfo[0])) {
            return 0;
        }
        
        const TypeInfo& info = s_typeInfo[typeIdx];
        size_t elements = GetElementCount();
        
        if (info.isQuantized) {
            size_t blocks = (elements + info.blockSize - 1) / info.blockSize;
            return blocks * info.typeSize;
        } else {
            return elements * info.typeSize;
        }
    }
    
    // Get type name
    const char* GetTypeName() const {
        switch (type) {
            case GGMLType::F32: return "f32";
            case GGMLType::F16: return "f16";
            case GGMLType::Q4_0: return "q4_0";
            case GGMLType::Q4_1: return "q4_1";
            case GGMLType::Q5_0: return "q5_0";
            case GGMLType::Q5_1: return "q5_1";
            case GGMLType::Q8_0: return "q8_0";
            case GGMLType::Q8_1: return "q8_1";
            case GGMLType::Q2_K: return "q2_K";
            case GGMLType::Q3_K: return "q3_K";
            case GGMLType::Q4_K: return "q4_K";
            case GGMLType::Q5_K: return "q5_K";
            case GGMLType::Q6_K: return "q6_K";
            case GGMLType::Q8_K: return "q8_K";
            case GGMLType::BF16: return "bf16";
            default: return "unknown";
        }
    }
};

GGUFTensor::GGUFTensor() : pImpl(new Impl()) {}
GGUFTensor::~GGUFTensor() = default;
GGUFTensor::GGUFTensor(GGUFTensor&&) noexcept = default;
GGUFTensor& GGUFTensor::operator=(GGUFTensor&&) noexcept = default;

bool GGUFTensor::Load(const std::string& name, uint32_t type, 
                      const std::vector<uint32_t>& dimensions,
                      const void* data, size_t dataSize) {
    if (name.empty() || !data || dataSize == 0) {
        return false;
    }
    
    pImpl->name = name;
    pImpl->type = static_cast<GGMLType>(type);
    pImpl->dimensions = dimensions;
    pImpl->data.resize(dataSize);
    std::memcpy(pImpl->data.data(), data, dataSize);
    pImpl->mappedData = nullptr;
    
    return true;
}

bool GGUFTensor::LoadMapped(const std::string& name, uint32_t type,
                            const std::vector<uint32_t>& dimensions,
                            const uint8_t* mappedData, size_t mappedSize,
                            size_t dataOffset) {
    if (name.empty() || !mappedData || mappedSize == 0) {
        return false;
    }
    
    pImpl->name = name;
    pImpl->type = static_cast<GGMLType>(type);
    pImpl->dimensions = dimensions;
    pImpl->mappedData = mappedData;
    pImpl->mappedSize = mappedSize;
    pImpl->dataOffset = dataOffset;
    pImpl->data.clear();
    
    return true;
}

const std::string& GGUFTensor::GetName() const {
    return pImpl->name;
}

uint32_t GGUFTensor::GetType() const {
    return static_cast<uint32_t>(pImpl->type);
}

const std::vector<uint32_t>& GGUFTensor::GetDimensions() const {
    return pImpl->dimensions;
}

size_t GGUFTensor::GetRank() const {
    return pImpl->dimensions.size();
}

size_t GGUFTensor::GetElementCount() const {
    return pImpl->GetElementCount();
}

size_t GGUFTensor::GetSize() const {
    return pImpl->GetSizeInBytes();
}

const void* GGUFTensor::GetData() const {
    if (!pImpl->data.empty()) {
        return pImpl->data.data();
    }
    if (pImpl->mappedData && pImpl->dataOffset < pImpl->mappedSize) {
        return pImpl->mappedData + pImpl->dataOffset;
    }
    return nullptr;
}

void* GGUFTensor::GetMutableData() {
    if (!pImpl->data.empty()) {
        return pImpl->data.data();
    }
    return nullptr;
}

bool GGUFTensor::IsQuantized() const {
    size_t typeIdx = static_cast<size_t>(pImpl->type);
    if (typeIdx >= sizeof(s_typeInfo) / sizeof(s_typeInfo[0])) {
        return false;
    }
    return s_typeInfo[typeIdx].isQuantized;
}

bool GGUFTensor::IsMapped() const {
    return pImpl->mappedData != nullptr;
}

const char* GGUFTensor::GetTypeName() const {
    return pImpl->GetTypeName();
}

size_t GGUFTensor::GetBlockSize() const {
    size_t typeIdx = static_cast<size_t>(pImpl->type);
    if (typeIdx >= sizeof(s_typeInfo) / sizeof(s_typeInfo[0])) {
        return 1;
    }
    return s_typeInfo[typeIdx].blockSize;
}

void GGUFTensor::Dequantize(float* output, size_t outputSize) const {
    if (!output || outputSize == 0) return;
    
    const void* data = GetData();
    if (!data) return;
    
    size_t elements = GetElementCount();
    size_t toCopy = std::min(elements, outputSize);
    
    switch (pImpl->type) {
        case GGMLType::F32:
            std::memcpy(output, data, toCopy * sizeof(float));
            break;
        case GGMLType::F16:
            // Convert F16 to F32
            // TODO: Implement F16 conversion
            break;
        case GGMLType::Q4_0:
            // Call Q4_0 dequantization
            extern void DequantizeQ4_0(const void*, float*, int);
            DequantizeQ4_0(data, output, static_cast<int>(toCopy));
            break;
        case GGMLType::Q8_0:
            // Call Q8_0 dequantization
            extern void DequantizeQ8_0(const void*, float*, int);
            DequantizeQ8_0(data, output, static_cast<int>(toCopy));
            break;
        default:
            // Unsupported type - fill with zeros
            std::fill(output, output + toCopy, 0.0f);
            break;
    }
}

}} // namespace RawrXD::Core

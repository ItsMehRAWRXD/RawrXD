#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::deep2 {

enum class GgmlStorageType : uint32_t {
    F32, F16, BF16,
    Q4_0, Q4_1, Q5_0, Q5_1, Q8_0,
    Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K,
    Unknown
};

struct PackedTensorDescriptor {
    std::string name;
    const void* data = nullptr;
    size_t bytes = 0;
    uint64_t fileOffset = 0;
    GgmlStorageType type = GgmlStorageType::Unknown;
    std::vector<uint64_t> dims;        // GGML/GGUF order: dim 0 is row width / fastest logical dimension.
    std::vector<uint64_t> byteStrides; // Optional. byteStrides[i] is byte distance for +1 in dim i.
    uint32_t expertAxis = 0;
    uint32_t layer = 0;
    uint32_t expertCount = 0;          // 0 => dims[expertAxis]
};

struct ExpertTensorSlice {
    uint32_t layer = 0;
    uint32_t expert = 0;
    const uint8_t* data = nullptr;
    size_t bytes = 0;
    uint64_t fileOffset = 0;
    size_t tensorByteOffset = 0;
};

struct PackedSliceReceipt {
    bool valid = false;
    bool usedExplicitStrides = false;
    bool quantBlockAligned = false;
    uint32_t experts = 0;
    size_t rowBytes = 0;
    size_t expertStrideBytes = 0;
    size_t coveredBytes = 0;
    const char* failure = nullptr;
};

class PackedExpertSlicer final {
public:
    static bool slice(const PackedTensorDescriptor& d,
                      std::vector<ExpertTensorSlice>& out,
                      PackedSliceReceipt* receipt = nullptr) noexcept;

    static bool typeGeometry(GgmlStorageType type,
                             uint32_t& blockElements,
                             uint32_t& blockBytes) noexcept;
};

} // namespace rawrxd::deep2

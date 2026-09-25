#pragma once
#include "ExpertCache.h"
#include "PackedExpertSlicer.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace rawrxd::deep2 {

struct ExpertTensorView {
    std::string name;
    const void* data = nullptr;
    size_t bytes = 0;
    uint64_t fileOffset = 0;
};

struct ExpertTensorGroup {
    ExpertKey key{};
    std::vector<ExpertTensorView> tensors;
    size_t totalBytes = 0;
};

struct ExpertCatalogStats {
    uint64_t tensorsSeen = 0;
    uint64_t expertTensorsMatched = 0;
    uint64_t expertsDiscovered = 0;
    uint64_t rejectedNull = 0;
    uint64_t rejectedName = 0;
    uint64_t packedTensorsSeen = 0;
    uint64_t packedTensorsSliced = 0;
    uint64_t packedSlicesAdded = 0;
    uint64_t packedRejected = 0;
};

class ExpertTensorCatalog final {
public:
    bool addTensor(const ExpertTensorView& tensor);
    bool addPackedTensor(const PackedTensorDescriptor& tensor, PackedSliceReceipt* receipt = nullptr);
    const ExpertTensorGroup* find(ExpertKey key) const;
    std::vector<ExpertKey> keys() const;
    ExpertCatalogStats stats() const noexcept { return stats_; }

    static bool parseExpertKey(std::string_view name, ExpertKey& outKey) noexcept;

private:
    bool addForKey(ExpertKey key, const ExpertTensorView& tensor);
    std::unordered_map<ExpertKey, ExpertTensorGroup, ExpertKeyHash> groups_;
    ExpertCatalogStats stats_{};
};

} // namespace rawrxd::deep2

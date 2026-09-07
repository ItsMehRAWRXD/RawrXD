// VwaElasticBridge.hpp — Elastic consumes PhysicalTensorRange (not VWA residency)
#pragma once
#include "VirtualTensorRange.hpp"
#include "ElasticResidencyManager.hpp"
#include <string>

namespace Deep2 {

struct ElasticRangeWitness {
    uint64_t registeredOffset = 0;
    uint64_t registeredBytes = 0;
    bool usedSourceDataMemcpy = false;
    bool zeroFill = false;
    ResidencyState state = ResidencyState::Cold;
};

// Register a resolved span as an Elastic-owned tensor. VWA does not place/evict.
inline bool ElasticRegisterPhysicalRange(ElasticResidencyManager& elastic,
                                         const std::string& name,
                                         const PhysicalTensorRange& range,
                                         TensorFormat fmt,
                                         uint32_t layer = 0,
                                         uint32_t expert = ~0u,
                                         ElasticRangeWitness* wit = nullptr) {
    if (wit) *wit = {};
    if (range.byteCount == 0) return false;
    if (wit) {
        wit->registeredOffset = range.absoluteFileOffset;
        wit->registeredBytes = range.byteCount;
        wit->usedSourceDataMemcpy = false; // sourceData forced null
        wit->zeroFill = false;
    }
    return elastic.RegisterTensor(
        name, layer, expert,
        static_cast<size_t>(range.absoluteFileOffset),
        static_cast<size_t>(range.byteCount),
        fmt,
        /*sourceData*/ nullptr,
        range.shardId);
}

} // namespace Deep2

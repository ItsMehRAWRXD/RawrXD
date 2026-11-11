// ============================================================================
// VAL-004: KV Cache Validation Gate
// ============================================================================
// Validates Key-Value cache functionality:
// - Cache allocation and growth
// - Cache read/write operations
// - Cache quantization (Q8_0, Q4_K)
// - Sliding window cache
// - Cache eviction strategies
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL004_KVCacheGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-004"; }
    std::string GetName() const override { return "KV Cache"; }
    std::string GetDescription() const override {
        return "Validates KV cache allocation, read/write operations, "
               "quantization, sliding window, and eviction strategies";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateCacheAllocation();
    bool ValidateCacheReadWrite();
    bool ValidateCacheQuantization();
    bool ValidateSlidingWindow();
    bool ValidateCacheEviction();
};

} // namespace Validation
} // namespace RawrXD

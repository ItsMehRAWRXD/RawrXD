// ============================================================================
// VAL-007: Memory Management Validation Gate
// ============================================================================
// Validates memory management functionality:
// - Aligned memory allocation
// - Memory pool management
// - NUMA-aware allocation
// - Memory-mapped I/O
// - Buffer reuse and caching
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL007_MemoryManagementGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-007"; }
    std::string GetName() const override { return "Memory Management"; }
    std::string GetDescription() const override {
        return "Validates aligned allocation, memory pools, NUMA awareness, "
               "memory-mapped I/O, and buffer management";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateAlignedAllocation();
    bool ValidateMemoryPools();
    bool ValidateNUMAAwareness();
    bool ValidateMemoryMapping();
    bool ValidateBufferReuse();
};

} // namespace Validation
} // namespace RawrXD

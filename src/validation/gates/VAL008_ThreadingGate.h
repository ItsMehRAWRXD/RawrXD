// ============================================================================
// VAL-008: Threading/Concurrency Validation Gate
// ============================================================================
// Validates threading and concurrency functionality:
// - Thread pool management
// - Work queue distribution
// - Lock-free data structures
// - Thread synchronization primitives
// - NUMA-aware thread pinning
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL008_ThreadingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-008"; }
    std::string GetName() const override { return "Threading/Concurrency"; }
    std::string GetDescription() const override {
        return "Validates thread pools, work distribution, lock-free structures, "
               "synchronization, and NUMA-aware thread pinning";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001", "VAL-007"}; }
    
private:
    bool ValidateThreadPool();
    bool ValidateWorkDistribution();
    bool ValidateLockFreeStructures();
    bool ValidateSynchronization();
    bool ValidateThreadPinning();
};

} // namespace Validation
} // namespace RawrXD

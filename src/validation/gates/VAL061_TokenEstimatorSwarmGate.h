// ============================================================================
// VAL-061: Token Estimator Swarm Validation Gate
// ============================================================================
// Validates the Token Estimator Swarm correctly tracks token estimates vs
// actuals and identifies slack categories.
// ============================================================================

#pragma once
#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL061_TokenEstimatorSwarmGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-061"; }
    std::string GetName() const override { return "Token Estimator Swarm Validation"; }
    std::string GetDescription() const override {
        return "Validates Token Estimator Swarm correctly tracks estimates vs actuals "
               "and identifies slack categories for optimization";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { 
        return {"VAL-060", "VAL-050"}; 
    }
};

} // namespace Validation
} // namespace RawrXD

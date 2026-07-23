// ============================================================================
// VAL-062: Swarm Integration Validation Gate
// ============================================================================
// Validates the complete end-to-end integration between TokenEfficiencySwarm
// and TokenEstimatorSwarm through the SwarmIntegrationManager.
// ============================================================================

#pragma once
#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL062_SwarmIntegrationGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-062"; }
    std::string GetName() const override { return "Swarm Integration Validation"; }
    std::string GetDescription() const override {
        return "Validates complete end-to-end integration between TokenEfficiencySwarm "
               "and TokenEstimatorSwarm through SwarmIntegrationManager";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { 
        return {"VAL-061"}; 
    }
};

} // namespace Validation
} // namespace RawrXD

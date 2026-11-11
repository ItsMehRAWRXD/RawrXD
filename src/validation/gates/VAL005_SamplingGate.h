// ============================================================================
// VAL-005: Sampling Validation Gate
// ============================================================================
// Validates token sampling functionality:
// - Greedy sampling
// - Temperature sampling
// - Top-k sampling
// - Top-p (nucleus) sampling
// - Repetition penalty
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL005_SamplingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-005"; }
    std::string GetName() const override { return "Token Sampling"; }
    std::string GetDescription() const override {
        return "Validates greedy, temperature, top-k, top-p sampling "
               "and repetition penalty mechanisms";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateGreedySampling();
    bool ValidateTemperatureSampling();
    bool ValidateTopKSampling();
    bool ValidateTopPSampling();
    bool ValidateRepetitionPenalty();
};

} // namespace Validation
} // namespace RawrXD

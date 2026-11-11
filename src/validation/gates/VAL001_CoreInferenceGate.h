// ============================================================================
// VAL-001: Core Inference Engine Validation Gate
// ============================================================================
// Validates the fundamental inference engine functionality:
// - Tensor operations (matmul, add, mul)
// - Activation functions (ReLU, GELU, SiLU, SwiGLU)
// - Layer normalization (RMSNorm, LayerNorm)
// - Basic transformer block execution
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL001_CoreInferenceGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-001"; }
    std::string GetName() const override { return "Core Inference Engine"; }
    std::string GetDescription() const override {
        return "Validates fundamental tensor operations, activations, and "
               "basic transformer block execution without model weights";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {}; }
    
private:
    bool ValidateTensorOps();
    bool ValidateActivations();
    bool ValidateNormalization();
    bool ValidateTransformerBlock();
    bool ValidateAttentionMechanism();
};

} // namespace Validation
} // namespace RawrXD

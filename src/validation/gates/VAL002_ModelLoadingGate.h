// ============================================================================
// VAL-002: Model Loading Validation Gate
// ============================================================================
// Validates GGUF model loading functionality:
// - GGUF file parsing and validation
// - Tensor metadata extraction
// - Weight dequantization (Q4_0, Q4_K, Q8_0, FP16, FP32)
// - Model architecture detection
// - Memory-mapped file loading
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL002_ModelLoadingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-002"; }
    std::string GetName() const override { return "Model Loading"; }
    std::string GetDescription() const override {
        return "Validates GGUF file parsing, tensor extraction, weight "
               "dequantization, and model architecture detection";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateGGUFParsing();
    bool ValidateTensorExtraction();
    bool ValidateDequantization();
    bool ValidateArchitectureDetection();
    bool ValidateMemoryMapping();
};

} // namespace Validation
} // namespace RawrXD

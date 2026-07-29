// ============================================================================
// VAL-006: Quantization Validation Gate
// ============================================================================
// Validates weight quantization functionality:
// - Q4_0 quantization/dequantization
// - Q4_K quantization/dequantization
// - Q5_0, Q5_K quantization
// - Q8_0 quantization/dequantization
// - FP16/FP32 conversion
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL006_QuantizationGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-006"; }
    std::string GetName() const override { return "Weight Quantization"; }
    std::string GetDescription() const override {
        return "Validates Q4_0, Q4_K, Q5_0, Q5_K, Q8_0 quantization "
               "and FP16/FP32 conversion accuracy";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateQ4_0();
    bool ValidateQ4_K();
    bool ValidateQ5_0();
    bool ValidateQ8_0();
    bool ValidateFP16Conversion();
};

} // namespace Validation
} // namespace RawrXD

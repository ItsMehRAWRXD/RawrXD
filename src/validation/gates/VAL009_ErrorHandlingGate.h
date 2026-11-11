// ============================================================================
// VAL-009: Error Handling Validation Gate
// ============================================================================
// Validates error handling functionality:
// - Exception safety
// - Error code propagation
// - Recovery mechanisms
// - Logging and diagnostics
// - Graceful degradation
// ============================================================================

#pragma once

#include "../ValidationGate_Master.h"

namespace RawrXD {
namespace Validation {

class VAL009_ErrorHandlingGate : public IValidationGate {
public:
    std::string GetId() const override { return "VAL-009"; }
    std::string GetName() const override { return "Error Handling"; }
    std::string GetDescription() const override {
        return "Validates exception safety, error propagation, recovery, "
               "logging, and graceful degradation";
    }
    GateStatus GetStatus() const override { return GateStatus::IMPLEMENTED; }
    
    ValidationResult Execute() override;
    std::vector<std::string> GetDependencies() const override { return {"VAL-001"}; }
    
private:
    bool ValidateExceptionSafety();
    bool ValidateErrorPropagation();
    bool ValidateRecovery();
    bool ValidateLogging();
    bool ValidateGracefulDegradation();
};

} // namespace Validation
} // namespace RawrXD

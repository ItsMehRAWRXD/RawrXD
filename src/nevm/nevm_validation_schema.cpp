//============================================================================
// nevm_validation_schema.cpp
// RawrXD N-EVM - Schema Validation Implementation
//============================================================================

#include "nevm_validation_schema.hpp"
#include <iostream>

namespace RawrXD {
namespace NEVM {

bool ValidationSchema::ValidateRuntime() const {
    // In production, this would check actual runtime version
    // For now, always return true
    return true;
}

Json::Value ValidationSchema::GetSchemaHeader() const {
    Json::Value header;
    header["version"] = VERSION;
    header["runtime_version"] = RUNTIME_VERSION;
    return header;
}

int ExitCodeMapper::MapToExitCode(ValidationExitCode code) {
    return static_cast<int>(code);
}

ValidationExitCode ExitCodeMapper::MapFromResults(
    bool correctness_passed,
    bool performance_passed,
    bool stability_passed,
    bool environment_ok,
    bool model_valid,
    bool schema_compatible) {
    
    if (!schema_compatible) return ValidationExitCode::SCHEMA_MISMATCH;
    if (!model_valid) return ValidationExitCode::INVALID_MODEL;
    if (!environment_ok) return ValidationExitCode::ENVIRONMENT_FAILURE;
    if (!correctness_passed) return ValidationExitCode::CORRECTNESS_FAILURE;
    if (!performance_passed) return ValidationExitCode::PERFORMANCE_REGRESSION;
    if (!stability_passed) return ValidationExitCode::STABILITY_FAILURE;
    
    return ValidationExitCode::SUCCESS;
}

} // namespace NEVM
} // namespace RawrXD

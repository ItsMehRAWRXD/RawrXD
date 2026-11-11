//============================================================================
// nevm_validation_schema.hpp
// RawrXD N-EVM - Validation Schema Versioning
// Versioned JSON output for historical comparisons
//============================================================================

#pragma once

#include <string>
#include <json/json.h>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Schema Version
//============================================================================

struct ValidationSchema {
    static constexpr const char* VERSION = "1.0";
    static constexpr const char* RUNTIME_VERSION = "NEVM-0.4";
    
    static Json::Value GetSchemaHeader() {
        Json::Value header;
        header["schema_version"] = VERSION;
        header["runtime_version"] = RUNTIME_VERSION;
        return header;
    }
    
    static bool ValidateSchema(const Json::Value& root) {
        if (!root.isMember("schema_version")) return false;
        
        std::string version = root["schema_version"].asString();
        return version == VERSION;
    }
};

//============================================================================
// Exit Codes for CI
//============================================================================

enum class ValidationExitCode {
    SUCCESS = 0,                    // All gates passed
    CORRECTNESS_FAILURE = 1,        // Logit or determinism failure
    PERFORMANCE_REGRESSION = 2,     // Below threshold
    STABILITY_FAILURE = 3,          // Stress test failure
    ENVIRONMENT_FAILURE = 4,        // Hardware/dependency issue
    INVALID_MODEL = 5,              // Model load failure
    SCHEMA_MISMATCH = 6,            // JSON schema version mismatch
    UNKNOWN_ERROR = 99
};

class ExitCodeMapper {
public:
    static int MapToInt(ValidationExitCode code) {
        return static_cast<int>(code);
    }
    
    static ValidationExitCode MapFromInt(int code) {
        switch (code) {
            case 0: return ValidationExitCode::SUCCESS;
            case 1: return ValidationExitCode::CORRECTNESS_FAILURE;
            case 2: return ValidationExitCode::PERFORMANCE_REGRESSION;
            case 3: return ValidationExitCode::STABILITY_FAILURE;
            case 4: return ValidationExitCode::ENVIRONMENT_FAILURE;
            case 5: return ValidationExitCode::INVALID_MODEL;
            case 6: return ValidationExitCode::SCHEMA_MISMATCH;
            default: return ValidationExitCode::UNKNOWN_ERROR;
        }
    }
    
    static const char* GetDescription(ValidationExitCode code) {
        switch (code) {
            case ValidationExitCode::SUCCESS: return "All gates passed";
            case ValidationExitCode::CORRECTNESS_FAILURE: return "Correctness failure (logit/determinism)";
            case ValidationExitCode::PERFORMANCE_REGRESSION: return "Performance regression";
            case ValidationExitCode::STABILITY_FAILURE: return "Stability failure";
            case ValidationExitCode::ENVIRONMENT_FAILURE: return "Environment failure";
            case ValidationExitCode::INVALID_MODEL: return "Invalid model";
            case ValidationExitCode::SCHEMA_MISMATCH: return "Schema version mismatch";
            case ValidationExitCode::UNKNOWN_ERROR: return "Unknown error";
        }
        return "Unknown";
    }
};

} // namespace NEVM
} // namespace RawrXD

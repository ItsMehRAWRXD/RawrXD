// ============================================================================
// Execution Result
// ============================================================================
// Output contract for RawrXD inference execution
// ============================================================================

#pragma once

#include "ExecutionStatus.hpp"
#include "ExecutionTelemetry.hpp"
#include "Diagnostic.hpp"

#include <string>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Execution Result Structure
// ============================================================================
// Unified result from any execution backend
// ============================================================================

struct ExecutionResult {
    // Status code
    ExecutionStatus status = ExecutionStatus::Success;
    
    // Generated output
    std::string output;
    
    // Token-level output (for streaming or detailed analysis)
    std::vector<std::string> tokens;
    std::vector<float> token_logprobs;
    
    // Performance metrics
    ExecutionTelemetry telemetry;
    
    // Diagnostics (warnings, info, errors)
    DiagnosticCollection diagnostics;
    
    // Backend-specific metadata (JSON string)
    std::string backend_metadata;
    
    // Convenience methods
    bool IsSuccess() const { return status == ExecutionStatus::Success; }
    bool HasErrors() const { return diagnostics.HasErrors(); }
    bool HasWarnings() const { return diagnostics.HasWarnings(); }
    
    // Factory methods for common results
    static ExecutionResult Success(const std::string& output) {
        ExecutionResult result;
        result.status = ExecutionStatus::Success;
        result.output = output;
        return result;
    }
    
    static ExecutionResult Error(ExecutionStatus status, const std::string& message) {
        ExecutionResult result;
        result.status = status;
        result.diagnostics.AddError("E000", message, "execution");
        return result;
    }
};

} // namespace Execution
} // namespace RawrXD

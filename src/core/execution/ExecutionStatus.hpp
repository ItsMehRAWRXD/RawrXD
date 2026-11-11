// ============================================================================
// Execution Status
// ============================================================================
// Status codes for RawrXD inference execution
// ============================================================================

#pragma once

#include <cstdint>

namespace RawrXD {
namespace Execution {

// ============================================================================
// Execution Status Enum
// ============================================================================
// Unified status codes across all backends
// ============================================================================

enum class ExecutionStatus : uint32_t {
    Success = 0,              // Normal completion
    UserError = 1,            // Invalid request parameters
    ValidationFailure = 2,  // Model/token validation failed
    RuntimeFailure = 3,       // Backend execution error
    Cancelled = 4,            // User/system cancellation
    Timeout = 5,              // Execution time limit exceeded
    NotImplemented = 6,       // Feature not yet available
    BackendUnavailable = 7,   // Requested backend not available
};

// Convert status to human-readable string
inline const char* ExecutionStatusToString(ExecutionStatus status) {
    switch (status) {
        case ExecutionStatus::Success: return "Success";
        case ExecutionStatus::UserError: return "UserError";
        case ExecutionStatus::ValidationFailure: return "ValidationFailure";
        case ExecutionStatus::RuntimeFailure: return "RuntimeFailure";
        case ExecutionStatus::Cancelled: return "Cancelled";
        case ExecutionStatus::Timeout: return "Timeout";
        case ExecutionStatus::NotImplemented: return "NotImplemented";
        case ExecutionStatus::BackendUnavailable: return "BackendUnavailable";
        default: return "Unknown";
    }
}

} // namespace Execution
} // namespace RawrXD

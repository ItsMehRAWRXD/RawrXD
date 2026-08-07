// ============================================================================
// PipelineState.hpp - Reverse GPU Path State Machine
// ============================================================================
// Fallback-safe reverse execution pipeline:
//   Normal pipeline bypassed when not applicable → re-enters through GPU
//   backend recovery path.
//
// Normalized ordering:
//   map → lessER* → pipelineNotApplicable? → YES: reverse → gpuBackend* →
//   tpsGPU → hop → unreverse → dualHotpatch → endNo(GPU)
// ============================================================================

#pragma once
#include <cstdint>
#include <string>

namespace Deep2 {

// ============================================================================
// Pipeline State
// ============================================================================
enum class PipelineState {
    Normal,           // Forward pipeline is valid
    ReverseRequired,  // Forward assumptions broken; reverse path needed
    GPURecovery,      // GPU backend repairing tensor map
    Complete,         // Recovery done, execution can proceed
    Failed            // No backend available (GPU or CPU fallback)
};

// ============================================================================
// Reverse GPU Path descriptor
// ============================================================================
struct ReverseGPUPath {
    bool pipelineApplicable = true;   // Forward size calculator valid?
    bool gpuAvailable       = false;    // Any GPU backend ready?
    bool cpuFallback        = true;     // CPU fallback permitted?
    PipelineState state     = PipelineState::Normal;

    float tokensPerSecond   = 0.0f;   // Measured TPS during recovery
    int   recoveryHops      = 0;        // Number of reverse hops executed

    std::string lastError;
};

// ============================================================================
// Load Result
// ============================================================================
enum class LoadResult {
    Success,
    FileNotFound,
    ParseError,
    TensorBoundsError,
    NoExecutionBackend,
    ReverseRequired,
    TruncationDetected,
    CorruptionDetected,
    Unknown
};

// ============================================================================
// Free helpers
// ============================================================================
inline const char* PipelineStateName(PipelineState s) {
    switch (s) {
        case PipelineState::Normal:          return "Normal";
        case PipelineState::ReverseRequired: return "ReverseRequired";
        case PipelineState::GPURecovery:     return "GPURecovery";
        case PipelineState::Complete:        return "Complete";
        case PipelineState::Failed:          return "Failed";
        default:                             return "Unknown";
    }
}

inline const char* LoadResultName(LoadResult r) {
    switch (r) {
        case LoadResult::Success:              return "Success";
        case LoadResult::FileNotFound:         return "FileNotFound";
        case LoadResult::ParseError:           return "ParseError";
        case LoadResult::TensorBoundsError:    return "TensorBoundsError";
        case LoadResult::NoExecutionBackend:   return "NoExecutionBackend";
        case LoadResult::ReverseRequired:      return "ReverseRequired";
        case LoadResult::TruncationDetected:   return "TruncationDetected";
        case LoadResult::CorruptionDetected:   return "CorruptionDetected";
        case LoadResult::Unknown:              return "Unknown";
        default:                               return "Unknown";
    }
}

} // namespace Deep2

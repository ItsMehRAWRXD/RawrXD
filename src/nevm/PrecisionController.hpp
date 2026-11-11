//=============================================================================
// NEVM Precision Controller
// Dynamic kernel selection based on precision/latency requirements
//=============================================================================

#pragma once

#include "../kernels/KernelRegistry.hpp"
#include <cstdint>
#include <vector>

namespace RawrXD {
namespace NEVM {

// Precision requirements
enum class PrecisionLevel : uint32_t {
    MAXIMUM = 0,    // FP32, no quantization
    HIGH    = 1,    // FP16/BF16
    MEDIUM  = 2,    // Q8
    LOW     = 3,    // Q4
    MINIMUM = 4,    // Q4 with approximations
};

// Latency requirements
enum class LatencyTarget : uint32_t {
    REALTIME = 0,   // < 1ms
    LOW      = 1,   // < 10ms
    MEDIUM   = 2,   // < 100ms
    HIGH     = 3,   // No constraint
};

// Execution choice
struct ExecutionPlan {
    Kernels::QuantType quant;
    Kernels::KernelCaps isa;
    float estimated_error;
    float estimated_latency_ms;
    void* kernel_entry;
    bool available;
};

// Precision controller for NEVM
class PrecisionController {
public:
    // Initialize with current hardware capabilities
    static void Initialize();
    
    // Select best execution plan for operation
    static ExecutionPlan SelectPlan(
        Kernels::KernelOp op,
        PrecisionLevel precision,
        LatencyTarget latency
    );
    
    // Get all available plans for operation
    static std::vector<ExecutionPlan> GetAvailablePlans(
        Kernels::KernelOp op
    );
    
    // Force specific precision (for testing/debugging)
    static void ForcePrecision(PrecisionLevel level);
    
    // Get current policy
    static PrecisionLevel GetCurrentPrecision();

private:
    static PrecisionLevel s_forcedPrecision;
    static bool s_initialized;
};

} // namespace NEVM
} // namespace RawrXD

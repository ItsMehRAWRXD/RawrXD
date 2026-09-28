#pragma once
// ============================================================================
// GpuRejectInstrumentation.hpp — RAWRXD_GPU_REJECT_INSTRUMENTATION_001
//
// First-class rejection telemetry for Deep2 GPU dispatch entry points.
// Captures entry calls, accepted calls, rejected calls, and first-witness
// breakdown by operation and rejection reason.
// ============================================================================

#include <cstdint>
#include <cstring>

namespace rawrxd {
namespace inference {

// ---------------------------------------------------------------------------
// GpuRejectReason — why a forward operation was rejected before GPU execution
// ---------------------------------------------------------------------------
enum class GpuRejectReason : uint32_t {
    None                     = 0,
    VulkanDisabled           = 1,
    VulkanNotInitialized     = 2,
    NoSupportedDevice        = 3,
    BackendUnavailable       = 4,
    NoPlacementPlan          = 5,
    WeightNotResident        = 6,
    UnsupportedQuantType     = 7,
    UnsupportedShape         = 8,
    UnsupportedOperation       = 9,
    KernelLookupMiss         = 10,
    KernelDispatchFailed       = 11,
    StrictFallbackForbidden  = 12,

    // Arena / admission reasons
    ArenaCreateFailed        = 13,
    ArenaBudgetExceeded      = 14,
    WeightWindowAdmissionFailed = 15,
    WeightSlotsInsufficient  = 16,
    OutputInvalid            = 17
};

// ---------------------------------------------------------------------------
// GpuOperation — which forward operation was attempted
// ---------------------------------------------------------------------------
enum class GpuOperation : uint8_t {
    UNKNOWN       = 0,
    EMBED_GATHER  = 1,
    LINEAR        = 2,
    QKV           = 3,
    O_PROJ        = 4,
    FFN           = 5,
    LM_HEAD       = 6
};

// ---------------------------------------------------------------------------
// GpuForwardCounters — first-witness rejection telemetry
// ---------------------------------------------------------------------------
struct GpuForwardCounters {
    uint64_t attempts      = 0;  // total dispatch entry calls
    uint64_t successes     = 0;  // accepted / forwarded to GPU
    uint64_t hostFallbacks = 0;  // rejected before reaching GPU

    GpuRejectReason firstGpuRejectReason = GpuRejectReason::None;
    const char*     firstGpuRejectFile   = nullptr;
    uint32_t        firstGpuRejectLine   = 0;
    uint32_t        firstGpuRejectLayer  = UINT32_MAX;
    uint32_t        firstGpuRejectQuantType = UINT32_MAX;
    char            firstGpuRejectTensor[128]{};
    GpuOperation    firstGpuRejectOp     = GpuOperation::UNKNOWN;

    uint64_t rejectArg0 = 0;
    uint64_t rejectArg1 = 0;
    uint64_t rejectArg2 = 0;
};

// ---------------------------------------------------------------------------
// recordGpuReject — first-witness rejection recorder
// ---------------------------------------------------------------------------
inline void recordGpuReject(GpuForwardCounters& c,
                            GpuRejectReason reason,
                            const char* file,
                            uint32_t line,
                            uint32_t layer,
                            uint32_t quantType,
                            const char* tensor,
                            GpuOperation op,
                            uint64_t arg0 = 0,
                            uint64_t arg1 = 0,
                            uint64_t arg2 = 0)
{
    ++c.hostFallbacks;

    if (c.firstGpuRejectReason != GpuRejectReason::None)
        return;

    c.firstGpuRejectReason   = reason;
    c.firstGpuRejectFile     = file;
    c.firstGpuRejectLine     = line;
    c.firstGpuRejectLayer    = layer;
    c.firstGpuRejectQuantType = quantType;
    c.firstGpuRejectOp       = op;
    c.rejectArg0             = arg0;
    c.rejectArg1             = arg1;
    c.rejectArg2             = arg2;

    if (tensor)
        strncpy_s(c.firstGpuRejectTensor, tensor, _TRUNCATE);
}

} // namespace inference
} // namespace rawrxd

// ---------------------------------------------------------------------------
// GPU_REJECT — site macro for dispatch entry points
// ---------------------------------------------------------------------------
#define GPU_REJECT(counter, reason, layer, qtype, tensor, op, ...) \
    rawrxd::inference::recordGpuReject((counter), (reason), __FILE__, __LINE__, \
                                         (layer), (qtype), (tensor), (op), ##__VA_ARGS__)


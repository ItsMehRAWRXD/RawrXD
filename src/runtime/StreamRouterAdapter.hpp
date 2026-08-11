// ============================================================================
// StreamRouterAdapter.hpp — Bridge B015 residency to Deep2 StreamRouter
// ============================================================================
// Feature-gated adapter. When disabled, falls back to legacy TensorExecutionRouter.
// When enabled, converts ResidentTensor → StreamLoc and dispatches through
// StreamRouter for zero-hop routing.
//
// Phase 1: Adapter only — no behavioral replacement of existing paths.
// ============================================================================
#pragma once
#include "ResidentTensor.hpp"
#include "../../include/Sovereign_ABI.h"
#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>

namespace rawrxd {

// ---------------------------------------------------------------------------
// StreamRouterAdapter — thin bridge, no ownership
// ---------------------------------------------------------------------------
class StreamRouterAdapter {
public:
    StreamRouterAdapter();
    ~StreamRouterAdapter();

    // Initialize with borrowed kernel table (lifetime managed by caller)
    bool Initialize(SovereignKernelTable* kernel_table);

    // Feature gate: when false, all Dispatch calls return false (fallback to legacy)
    void SetEnabled(bool enabled) noexcept { enabled_ = enabled; }
    bool IsEnabled() const noexcept { return enabled_; }

    // Convert ResidentTensor → kernel dispatch and execute
    // Returns true if kernel handled the request; caller must fall back otherwise.
    bool Dispatch(const ExecutionRequest& req);

    // Batch dispatch — up to 8 requests at once
    size_t DispatchBatch8(const ExecutionRequest* reqs, size_t count);

    // Telemetry
    struct Telemetry {
        uint64_t requests_dispatched;
        uint64_t requests_fallback;   // Kernel returned false or not registered
        uint64_t batch_dispatches;
        double   avg_latency_ns;
    };
    Telemetry GetTelemetry() const;
    void ResetTelemetry();

private:
    SovereignKernelTable* kernel_table_ = nullptr;
    bool enabled_ = false;

    // Internal: dispatch a single MatMul through the kernel table
    bool DispatchMatMul_(const ExecutionRequest& req);

    Telemetry telemetry_{};
};

} // namespace rawrxd

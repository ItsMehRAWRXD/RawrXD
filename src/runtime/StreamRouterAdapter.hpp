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
#include "../deep2/StreamRouter.hpp"
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

    // Initialize with borrowed StreamRouter (lifetime managed by caller)
    bool Initialize(Deep2::StreamRouter* router);

    // Feature gate: when false, all Dispatch calls return false (fallback to legacy)
    void SetEnabled(bool enabled) noexcept { enabled_ = enabled; }
    bool IsEnabled() const noexcept { return enabled_; }

    // Convert ResidentTensor → StreamLoc and dispatch
    // Returns true if StreamRouter handled the request; caller must fall back otherwise.
    bool Dispatch(const ExecutionRequest& req);

    // Batch dispatch — up to 8 requests at once (AVX2 path in StreamRouter)
    size_t DispatchBatch8(const ExecutionRequest* reqs, size_t count);

    // Telemetry
    struct Telemetry {
        uint64_t requests_dispatched;
        uint64_t requests_fallback;   // StreamRouter returned false
        uint64_t batch_dispatches;
        double   avg_latency_ns;
    };
    Telemetry GetTelemetry() const;
    void ResetTelemetry();

private:
    Deep2::StreamRouter* router_ = nullptr;
    bool enabled_ = false;

    // Internal: map ResidentTensor to StreamLoc for StreamRouter
    bool MapToStreamLoc_(const ResidentTensor& tensor, Deep2::StreamLoc& out);

    Telemetry telemetry_{};
};

} // namespace rawrxd

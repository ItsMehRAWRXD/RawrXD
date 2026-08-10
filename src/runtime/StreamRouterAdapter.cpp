// ============================================================================
// StreamRouterAdapter.cpp — Bridge implementation
// ============================================================================
// Phase 1: Stub implementation. Compiles and links, but Dispatch returns false
// until StreamRouter integration is wired. This proves the ABI compiles
// without breaking existing paths.
// ============================================================================

#include "StreamRouterAdapter.hpp"
#include <cstdio>
#include <chrono>

namespace rawrxd {

StreamRouterAdapter::StreamRouterAdapter() = default;
StreamRouterAdapter::~StreamRouterAdapter() = default;

bool StreamRouterAdapter::Initialize(Deep2::StreamRouter* router) {
    if (!router) return false;
    router_ = router;
    enabled_ = true;
    printf("[StreamRouterAdapter] Initialized (Phase 1 stub)\n");
    return true;
}

bool StreamRouterAdapter::Dispatch(const ExecutionRequest& req) {
    if (!enabled_ || !router_) {
        return false; // Fallback to legacy path
    }

    auto t0 = std::chrono::high_resolution_clock::now();

    // Phase 1: Log the request but do not actually dispatch yet.
    // This proves the adapter compiles and the feature gate works.
    printf("[StreamRouterAdapter] Dispatch: op=%u layer=%u weights=%s\n",
           static_cast<uint32_t>(req.op),
           req.ctx.layer,
           req.weights ? "present" : "null");

    // TODO(Phase 2): Map ResidentTensor → StreamLoc, then call router_->RouteToken()
    // TODO(Phase 3): For MatMul, use router_->RouteTokenBatch8() for AVX2 throughput

    auto t1 = std::chrono::high_resolution_clock::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    telemetry_.requests_fallback++;
    telemetry_.avg_latency_ns = (telemetry_.avg_latency_ns * (telemetry_.requests_dispatched + telemetry_.requests_fallback - 1) + ns)
                                / (telemetry_.requests_dispatched + telemetry_.requests_fallback);

    return false; // Phase 1: always fallback
}

size_t StreamRouterAdapter::DispatchBatch8(const ExecutionRequest* reqs, size_t count) {
    if (!enabled_ || !router_ || !reqs || count == 0) {
        return 0;
    }

    size_t dispatched = 0;
    for (size_t i = 0; i < count; ++i) {
        if (Dispatch(reqs[i])) {
            ++dispatched;
        }
    }
    telemetry_.batch_dispatches++;
    return dispatched;
}

StreamRouterAdapter::Telemetry StreamRouterAdapter::GetTelemetry() const {
    return telemetry_;
}

void StreamRouterAdapter::ResetTelemetry() {
    telemetry_ = Telemetry{};
}

bool StreamRouterAdapter::MapToStreamLoc_(const ResidentTensor& tensor, Deep2::StreamLoc& out) {
    // Phase 2: Populate StreamLoc from ResidentTensor
    // For now, just zero-init to prove the struct is accessible
    out = Deep2::StreamLoc{};
    out.buffer_base = const_cast<void*>(tensor.data);
    out.buffer_cap = static_cast<uint32_t>(tensor.bytes / sizeof(float));
    return true;
}

} // namespace rawrxd

// ============================================================================
// B014_RingAdapter.cpp — Bridge existing B014 profiler to RingTrapdoor sink
// ============================================================================
// Purpose: Connect the certified B014 profiler to the new RingTrapdoor telemetry
//          layer WITHOUT modifying B014's authoritative behavior.
//
// Architecture:
//   B014Profiler (unchanged, authoritative)
//        │
//        ├── JSON export  ← certification evidence (unchanged)
//        ├── CSV export   ← certification evidence (unchanged)
//        │
//        └── B014_RingAdapter  ← NEW: second sink
//                 │
//                 ▼
//            Sovereign_RingTelemetry
//                 │
//                 ▼
//            SPSC shared ring
//                 │
//                 ▼
//               IDE / Agent
//
// Design:
//   - B014 profiler remains the source of truth.
//   - Adapter subscribes to B014 events and forwards them to the ring.
//   - If ring is unavailable, B014 continues normally.
//   - If ring is full, events are dropped (configurable).
//   - No locks on the inference thread — lock-free SPSC only.
// ============================================================================

#include "b014_profiler.hpp"
#include "Sovereign_ABI.h"
#include <cstdint>
#include <cstring>
#include <windows.h>

namespace b014 {

// ============================================================================
// Adapter state
// ============================================================================
class B014RingAdapter {
public:
    static B014RingAdapter& Instance() {
        static B014RingAdapter inst;
        return inst;
    }

    // Initialize with optional ring config. If config is null, adapter is no-op.
    bool Init(const SovereignRingTelemetryConfig* config) {
        if (!config) {
            enabled_ = false;
            return true;
        }
        enabled_ = Sovereign_RingTelemetry_Init(config);
        if (enabled_) {
            fprintf(stderr, "[B014RingAdapter] Initialized, ring telemetry active\n");
        }
        return enabled_;
    }

    void Shutdown() {
        if (enabled_) {
            Sovereign_RingTelemetry_Shutdown();
            enabled_ = false;
        }
    }

    // Called by B014 profiler hooks (inlined, zero overhead when disabled)
    inline void EmitEvent(uint32_t event_type, uint64_t timestamp_ns,
                          const void* data, size_t data_len) {
        if (!enabled_) return;
        Sovereign_RingTelemetry_Emit(event_type, timestamp_ns, data, data_len);
    }

    // Convenience: emit a simple timing event
    inline void EmitTiming(uint32_t event_type, uint32_t layer,
                           uint64_t start_ns, uint64_t end_ns) {
        if (!enabled_) return;
        struct TimingPayload {
            uint32_t layer;
            uint32_t pad;
            uint64_t start_ns;
            uint64_t end_ns;
            uint64_t duration_ns;
        } payload;
        payload.layer = layer;
        payload.pad = 0;
        payload.start_ns = start_ns;
        payload.end_ns = end_ns;
        payload.duration_ns = end_ns > start_ns ? (end_ns - start_ns) : 0;
        Sovereign_RingTelemetry_Emit(event_type, end_ns, &payload, sizeof(payload));
    }

    bool IsEnabled() const { return enabled_; }

private:
    B014RingAdapter() = default;
    ~B014RingAdapter() { Shutdown(); }
    bool enabled_ = false;
};

} // namespace b014

// ============================================================================
// C API for B014 profiler integration
// ============================================================================

extern "C" {

// Initialize the adapter. Call once after B014 profiler is set up.
bool B014_RingAdapter_Init(const SovereignRingTelemetryConfig* config) {
    return b014::B014RingAdapter::Instance().Init(config);
}

// Shutdown the adapter. Call before destroying B014 profiler.
void B014_RingAdapter_Shutdown() {
    b014::B014RingAdapter::Instance().Shutdown();
}

// Emit a raw event into the ring
void B014_RingAdapter_Emit(uint32_t event_type, uint64_t timestamp_ns,
                            const void* data, size_t data_len) {
    b014::B014RingAdapter::Instance().EmitEvent(event_type, timestamp_ns, data, data_len);
}

// Emit a timing event (layer-scoped)
void B014_RingAdapter_EmitTiming(uint32_t event_type, uint32_t layer,
                                  uint64_t start_ns, uint64_t end_ns) {
    b014::B014RingAdapter::Instance().EmitTiming(event_type, layer, start_ns, end_ns);
}

// Check if ring telemetry is active
bool B014_RingAdapter_IsEnabled() {
    return b014::B014RingAdapter::Instance().IsEnabled();
}

} // extern "C"

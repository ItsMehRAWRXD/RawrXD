#pragma once
#include "Deep2StackGuard.h"
#include "ExpertScheduler.h"
#include <cstdint>

namespace rawrxd {
struct Batch005Runtime {
    StackSafetyTelemetry stack;
    SchedulerTelemetry scheduler;
    uint32_t maxForwardDepth{8};
    size_t initialScratchBytes{8u * 1024u * 1024u};
};

// Call at the very top of Deep2Engine::forward / forwardLayer.
// Returns false instead of allowing runaway recursive re-entry.
inline bool enterForward(Batch005Runtime& rt, ForwardDepthGuard& guard) noexcept {
    rt.stack.forwardEntries.fetch_add(1, std::memory_order_relaxed);
    updateMaxDepth(rt.stack, guard.depth());
    if (!guard.ok()) {
        rt.stack.recursionRejects.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    return true;
}
} // namespace rawrxd

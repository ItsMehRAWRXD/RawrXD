#include "Deep2B59StabilityGovernor.hpp"

namespace Deep2 {

B59Plan B59StabilityGovernor::make(const B59Telemetry& t) noexcept {
    B59Plan p{};

    if (t.thermalThrottleEvents || t.driverRetryEvents) {
        p.holdTuning = true;
        p.reduceConcurrency = true;
        p.reducePrefetch = true;
        p.disableSpeculation = true;
        p.recertify = true;
        p.concurrencyScalePct = 80;
        return p;
    }

    if (t.baselineTps > 0.0 && t.recentTps < t.baselineTps * 0.95) {
        p.holdTuning = true;
        p.recertify = true;
        p.concurrencyScalePct = 90;
    }

    if (t.recentSkew > 0.05 || t.recentQueueIdle > 0.03) {
        p.reduceConcurrency = true;
        p.concurrencyScalePct = p.concurrencyScalePct > 90 ? 90 : p.concurrencyScalePct;
    }

    return p;
}

}

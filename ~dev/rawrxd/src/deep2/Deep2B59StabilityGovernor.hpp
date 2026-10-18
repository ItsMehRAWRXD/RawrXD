#pragma once
#include <cstdint>

namespace Deep2 {

struct B59Telemetry {
    double recentTps = 0.0;
    double baselineTps = 0.0;
    double recentBandwidthFraction = 0.0;
    double recentComputeFraction = 0.0;
    double recentSkew = 0.0;
    double recentQueueIdle = 0.0;
    uint32_t thermalThrottleEvents = 0;
    uint32_t driverRetryEvents = 0;
};

struct B59Plan {
    bool holdTuning = false;
    bool reduceConcurrency = false;
    bool reducePrefetch = false;
    bool disableSpeculation = false;
    bool recertify = false;
    uint32_t concurrencyScalePct = 100;
};

class B59StabilityGovernor {
public:
    static B59Plan make(const B59Telemetry&) noexcept;
};

}

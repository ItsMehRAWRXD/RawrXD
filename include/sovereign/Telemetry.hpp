#pragma once
#include <cstdint>

namespace Sovereign {
namespace Telemetry {
    struct Snapshot {
        float tokensPerSec = 0.0f;
        float nvmeBandwidthMBps = 0.0f;
        float thermalC = 0.0f;
    };
    inline Snapshot GetSnapshot() { return Snapshot{}; }
}
}

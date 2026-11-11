#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>

namespace Deep2 {

struct B67TokenTelemetry {
    uint64_t tokenIndex = 0;
    uint64_t wallNs = 0;
    uint64_t gpu0Ns = 0;
    uint64_t gpu1Ns = 0;
    uint64_t overlapNs = 0;
    uint64_t hostSyncNs = 0;
    uint64_t queueIdleNs = 0;

    uint64_t bytesRead = 0;
    uint64_t bytesWritten = 0;
    double flops = 0.0;

    uint64_t weightReloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;

    uint64_t gpu0Forwards = 0;
    uint64_t gpu1Forwards = 0;

    bool parity = false;
    bool stableOutput = false;
};

struct B67Derived {
    double rawTps = 0.0;
    double measuredBandwidthGBs = 0.0;
    double measuredComputeTFLOPs = 0.0;
    double overlapFraction = 0.0;
    double completionSkew = 1.0;
    double hostSyncFraction = 1.0;
    double queueIdleFraction = 1.0;
};

class B67LiveTelemetry {
public:
    static B67Derived derive(const B67TokenTelemetry&) noexcept;
    static bool validSteadySample(const B67TokenTelemetry&) noexcept;
};

} // namespace Deep2

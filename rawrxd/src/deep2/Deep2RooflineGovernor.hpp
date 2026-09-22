#pragma once
#include "Deep2DualGpuBalancer.hpp"

namespace Deep2::Roofline {

struct GovernorDecision {
    SplitPlan split{};
    u32 prefetchDepth = 1;
    bool useFusedBatch = true;
    bool bandwidthBound = true;
    bool useColumnSplit = false;
    double measuredTps = 0.0;
    double estimatedRooflineTps = 0.0;
    double rooflineFraction = 0.0;
    double speculativeAcceptanceRatio = 0.0;
    double specWindowMultiplier = 1.0;
};

class RooflineGovernor {
public:
    explicit RooflineGovernor(HardwareProfile hw = R9700_Rx7800XT()) : hw_(hw) {}
    GovernorDecision decide(u32 rows, u64 bytesPerToken, double teraOpsPerToken,
                            const TokenMetrics* previous) const noexcept;
    const HardwareProfile& hardware() const noexcept { return hw_; }
private:
    HardwareProfile hw_{};
};

} // namespace Deep2::Roofline

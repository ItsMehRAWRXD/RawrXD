#include "Deep2RooflineGovernor.hpp"

namespace Deep2::Roofline {

GovernorDecision RooflineGovernor::decide(u32 rows, u64 bytesPerToken, double teraOpsPerToken,
                                          const TokenMetrics* prev) const noexcept {
    GovernorDecision d{};
    const auto est = EstimateRoofline(hw_, bytesPerToken, teraOpsPerToken);
    d.estimatedRooflineTps = est.rooflineTps;
    d.bandwidthBound = est.bandwidthLimitedTps <= est.computeLimitedTps;

    double f0 = hw_.gpuBandwidthGBs[0] / (hw_.gpuBandwidthGBs[0] + hw_.gpuBandwidthGBs[1]);
    if (prev && prev->gpu[0].elapsedNs && prev->gpu[1].elapsedNs) {
        const double r0 = prev->gpu[0].workUnits / static_cast<double>(prev->gpu[0].elapsedNs);
        const double r1 = prev->gpu[1].workUnits / static_cast<double>(prev->gpu[1].elapsedNs);
        if (r0 + r1 > 0.0) f0 = r0 / (r0 + r1);
        d.measuredTps = prev->tps();
        if (d.estimatedRooflineTps > 0.0) d.rooflineFraction = d.measuredTps / d.estimatedRooflineTps;
        const double missRate = (prev->prefetchHits + prev->prefetchMisses)
            ? static_cast<double>(prev->prefetchMisses) / static_cast<double>(prev->prefetchHits + prev->prefetchMisses)
            : 0.0;
        d.prefetchDepth = missRate > 0.20 ? 3u : (missRate > 0.05 ? 2u : 1u);
        const double skew = prev->completionSkew();
        const double overlap = prev->overlapRatio();
        d.useColumnSplit = (skew > 0.25) && (overlap > 0.50);
        if (prev->speculativeProposed > 0) {
            d.speculativeAcceptanceRatio = static_cast<double>(prev->speculativeAccepted) / static_cast<double>(prev->speculativeProposed);
            d.specWindowMultiplier = 1.0 + d.speculativeAcceptanceRatio;
        }
    }

    f0 = std::clamp(f0, 0.10, 0.90);
    u32 r0 = RoundRows(static_cast<u32>(std::llround(rows * f0)), 32);
    if (r0 > rows) r0 = rows;
    d.split.rows[0] = r0;
    d.split.rows[1] = rows - r0;
    d.split.fraction[0] = rows ? static_cast<double>(r0) / rows : 0.5;
    d.split.fraction[1] = 1.0 - d.split.fraction[0];
    d.useFusedBatch = !prev || prev->gpu[0].waitNs + prev->gpu[1].waitNs > 0 || prev->tokenWallNs < 1000000000ull;
    return d;
}

} // namespace Deep2::Roofline

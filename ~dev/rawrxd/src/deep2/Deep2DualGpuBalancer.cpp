#include "Deep2DualGpuBalancer.hpp"

namespace Deep2::Roofline {

void DualGpuBalancer::reset() noexcept { rate_[0] = rate_[1] = 0.0; }

void DualGpuBalancer::update(unsigned gpu, const DeviceSample& s) noexcept {
    if (gpu >= 2 || !s.elapsedNs || s.workUnits <= 0.0) return;
    const double observed = s.workUnits / static_cast<double>(s.elapsedNs);
    if (rate_[gpu] == 0.0) rate_[gpu] = observed;
    else rate_[gpu] = cfg_.ewmaAlpha * observed + (1.0 - cfg_.ewmaAlpha) * rate_[gpu];
}

SplitPlan DualGpuBalancer::plan(u32 totalRows) const noexcept {
    SplitPlan p{};
    double f0 = 0.5;
    const double sum = rate_[0] + rate_[1];
    if (sum > 0.0) f0 = rate_[0] / sum;
    f0 = std::clamp(f0, cfg_.minFraction, cfg_.maxFraction);

    u32 r0 = RoundRows(static_cast<u32>(std::llround(totalRows * f0)), cfg_.rowGranularity);
    if (r0 > totalRows) r0 = totalRows;
    u32 r1 = totalRows - r0;
    if (totalRows && !r0) { r0 = std::min(cfg_.rowGranularity, totalRows); r1 = totalRows - r0; }
    if (totalRows > cfg_.rowGranularity && !r1) { r1 = cfg_.rowGranularity; r0 = totalRows - r1; }

    p.rows[0] = r0; p.rows[1] = r1;
    p.fraction[0] = totalRows ? static_cast<double>(r0) / totalRows : 0.5;
    p.fraction[1] = 1.0 - p.fraction[0];
    return p;
}

} // namespace Deep2::Roofline

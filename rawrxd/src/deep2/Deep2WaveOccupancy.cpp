#include "Deep2WaveOccupancy.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

OccupancyPlan WaveOccupancyScheduler::make(const OccupancyInput& in,
                                           const DeviceRoofline& gpu0,
                                           const DeviceRoofline& gpu1) noexcept {
    OccupancyPlan p{};
    if (!in.totalRows) return p;

    double s0 = gpu0.bandwidthGBs > 0.0 ? gpu0.bandwidthGBs : 1.0;
    double s1 = gpu1.bandwidthGBs > 0.0 ? gpu1.bandwidthGBs : 1.0;

    if (in.recentGpu0NsPerRow > 0.0) s0 = 1.0 / in.recentGpu0NsPerRow;
    if (in.recentGpu1NsPerRow > 0.0) s1 = 1.0 / in.recentGpu1NsPerRow;

    const double frac0 = s0 / (s0 + s1);
    p.gpu0Rows = static_cast<uint32_t>(std::llround(double(in.totalRows) * frac0));
    p.gpu0Rows = std::min(p.gpu0Rows, in.totalRows);
    p.gpu1Rows = in.totalRows - p.gpu0Rows;

    const uint32_t wave = std::max(gpu0.waveWidth, gpu1.waveWidth);
    p.workgroupSize = wave >= 64 ? 256u : 128u;
    p.wavesPerGroup = std::max(1u, p.workgroupSize / std::max(1u, wave));

    // Conservative occupancy model. Production backend may override after timing.
    uint32_t regLimit = in.regsPerThread > 96 ? 1u : (in.regsPerThread > 64 ? 2u : 4u);
    uint32_t smemLimit = in.sharedBytesPerGroup > 32768 ? 1u :
                         (in.sharedBytesPerGroup > 16384 ? 2u : 4u);
    p.groupsPerCU = std::max(1u, std::min(regLimit, smemLimit));
    return p;
}

} // namespace Deep2

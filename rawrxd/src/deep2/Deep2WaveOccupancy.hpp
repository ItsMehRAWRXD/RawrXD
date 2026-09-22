#pragma once
#include "Deep2RooflineTypes.hpp"
#include <cstdint>

namespace Deep2 {

struct OccupancyInput {
    uint32_t totalRows = 0;
    uint32_t regsPerThread = 0;
    uint32_t sharedBytesPerGroup = 0;
    double recentGpu0NsPerRow = 0.0;
    double recentGpu1NsPerRow = 0.0;
};

struct OccupancyPlan {
    uint32_t gpu0Rows = 0;
    uint32_t gpu1Rows = 0;
    uint32_t groupsPerCU = 1;
    uint32_t wavesPerGroup = 1;
    uint32_t workgroupSize = 64;
};

class WaveOccupancyScheduler {
public:
    static OccupancyPlan make(const OccupancyInput& in,
                              const DeviceRoofline& gpu0,
                              const DeviceRoofline& gpu1) noexcept;
};

} // namespace Deep2

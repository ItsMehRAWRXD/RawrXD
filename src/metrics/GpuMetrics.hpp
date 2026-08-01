#pragma once
#include <string>
#include <vector>
#include <windows.h>

struct GpuAdapterSnapshot {
    std::string deviceName;
    size_t dedicatedVramBytes;
    size_t allocatedVramBytes;
    unsigned int utilizationPercent;
};

class GpuMetrics {
public:
    GpuMetrics() = default;
    std::vector<GpuAdapterSnapshot> PollHardwareGraphicsAdapters();
};

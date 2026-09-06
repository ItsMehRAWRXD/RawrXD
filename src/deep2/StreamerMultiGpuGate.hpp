// StreamerMultiGpuGate.hpp — STREAMER_MULTIGPU_001 topology + sync probes
#pragma once
#include <cstdio>
#include <cstdint>

namespace Deep2 {

struct MultiGpuAdapterInfo {
    char name[128];
    uint64_t dedicatedVramBytes;
    uint32_t vendorId;
};

struct MultiGpuGateReport {
    unsigned adapterCount = 0;
    MultiGpuAdapterInfo adapters[8]{};
    bool syncGateOk = false;
    bool vulkanIcdBlocked = false;
    unsigned gpuComputeActive = 0;
    const char* backend = "CPU_NATIVE";
    const char* laneA = "NOT_WIRED";
    const char* laneB = "NOT_WIRED";
    const char* laneC = "NOT_WIRED";
    const char* laneD = "NOT_WIRED";
    const char* gateStatus = "SEALED_BLOCKED";
    const char* blocker = "GGUF_DECODE_NOT_ON_GPU";
};

// Real DXGI enum + Local\\ MultiGpu sync map. Does not claim GPU decode.
bool RunStreamerMultiGpuGate(MultiGpuGateReport& out) noexcept;
void EmitStreamerMultiGpuWitnesses(FILE* f, const MultiGpuGateReport& r) noexcept;

} // namespace Deep2

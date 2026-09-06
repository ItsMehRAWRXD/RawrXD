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
    const char* laneA = "HOST_SYNC_MAP";
    const char* laneB = "DUAL_ADAPTER_DXGI";
    const char* laneC = "CONTIGUOUS_LAYER_PLAN";
    const char* laneD = "RESIDENT_GEMV_EXEC";
    const char* gateStatus = "SEALED_BLOCKED";
    const char* blocker = "NONE";
};

// DXGI enum + sync map; lanes wired to MULTI_GPU_LAYER / HYBRID real exec path.
bool RunStreamerMultiGpuGate(MultiGpuGateReport& out) noexcept;
void EmitStreamerMultiGpuWitnesses(FILE* f, const MultiGpuGateReport& r) noexcept;

} // namespace Deep2

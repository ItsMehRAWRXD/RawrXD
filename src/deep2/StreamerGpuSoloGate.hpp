#pragma once
#include <cstdio>
#include <cstdint>

namespace Deep2 {

struct GpuSoloAdapter {
    char name[128];
    uint64_t dedicatedVramBytes = 0;
    uint64_t sharedVramBytes = 0;
    uint32_t vendorId = 0;
    uint32_t role = 3;
    const char* duty = "DETECTED/UNUSED";
};

struct GpuSoloReport {
    unsigned adapterCount = 0;
    GpuSoloAdapter adapters[8]{};
    int openIndex = -1;
    const char* selectedName = "";
    unsigned vkPhysCount = 0;
    int vkCreateSelected = -1;
    unsigned gpuComputeActive = 0;
    unsigned realGpuForward = 0;
    unsigned cpuFallbackUsed = 1;
    unsigned realWeightLayers = 0;
    const char* backend = "CPU_NATIVE";
    const char* gateStatus = "SEALED_BLOCKED";
    const char* blocker = "GGUF_DECODE_NOT_ON_GPU";
};

extern "C" unsigned GpuSolo_ScoreAdapter(unsigned long long dedicated,
                                         unsigned long long shared,
                                         unsigned flags);
extern "C" int GpuSolo_PickOpenIndex(const unsigned* roles,
                                    const unsigned long long* vram,
                                    unsigned count,
                                    unsigned wantRole);

bool RunStreamerGpuSoloSelect(GpuSoloReport& out) noexcept;
int RunStreamerGpuSoloVkProbe(GpuSoloReport& out) noexcept;
void EmitStreamerGpuSoloWitnesses(FILE* f, const GpuSoloReport& r) noexcept;

} // namespace Deep2

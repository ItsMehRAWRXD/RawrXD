// deep2_gpu_solo_cert.cpp — STREAMER_GPU_SOLO_001: open one primary (generic)
#define _CRT_SECURE_NO_WARNINGS
#include "StreamerGpuSoloGate.hpp"
#include <cstdio>

int main() {
    Deep2::GpuSoloReport r{};
    printf("============================================================\n");
    printf("STREAMER_GPU_SOLO_001\n");
    printf("============================================================\n");
    const bool classified = Deep2::RunStreamerGpuSoloSelect(r);
    if (classified && r.openIndex >= 0)
        Deep2::RunStreamerGpuSoloVkProbe(r);
    r.gpuComputeActive = 0;
    r.realGpuForward = 0;
    r.cpuFallbackUsed = 1;
    r.backend = "CPU_NATIVE";
    r.gateStatus = "SEALED_BLOCKED";
    if (r.openIndex < 0)
        r.blocker = "NO_COMPUTE_PRIMARY";
    else if (r.vkCreateSelected == 1)
        r.blocker = "GGUF_DECODE_NOT_ON_GPU";
    FILE* vf = fopen("G:\\~dev\\rawrxd\\evidence\\STREAMER_CERT_001\\STREAMER_GPU_SOLO_001.txt", "w");
    Deep2::EmitStreamerGpuSoloWitnesses(vf, r);
    if (vf) fclose(vf);
    printf("NOTE=enumerate_all_open_one; forward_not_wired; cpu_certified_path_intact\n");
    printf("============================================================\n");
    return classified && r.openIndex >= 0 ? 0 : 1;
}

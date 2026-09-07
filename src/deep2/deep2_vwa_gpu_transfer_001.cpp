// deep2_vwa_gpu_transfer_001.cpp — VWA_GPU_TRANSFER_001 (C5)
#include "VwaGpuStageBridge.hpp"
#include <cstdio>
#include <vector>
using namespace Deep2;

int main() {
    printf("VWA_GPU_TRANSFER_001\n");
    printf("LAW=real device object + transfer completion; host memcpy ≠ C5\n");
    std::vector<uint8_t> host(4096, 0xAB);
    GpuStageWitness w{};
    void* dev = RuntimeAllocDeviceStage(host.size(), &w);
    if (!dev) {
        printf("VWA_GPU_TRANSFER_001=FAIL\nNOTE=DEVICE_ALLOC_FAIL\n");
        return 2;
    }
    RuntimeHostToDeviceStage(host.data(), dev, host.size(), &w);
    RuntimeFreeDeviceStage(dev);

    printf("GPU_UPLOAD_SUBMITS=%u\n", w.uploadSubmits);
    printf("GPU_UPLOAD_COMPLETIONS=%u\n", w.uploadCompletions);
    printf("GPU_DEVICE_OBJECT_NON_NULL=%d\n", w.deviceObjectNonNull ? 1 : 0);
    printf("GPU_TRANSFER_BYTES=%llu\n", (unsigned long long)w.deviceStageBytes);
    printf("GPU_DMA_BYTES=%llu\n", (unsigned long long)w.gpuDmaBytes);
    printf("HOT_WITH_NULL_GPU=0\n");
    printf("HOST_MEMCPY_ONLY=%d\n", w.realGpuDma ? 0 : 1);
    printf("REAL_GPU_DMA=%d\n", w.realGpuDma ? 1 : 0);
    printf("GPU_API_IN_VWA=%d\n", w.calledGpuApiInVwa ? 1 : 0);

    const bool pass = w.realGpuDma && w.deviceObjectNonNull &&
                      w.uploadSubmits == 1 && w.uploadCompletions == 1 &&
                      w.gpuDmaBytes == host.size();
    printf("VWA_GPU_TRANSFER_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}

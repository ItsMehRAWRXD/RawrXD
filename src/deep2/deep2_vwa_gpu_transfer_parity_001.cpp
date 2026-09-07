// deep2_vwa_gpu_transfer_parity_001.cpp — VWA_GPU_TRANSFER_PARITY_001
#include "VwaConsumerHarness.hpp"
#include "VwaGpuStageBridge.hpp"
#include <cstdio>
#include <cstring>
using namespace Deep2;
using namespace Deep2::vwa_harness;

int main() {
    printf("VWA_GPU_TRANSFER_PARITY_001\n");
    Shard s; MakeQ4KShard(s, 512, 4);
    PhysicalTensorRange r{}; ResolveBlocks(s, 0, 4, r);
    const uint8_t* host = s.bytes.data() + (size_t)r.absoluteFileOffset;
    GpuStageWitness w{};
    void* dev = RuntimeAllocDeviceStage((size_t)r.byteCount, &w);
    RuntimeHostToDeviceStage(host, dev, (size_t)r.byteCount, &w);
    int ok = std::memcmp(host, dev, (size_t)r.byteCount) == 0;
    printf("HOST_STAGE_BYTES=%llu\nDEVICE_STAGE_BYTES=%llu\nPARITY=%d\n",
           (unsigned long long)w.hostStageBytes,
           (unsigned long long)w.deviceStageBytes, ok);
    printf("GPU_DMA_CLAIMED=0\nDEVICE_SELECTION_IN_VWA=0\n");
    RuntimeFreeDeviceStage(dev);
    if (!ok) return 2;
    printf("VWA_GPU_TRANSFER_PARITY_001=PASS\n");
    return 0;
}

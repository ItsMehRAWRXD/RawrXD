// deep2_vwa_gpu_stage_001.cpp — VWA_GPU_STAGE_001
#include "VwaConsumerHarness.hpp"
#include "VwaElasticBridge.hpp"
#include "VwaGpuStageBridge.hpp"
#include "vwa/VwaPhysical.hpp"
#include <cstdio>
using namespace Deep2;
using namespace Deep2::vwa_harness;

int main() {
    printf("VWA_GPU_STAGE_001\n");
    printf("LAW=runtime placement stages host→device; VWA does not select GPU\n");
    Shard s; MakeQ4KShard(s, 1024, 8);
    PhysicalTensorRange r{}; ResolveBlocks(s, 1, 2, r);
    vwa::MemoryBackend mem; mem.MapShard(0, s.bytes.data(), s.bytes.size());
    ElasticResidencyManager elastic;
    ElasticResidencyConfig cfg; cfg.useQuantizedGpuPath = true;
    elastic.Initialize(cfg); elastic.SetPhysicalBackend(&mem);
    ElasticRegisterPhysicalRange(elastic, "gpu.t", r, TensorFormat::Q4_K);
    ElasticResidencyManager::ResidencyHandle h{};
    elastic.AcquireTensor("gpu.t", 0, /*needVram*/1, h);
    if (!h.cpuPtr) return 2;

    GpuStageWitness gw{};
    void* dev = RuntimeAllocDeviceStage((size_t)r.byteCount, &gw);
    if (!dev) {
        printf("VWA_GPU_STAGE_001=FAIL\nNOTE=DEVICE_ALLOC_FAIL\n");
        return 3;
    }
    if (!RuntimeHostToDeviceStage(h.cpuPtr, dev, (size_t)r.byteCount, &gw)) {
        RuntimeFreeDeviceStage(dev);
        printf("VWA_GPU_STAGE_001=FAIL\nNOTE=H2D_FAIL\n");
        return 4;
    }

    printf("HOST_STAGE_BYTES=%llu\n", (unsigned long long)gw.hostStageBytes);
    printf("DEVICE_STAGE_BYTES=%llu\n", (unsigned long long)gw.deviceStageBytes);
    printf("GPU_DMA_BYTES=%llu\n", (unsigned long long)gw.gpuDmaBytes);
    printf("GPU_UPLOAD_SUBMITS=%u\n", gw.uploadSubmits);
    printf("GPU_UPLOAD_COMPLETIONS=%u\n", gw.uploadCompletions);
    printf("REAL_GPU_DMA=%d\n", gw.realGpuDma ? 1 : 0);
    printf("DEVICE_SELECTION_IN_VWA=%d\n", gw.deviceSelectionInVwa ? 1 : 0);
    printf("GPU_API_IN_VWA=%d\n", gw.calledGpuApiInVwa ? 1 : 0);
    RuntimeFreeDeviceStage(dev);
    elastic.ReleaseTensor("gpu.t"); elastic.Shutdown();

    const bool pass = gw.realGpuDma && gw.gpuDmaBytes == r.byteCount &&
                      gw.uploadSubmits == 1 && gw.uploadCompletions == 1 &&
                      !gw.deviceSelectionInVwa && !gw.calledGpuApiInVwa;
    printf("VWA_GPU_STAGE_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 5;
}

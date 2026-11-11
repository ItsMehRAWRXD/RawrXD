// Batch9_VulkanMultiGpuCert.cpp
// Hardware/runtime proof only. It does NOT mint full-model authority.
#include "vulkan_compute.h"
#include "Deep2GpuOverlapWitness.hpp"

#include <algorithm>
#include <cstdio>
#include <future>
#include <vector>

int main() {
    using namespace Deep2;

    auto devs=VulkanCompute::EnumeratePhysicalDevices();
    std::printf("BATCH9_ENUM_COUNT=%zu\n",devs.size());
    for(const auto& d:devs)
        std::printf("DEVICE ordinal=%u compute=%u discrete=%u vendor=0x%04x "
                    "vram=%llu name=%s\n",
                    d.ordinal,d.compute?1u:0u,d.discrete?1u:0u,d.vendorId,
                    (unsigned long long)d.deviceLocalBytes,d.name.c_str());

    std::vector<VulkanPhysicalInfo> compute;
    for(const auto& d:devs) if(d.compute) compute.push_back(d);
    if(compute.empty()) {
        std::puts("BATCH9_DEVICE_RUNTIME=HOLD_NO_COMPUTE_DEVICE");
        return 2;
    }

    VulkanCompute g0(compute[0].ordinal);
    if(!g0.initialize()){
        std::puts("BATCH9_GPU0_INIT=FAIL");
        return 3;
    }
    const bool p0=g0.RunComputeProbe(1u<<18,1.25f,-0.5f,nullptr);
    std::printf("BATCH9_GPU0_PROBE=%s\n",p0?"PASS":"FAIL");
    if(!p0) return 4;

    if(compute.size()<2){
        std::puts("BATCH9_DUAL_GPU=HOLD_ONLY_ONE_COMPUTE_DEVICE");
        return 0;
    }

    VulkanCompute g1(compute[1].ordinal);
    if(!g1.initialize()){
        std::puts("BATCH9_GPU1_INIT=FAIL");
        return 5;
    }

    constexpr uint64_t epoch=0xB90001ull;
    g0.SetWorkEpoch(epoch);
    g1.SetWorkEpoch(epoch);

    auto f0=std::async(std::launch::async,[&]{
        return g0.RunComputeProbe(1u<<20,0.75f,0.25f,nullptr);
    });
    auto f1=std::async(std::launch::async,[&]{
        return g1.RunComputeProbe(1u<<20,-0.5f,1.0f,nullptr);
    });

    const bool a=f0.get(),b=f1.get();
    std::printf("BATCH9_DUAL_PROBE=%s\n",(a&&b)?"PASS":"FAIL");
    if(!a||!b) return 6;

    // CapabilityProbe intervals are intentionally excluded from product
    // temporal authority. This prints hardware timing capability only.
    auto i0=g0.LastInterval();
    auto i1=g1.LastInterval();
    const uint64_t hostOverlap=Deep2IntervalOverlapNs(
        i0.hostSubmitNs,i0.hostCompleteNs,i1.hostSubmitNs,i1.hostCompleteNs);
    const uint64_t gpuOverlap=(i0.calibrated&&i1.calibrated)
        ?Deep2IntervalOverlapNs(
            i0.gpuStartNs,i0.gpuEndNs,i1.gpuStartNs,i1.gpuEndNs):0;

    std::printf("CAPABILITY_HOST_OVERLAP_NS=%llu\n",
                (unsigned long long)hostOverlap);
    std::printf("CAPABILITY_CALIBRATED=%u\n",
                (i0.calibrated&&i1.calibrated)?1u:0u);
    std::printf("CAPABILITY_GPU_OVERLAP_NS=%llu\n",
                (unsigned long long)gpuOverlap);
    std::puts("PRODUCT_TEMPORAL_AUTHORITY=0");
    std::puts("FULL_MODEL_E2E_PASS=0");
    return 0;
}

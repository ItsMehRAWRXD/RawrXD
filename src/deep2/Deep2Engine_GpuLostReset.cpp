// Deep2Engine_GpuLostReset.cpp — VK_ERROR_DEVICE_LOST / Code31 → destroy+reinit
#include "Deep2Engine.h"
#include "GpuPreflight.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "lavapath/DualStickExpertBundle.hpp"
#include <cstdio>

namespace Deep2 {

bool Deep2Engine::anyVulkanDeviceLost() const {
    for (unsigned s = 0; s < vulkanDevices_.size(); ++s) {
        auto* vc = vulkanDevices_[s].get();
        if (vc && vc->IsDeviceLost()) return true;
    }
    if (vulkanCompute_ && vulkanCompute_->IsDeviceLost()) return true;
    return false;
}

bool Deep2Engine::recoverVulkanAfterDeviceLost() {
    std::fprintf(stderr, "GPU_LOST_RECOVER_BEGIN\n");
    std::fflush(stderr);
    if (!anyVulkanDeviceLost() && !vulkanInitialized_) {
        std::fprintf(stderr, "GPU_LOST_RECOVER=SKIP reason=NOT_LOST\n");
        std::fflush(stderr);
        return false;
    }

    // PnP Code 31 / ERROR_GEN_FAILURE: recognize + DevNode reset before Vulkan reopen.
    {
        auto gpus = EnumerateGpuHealth();
        int code31 = 0;
        for (const auto& g : gpus) {
            if (GpuIsCode31(g.problem)) {
                ++code31;
                std::fprintf(stderr,
                             "GPU_LOST_CODE31_SEEN problem=%lu started=%d name=%ls\n",
                             g.problem, g.started ? 1 : 0, g.friendlyName.c_str());
            }
        }
        std::fprintf(stderr, "GPU_LOST_CODE31_COUNT=%d\n", code31);
        std::fflush(stderr);
    }
    (void)GpuPreflightCheck(/*allowCpuOnly=*/true);

    DualStickBindVc(0, nullptr);
    DualStickBindVc(1, nullptr);
    DualStickBundleTableReset();

    for (auto& vc : vulkanDevices_) {
        if (vc) {
            vc->ClearPinnedGemvWeights();
            vc->ReleaseWeightWindow();
        }
    }
    vulkanDevices_.clear();
    vulkanCompute_.reset();
    vulkanInitialized_ = false;
    vulkanEnabled_ = false;
    multiGpuLayerPlan_ = MultiGpuLayerPlan{};
    ++residencyEpoch_;
    ++dualStickResetEvents_;
    std::fprintf(stderr, "GPU_LOST_DESTROY_OK residency_epoch=%llu\n",
                 (unsigned long long)residencyEpoch_);
    std::fflush(stderr);

    enableVulkan(true);
    const bool ok = vulkanInitialized_ && !vulkanDevices_.empty() &&
                    !anyVulkanDeviceLost();
    std::fprintf(stderr, "GPU_LOST_RECOVER=%s devices=%zu creates=%llu\n",
                 ok ? "PASS" : "FAIL", vulkanDevices_.size(),
                 (unsigned long long)deviceCreateEvents_);
    std::fflush(stderr);
    return ok;
}

} // namespace Deep2

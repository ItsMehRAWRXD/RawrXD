// ============================================================================
// Deep2Engine_VulkanRuntime.cpp — Batch 9 physical-device runtime binding
// ============================================================================
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "Deep2GpuOverlapWitness.hpp"
#include "vulkan_compute.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace Deep2 {

namespace {

int deviceScore(const VulkanPhysicalInfo& d) {
    int score = 0;
    if (d.compute) score += 100000;
    if (d.discrete) score += 10000;
    if (d.vendorId == 0x1002) score += 1000; // rawr's AMD pair first
    score += static_cast<int>(
        std::min<uint64_t>(d.deviceLocalBytes >> 30, 512));
    return score;
}

} // namespace

void Deep2Engine::enableVulkan(bool enable) {
    if (!enable) {
        vulkanDevices_.clear();
        vulkanCompute_.reset();
        multiGpuLayerPlan_.clear();
        vulkanEnabled_ = false;
        vulkanInitialized_ = false;
        gpuFwdCommitted_ = false;
        return;
    }

    vulkanEnabled_ = true;
    vulkanInitialized_ = false;
    vulkanStrictViolation_ = false;
    vulkanDevices_.clear();
    vulkanCompute_.reset();
    multiGpuLayerPlan_.clear();

    auto devs = VulkanCompute::EnumeratePhysicalDevices();
    devs.erase(
        std::remove_if(devs.begin(),devs.end(),
            [](const VulkanPhysicalInfo& d){ return !d.compute; }),
        devs.end());

    std::stable_sort(devs.begin(),devs.end(),
        [](const VulkanPhysicalInfo& a,const VulkanPhysicalInfo& b){
            const int sa=deviceScore(a), sb=deviceScore(b);
            if(sa!=sb) return sa>sb;
            return a.ordinal<b.ordinal;
        });

    // Deep2 Batch 9 owns a maximum of two physical sticks because the current
    // product plan and receipts are dual-stick authority.
    for (size_t i=0; i<devs.size() && vulkanDevices_.size()<2; ++i) {
        auto vc=std::make_unique<VulkanCompute>(devs[i].ordinal);
        if (!vc->initialize()) {
            std::fprintf(stderr,
                "BATCH9_DEVICE_REJECT ordinal=%u name=%s reason=INITIALIZE_FAIL\n",
                devs[i].ordinal,devs[i].name.c_str());
            continue;
        }
        vulkanDevices_.push_back(std::move(vc));
    }

    if (vulkanDevices_.empty()) {
        vulkanStrictViolation_ = vulkanStrictNoCpuFallback_;
        std::fprintf(stderr,
            "BATCH9_VULKAN_INIT=HOLD no_compute_device_initialized\n");
        return;
    }

    if (modelWeights.loaded && modelWeights.numLayers) {
        std::vector<uint64_t> caps;
        for (const auto& d : vulkanDevices_)
            caps.push_back(d->deviceLocalBytes());
        if (!multiGpuLayerPlan_.configure(modelWeights.numLayers,caps,false,0)) {
            std::fprintf(stderr,"BATCH9_MULTIGPU_PLAN=HOLD\n");
            if (vulkanStrictNoCpuFallback_) {
                vulkanDevices_.clear();
                vulkanStrictViolation_=true;
                return;
            }
        }
    }

    vulkanInitialized_=true;
    std::fprintf(stdout,
        "BATCH9_VULKAN_INIT=DEVICE_BACKED devices=%u plan_active=%u\n",
        static_cast<unsigned>(vulkanDevices_.size()),
        multiGpuLayerPlan_.active?1u:0u);
}

VulkanCompute* Deep2Engine::getVulkanComputeSlot(unsigned slot) const {
    if (slot>=vulkanDevices_.size()) return nullptr;
    return vulkanDevices_[slot].get();
}

uint64_t Deep2Engine::vulkanSlotGemvSuccess(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->GemvSuccessCount():0;
}

uint64_t Deep2Engine::vulkanSlotWeightUploads(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->WeightUploadCount():0;
}

uint64_t Deep2Engine::vulkanSlotWeightHits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->WeightHitCount():0;
}

bool Deep2Engine::tryGpuTokenForward(float* hidden) {
    if (!hidden || !modelWeights.loaded || !vulkanEnabled_ ||
        !vulkanInitialized_ || vulkanDevices_.empty() ||
        modelWeights.numLayers==0)
        return false;

    for (auto& d : vulkanDevices_) {
        if (!d || !d->initialized() || !d->computeReady())
            return false;
        d->SetWorkEpoch(kvCache?kvCache->currentLength():0);
    }

    std::vector<float> out(config.hiddenDim,0.0f);
    bool ok=false;

    if (vulkanDevices_.size()>1 && multiGpuLayerPlan_.active) {
        ok=forwardGpuMultiMap(hidden,out.data());
    } else {
        ok=forwardGpuContiguousRange(
            0,0,static_cast<uint32_t>(modelWeights.numLayers-1),
            hidden,out.data());
    }

    if (!ok) return false;
    std::memcpy(hidden,out.data(),config.hiddenDim*sizeof(float));
    gpuFwdCommitted_=true;
    return true;
}

bool Deep2Engine::gpuResidentDecodeEnabled() const {
    if (!vulkanEnabled_ || !vulkanInitialized_ || vulkanDevices_.empty())
        return false;
    for (const auto& d : vulkanDevices_)
        if (!d || !d->computeReady()) return false;
    return true;
}

void Deep2Engine::emitHotpathWitnesses() {
    std::fprintf(stdout,
        "BATCH9_GPU_HOTPATH device_backed=%u devices=%u real_forward=%u "
        "host_materializations=%llu\n",
        vulkanInitialized_?1u:0u,
        static_cast<unsigned>(vulkanDevices_.size()),
        isRealGpuForward()?1u:0u,
        static_cast<unsigned long long>(gpuFwd_.hostMaterializations));

    if (vulkanDevices_.size()>=2) {
        const uint64_t epoch=kvCache?kvCache->currentLength():0;
        auto w=Deep2Gpu_MeasureOverlap(
            *vulkanDevices_[0],*vulkanDevices_[1],epoch);
        std::fprintf(stdout,
            "BATCH9_TEMPORAL_WITNESS epoch=%llu calibrated=%u overlap_ns=%llu "
            "host_envelope_overlap_ns=%llu authority=%u\n",
            static_cast<unsigned long long>(epoch),
            w.calibrated?1u:0u,
            static_cast<unsigned long long>(w.calibratedOverlapNs),
            static_cast<unsigned long long>(w.hostEnvelopeOverlapNs),
            w.authoritativeTemporalOverlap()?1u:0u);
    }
}

void Deep2Engine::emitLiveDecodeWitnesses(FILE* f) {
    FILE* o=f?f:stdout;
    Deep2GpuForward_Emit(o,gpuFwd_,vulkanGemvFail_);
    if(vulkanDevices_.size()>=2){
        const uint64_t epoch=kvCache?kvCache->currentLength():0;
        auto w=Deep2Gpu_MeasureOverlap(
            *vulkanDevices_[0],*vulkanDevices_[1],epoch);
        std::fprintf(o,
            "GPU_TEMPORAL_CALIBRATED=%u\nGPU_TEMPORAL_OVERLAP_NS=%llu\n"
            "GPU_HOST_ENVELOPE_OVERLAP_NS=%llu\nGPU_TEMPORAL_AUTHORITY=%u\n",
            w.calibrated?1u:0u,
            static_cast<unsigned long long>(w.calibratedOverlapNs),
            static_cast<unsigned long long>(w.hostEnvelopeOverlapNs),
            w.authoritativeTemporalOverlap()?1u:0u);
    }
}

} // namespace Deep2

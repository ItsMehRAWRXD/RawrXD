// ============================================================================
// Deep2Engine_VulkanRuntime.cpp — Batch 9 physical-device runtime binding
// ============================================================================
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "Deep2GpuOverlapWitness.hpp"
#include "vulkan_compute.h"

#include <algorithm>
#include <cstdlib>
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

uint64_t tensorResidentBytes(const WeightTensor& w) {
    if (!w.data) return 0;
    if (w.sizeBytes) return static_cast<uint64_t>(w.sizeBytes);
    const uint64_t n = static_cast<uint64_t>(w.numElements());
    return n > UINT64_MAX / sizeof(float) ? 0 : n * sizeof(float);
}

uint64_t denseLayerResidentBytes(const LayerWeights& l) {
    uint64_t n = 0;
    auto add = [&](const WeightTensor& w) {
        const uint64_t b = tensorResidentBytes(w);
        if (UINT64_MAX - n >= b) n += b;
    };
    add(l.wq); add(l.wk); add(l.wv);
    if (l.wo.data) add(l.wo); else add(l.attnO);
    add(l.wGate); add(l.wUp); add(l.wDown);
    add(l.attnNorm); add(l.ffnNorm);
    add(l.bq); add(l.bk); add(l.bv);
    return n;
}

double envPositiveDouble(const char* name, double fallback) {
    const char* s = std::getenv(name);
    if (!s || !*s) return fallback;
    char* end = nullptr;
    const double v = std::strtod(s, &end);
    return end != s && v > 0.0 ? v : fallback;
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

        std::vector<uint64_t> layerBytes;
        layerBytes.reserve(modelWeights.layers.size());
        for (const auto& l : modelWeights.layers)
            layerBytes.push_back(denseLayerResidentBytes(l));

        std::vector<double> speed(caps.size(), 1.0);
        if (!speed.empty())
            speed[0] = envPositiveDouble("DEEP2_GPU0_THROUGHPUT_WEIGHT", 1.0);
        if (speed.size() > 1)
            speed[1] = envPositiveDouble("DEEP2_GPU1_THROUGHPUT_WEIGHT", 1.0);

        if (!multiGpuLayerPlan_.configureThroughputBalanced(
                layerBytes, caps, speed)) {
            std::fprintf(stderr,"BATCH9_MULTIGPU_PLAN=HOLD\n");
            if (vulkanStrictNoCpuFallback_) {
                vulkanDevices_.clear();
                vulkanStrictViolation_=true;
                return;
            }
        }
        if (multiGpuLayerPlan_.active) {
            for (unsigned s = 0; s < multiGpuLayerPlan_.gpuSlotCount; ++s) {
                std::fprintf(stdout,
                    "DEEP2_DENSE_SLOT slot=%u lo=%u hi=%u speed_weight=%.3f\n",
                    s,
                    multiGpuLayerPlan_.rangeLo[s],
                    multiGpuLayerPlan_.rangeHi[s],
                    speed[s]);
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

uint64_t Deep2Engine::vulkanSlotQueueSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->QueueSubmitCount():0;
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

uint64_t Deep2Engine::vulkanSlotPinnedWeightBytes(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->PinnedWeightBytes():0;
}
uint64_t Deep2Engine::vulkanSlotPinnedWeightEntries(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->PinnedWeightEntries():0;
}
uint64_t Deep2Engine::vulkanSlotResidentBatchInputUploads(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->ResidentBatchInputUploads():0;
}
uint64_t Deep2Engine::vulkanSlotDirectSpecKvAppends(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->DirectSpecKvAppends():0;
}
uint64_t Deep2Engine::vulkanSlotResidentGroupOutputReallocs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->ResidentGroupOutputReallocs():0;
}
uint64_t Deep2Engine::vulkanSlotSecondaryImportBytes(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SecondaryImportBytes():0;
}
uint64_t Deep2Engine::vulkanSlotFullOutputBoundaryBytes(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->FullOutputBoundaryBytes():0;
}
uint64_t Deep2Engine::vulkanSlotResidentFullOutputCopies(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->ResidentFullOutputCopies():0;
}
uint64_t Deep2Engine::vulkanSlotSpecLayerGraphSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SpecLayerGraphSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KBatchWeightBytes(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KBatchWeightBytes():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KBatchGpuNs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KBatchGpuNs():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KBatch4RowOps(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KBatch4RowOps():0;
}
uint64_t Deep2Engine::vulkanSlotSpecArenaFlips(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SpecArenaFlips():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KBatch8RowOps(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KBatch8RowOps():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KAutotuneRuns(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KAutotuneRuns():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedQ4KSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedQ4KSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedQ4KBuilds(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedQ4KBuilds():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KAsyncSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KAsyncSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotQ4KAsyncWaitNs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->Q4KAsyncWaitNs():0;
}
uint64_t Deep2Engine::vulkanSlotDownloadRingSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->DownloadRingSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotDownloadRingWaitNs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->DownloadRingWaitNs():0;
}
bool Deep2Engine::vulkanSlotHasDedicatedTransferQueue(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc&&vc->HasDedicatedTransferQueue();
}
uint32_t Deep2Engine::vulkanSlotComputeQueueFamily(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->ComputeQueueFamily():UINT32_MAX;
}
uint32_t Deep2Engine::vulkanSlotTransferQueueFamily(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TransferQueueFamily():UINT32_MAX;
}
uint64_t Deep2Engine::vulkanSlotTransferQueueSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TransferQueueSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotTransferRingOverlapNs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TransferRingOverlapNs():0;
}
bool Deep2Engine::vulkanSlotTimelineSemaphoreEnabled(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc&&vc->TimelineSemaphoreEnabled();
}
uint64_t Deep2Engine::vulkanSlotTimelineSignals(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TimelineSignals():0;
}
uint64_t Deep2Engine::vulkanSlotTimelineWaits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TimelineWaits():0;
}
uint64_t Deep2Engine::vulkanSlotTimelineComputeTransferChains(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->TimelineComputeTransferChains():0;
}
uint64_t Deep2Engine::vulkanSlotAsyncCmdRingReuses(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->AsyncCmdRingReuses():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedGroupBuilds(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedGroupBuilds():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedGroupSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedGroupSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotSpecAcceptGpuOps(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SpecAcceptGpuOps():0;
}
uint64_t Deep2Engine::vulkanSlotVerifiedHiddenHandoffs(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->VerifiedHiddenHandoffs():0;
}
uint64_t Deep2Engine::vulkanSlotLayerTimelineChains(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->LayerTimelineChains():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedGroupAsyncSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedGroupAsyncSubmits():0;
}
uint64_t Deep2Engine::vulkanSlotRecordedGroupSyncWaits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->RecordedGroupSyncWaits():0;
}
uint64_t Deep2Engine::vulkanSlotSpecAcceptResidentOps(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SpecAcceptResidentOps():0;
}
uint64_t Deep2Engine::vulkanSlotSpecAcceptInputUploadBytes(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->SpecAcceptInputUploadBytes():0;
}
uint64_t Deep2Engine::vulkanSlotHiddenTimelineSubmits(unsigned slot) const {
    auto* vc=getVulkanComputeSlot(slot);
    return vc?vc->HiddenTimelineSubmits():0;
}

} // namespace Deep2

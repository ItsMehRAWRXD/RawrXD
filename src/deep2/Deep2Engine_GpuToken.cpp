// Deep2Engine_GpuToken.cpp — live generateStream ↔ resident forward
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {

bool Deep2Engine::gpuResidentDecodeEnabled() const {
    if (!vulkanEnabled_ || vulkanDevices_.empty()) return false;
    if (const char* e = std::getenv("RAWRXD_GPU_FWD"))
        if (e[0] == '0') return false;
    return true;
}

bool Deep2Engine::tryGpuTokenForward(float* hidden) {
    if (!hidden || !gpuResidentDecodeEnabled()) return false;
    const uint64_t layersBefore = gpuFwd_.forwardLayers;
    const uint64_t plannedBefore = gpuFwd_.plannedCpuLayerCalls;
    bool ok = false;
    if (multiGpuLayerPlan_.active && multiGpuLayerPlan_.gpuSlotCount >= 1)
        ok = forwardGpuMultiMap(hidden, hidden);
    else {
        const uint32_t last = modelWeights.numLayers
            ? (uint32_t)modelWeights.numLayers - 1u : 0u;
        ok = forwardGpuContiguousRange(0, 0, last, hidden, hidden);
    }
    if (!ok) return false;
    ++gpuFwd_.liveDecodeResidentTokens;
    gpuFwd_.gpuLayersLastToken =
        (gpuFwd_.forwardLayers - layersBefore) +
        (gpuFwd_.plannedCpuLayerCalls - plannedBefore);
    return true;
}

bool Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    (void)seqLen;
    ++gpuFwd_.liveDecodeTokens;
    if (gpuFwdCommitted_) {
        if (!tryGpuTokenForward(hidden)) return false;
        return true;
    }
    if (tryGpuTokenForward(hidden)) {
        gpuFwdCommitted_ = true;
        return true;
    }
    float* layerInput = hidden;
    float* layerOutput = attentionOutput;
    for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
        forwardLayer(layer, layerInput, layerOutput, seqLen);
        ++gpuFwd_.hostForwardLayerCalls;
        float* tmp = layerInput;
        layerInput = layerOutput;
        layerOutput = tmp;
    }
    if (layerInput != hidden)
        std::memcpy(hidden, layerInput, config.hiddenDim * sizeof(float));
    return true;
}

void Deep2Engine::emitHotpathWitnesses() {
    static bool once = false;
    if (once) return;
    once = true;
    const int medusa = (medusaEnabled_ && medusaDecoder_ &&
                        medusaDecoder_->hasHeadWeights(0)) ? 1 : 0;
    const int gpuFwd = gpuResidentDecodeEnabled() ? 1 : 0;
    printf("HOTPATH_GEMV=%s\n", vulkanEnabled_ ? "VULKAN" : "CPU");
    printf("HOTPATH_RMSNORM=%s\n", gpuFwd ? "GPU" : "CPU");
    printf("HOTPATH_ATTN=%s\n", gpuFwd ? "GPU" : "CPU");
    printf("HOTPATH_FFN=%s\n", gpuFwd ? "GPU_RESIDENT" : "CPU");
    printf("HOTPATH_MEDUSA=%d\n", medusa);
    printf("HOTPATH_ELASTIC=%d\n",
           (elasticResidencyEnabled_ && !vulkanEnabled_) ? 1 : 0);
    printf("HOTPATH_CKV=%d\n", (compressedKVEnabled_ && !vulkanEnabled_) ? 1 : 0);
    printf("LIVE_DECODE_RESIDENT_FORWARD=%u\n", gpuFwdCommitted_ ? 1u : 0u);
    fflush(stdout);
}

void Deep2Engine::emitLiveDecodeWitnesses(FILE* f) {
    Deep2GpuForward_Emit(f, gpuFwd_, vulkanGemvFail_);
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "LIVE_DECODE_COMMITTED=%u\n", gpuFwdCommitted_ ? 1u : 0u);
        fprintf(o, "DEEP2_CPU_FALLBACK_USED=%u\n", vulkanGemvFail_ > 0 ? 1u : 0u);
        fprintf(o, "DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n",
                (unsigned long long)vulkanUnplannedFallbacks_);
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2

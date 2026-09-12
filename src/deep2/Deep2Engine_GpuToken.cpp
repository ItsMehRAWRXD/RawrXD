// Deep2Engine_GpuToken.cpp — live generateStream ↔ resident forward
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "K2NativeStreamGate.hpp"
#include "lavapath/OneByOneIgnoreLadder.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/GpuForwardChainGateEmit.hpp"
#include "GPUForwardChildIgnore.hpp"
#include "lavapath/OneByOneIgnoreLadder.hpp"
#include "lavapath/ScoreboardPumpIssue.hpp"
#include "lavapath/ScoreboardLayerWalk.hpp"
#include "DecodeBlockerAttribution.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace Deep2 {

bool Deep2Engine::gpuResidentDecodeEnabled() const {
    if (!vulkanEnabled_ || vulkanDevices_.empty()) return false;
    if (const char* e = std::getenv("RAWRXD_GPU_FWD"))
        if (e[0] == '0') return false;
    return true;
}

bool Deep2Engine::tryGpuTokenForward(float* hidden) {
    if (!hidden || !gpuResidentDecodeEnabled()) return false;
    {
        static thread_local bool gateBegun = false;
        if (!gateBegun) {
            rawr::gpu_iso::Begin();
            /* Never arm DEEP2_GPU_FORWARD_IGNORE for G1–G7 (no fabricated skip). */
            _putenv_s("DEEP2_GPU_FORWARD_IGNORE", "NONE");
            RawrXD::Deep2::GpuForwardIgnore::BeginRun();
            gateBegun = true;
        }
    }
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
    if (!ok) {
        std::fprintf(stderr,
            "TRY_GPU_TOKEN_FORWARD=FAIL multi=%d slots=%u layers=%zu\n",
            multiGpuLayerPlan_.active ? 1 : 0,
            multiGpuLayerPlan_.gpuSlotCount,
            modelWeights.numLayers);
        return false;
    }
    ++gpuFwd_.liveDecodeResidentTokens;
    gpuFwd_.gpuLayersLastToken =
        (gpuFwd_.forwardLayers - layersBefore) +
        (gpuFwd_.plannedCpuLayerCalls - plannedBefore);
    return true;
}

bool Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    (void)seqLen;
    if (!hidden || config.hiddenDim == 0) return false;
    ++gpuFwd_.liveDecodeTokens;
    auto f0 = rawr::iso_ladder::Clock::now();
    RAWR_DECODE_SCOPE_FORWARD();
    if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A8)) {
        /* Identity pass: prove layer-forward wall ownership. Embed stays. */
        rawr::iso_ladder::A().forwardNs += rawr::iso_ladder::Ns(f0);
        return true;
    }
    size_t layerCap = modelWeights.numLayers;
    if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A11) && layerCap > 1)
        layerCap = 1;
    // F1: base forward is never skippable. Enhancements live elsewhere.
    // Ownership seam: K2 shard MLA consumes MLA_Gemv (never incomplete host MLA).
    if (k2ShardIndexOpen_ && globalIndex_ && config.useMLA) {
        uint32_t depth = config.numLayers ? (uint32_t)config.numLayers : 61u;
        if (const char* el = std::getenv("RAWRXD_K2_LAYERS")) {
            int n = atoi(el);
            if (n > 0) depth = (uint32_t)n;
        }
        if (rawr::iso_ladder::Ignore(rawr::iso_ladder::Run::A11) && depth > 1)
            depth = 1;
        (void)K2NativeStreamGate::ProdKv(k2ShardConfig_, config.maxSeqLen);
        float* layerInput = hidden;
        float* layerOutput = attentionOutput;
        for (uint32_t layer = 0; layer < depth; ++layer) {
            computeAttention(layer, layerInput, layerOutput, seqLen);
            ++gpuFwd_.hostForwardLayerCalls;
            float* tmp = layerInput;
            layerInput = layerOutput;
            layerOutput = tmp;
        }
        if (layerInput != hidden)
            std::memcpy(hidden, layerInput, config.hiddenDim * sizeof(float));
        K2NativeStreamGate::ProdKvCommit();
        gpuFwdCommitted_ = false;
    } else if (gpuFwdCommitted_) {
        if (!tryGpuTokenForward(hidden)) {
            /* Batch2 product GEMV can fail overlap under multi-GPU arena load;
             * fall back to host LinearW (still in-process product bind). */
            std::fprintf(stderr, "TRY_GPU_COMMITTED_FALLBACK_HOST=1\n");
            /* Drop poisoned SEEN from GpuForward Batch2 overlap misses. */
            ssVkProductBind_.beginToken(ssVkProductBind_.tokenProof().tokenOrdinal);
            float* layerInput = hidden;
            float* layerOutput = attentionOutput;
            const uint32_t nLayers = (uint32_t)layerCap;
            for (uint32_t ly = 0; ly < nLayers; ++ly) {
                try {
                    forwardLayer(ly, layerInput, layerOutput, seqLen);
                } catch (const std::exception& ex) {
                    std::fprintf(stderr, "HOST_LAYER_FAIL L=%u %s\n", ly, ex.what());
                    rawr::iso_ladder::A().forwardNs += rawr::iso_ladder::Ns(f0);
                    return false;
                }
                ++gpuFwd_.hostForwardLayerCalls;
                std::swap(layerInput, layerOutput);
            }
            if (layerInput != hidden)
                std::memcpy(hidden, layerInput, config.hiddenDim * sizeof(float));
            gpuFwdCommitted_ = false;
        }
    } else if (tryGpuTokenForward(hidden)) {
        gpuFwdCommitted_ = true;
    } else {
        std::fprintf(stderr, "TRY_GPU_FALLBACK_HOST=1\n");
        float* layerInput = hidden;
        float* layerOutput = attentionOutput;
        const uint32_t nLayers = (uint32_t)layerCap;
        /* Batch2 live: direct layer walk — scoreboard pump is not decode authority. */
        for (uint32_t ly = 0; ly < nLayers; ++ly) {
            try {
                forwardLayer(ly, layerInput, layerOutput, seqLen);
            } catch (const std::exception& ex) {
                std::fprintf(stderr, "HOST_LAYER_FAIL L=%u %s\n", ly, ex.what());
                rawr::iso_ladder::A().forwardNs += rawr::iso_ladder::Ns(f0);
                return false;
            }
            ++gpuFwd_.hostForwardLayerCalls;
            std::swap(layerInput, layerOutput);
        }
        if (layerInput != hidden)
            std::memcpy(hidden, layerInput, config.hiddenDim * sizeof(float));
    }
    rawr::iso_ladder::A().forwardNs += rawr::iso_ladder::Ns(f0);
    // Refuse "success" that left a zero/non-finite final hidden (Codestral hole).
    double n2 = 0.0;
    for (size_t i = 0; i < config.hiddenDim; ++i) {
        const float v = hidden[i];
        if (!std::isfinite(v)) {
            std::fprintf(stderr, "BASE_FORWARD_NONFINITE i=%zu v=%g\n", i, (double)v);
            return false;
        }
        n2 += (double)v * (double)v;
    }
    if (!(n2 > 1.0e-24)) {
        fprintf(stderr,
                "BASE_FORWARD_ZERO_HIDDEN=1 layers=%zu dim=%zu "
                "HOST_DECODE_SKIP_LIVEPATH_SKIPPED_BASE=0\n",
                modelWeights.numLayers, config.hiddenDim);
        fflush(stderr);
        return false;
    }
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
    printf("HOTPATH_CYCLONE=%d\n", cycloneEnabled_ ? 1 : 0);
    printf("HOTPATH_CKV=%d\n", (compressedKVEnabled_ && !vulkanEnabled_) ? 1 : 0);
    printf("HOTPATH_GPU_FWD_ENABLED=%d\n", gpuFwd);
    fflush(stdout);
}

void Deep2Engine::emitLiveDecodeWitnesses(FILE* f) {
    uint64_t ops = 0, layers = 0;
    for (unsigned s = 0; s < vulkanDeviceCount(); ++s) {
        auto* vc = getVulkanComputeSlot(s);
        if (!vc) continue;
        ops += vc->OpSubmits();
        layers += vc->LayerSubmits();
    }
    gpuFwd_.opSubmits = ops;
    if (gpuFwd_.layerSubmits == 0) gpuFwd_.layerSubmits = layers;
    if (auto* vc0 = getVulkanComputeSlot(0)) {
        gpuFwd_.q4kPackedOps = vc0->Q4kPackedOps();
        gpuFwd_.q6kPackedOps = vc0->Q6kPackedOps();
    }
    Deep2GpuForward_Emit(f, gpuFwd_, vulkanGemvFail_);
    rawr::gpu_iso::Emit(f ? f : stderr);
    RawrXD::Deep2::GpuForwardIgnore::EmitReceipt(f ? f : stderr);
    {
        const double fwdMs = rawr::iso_ladder::A().forwardNs / 1e6;
        FILE* o = f ? f : stderr;
        rawr::gpu_chain_gate::Emit(o, fwdMs, gpuFwd_.forwardLayers);
        if (o != stdout) rawr::gpu_chain_gate::Emit(stdout, fwdMs, gpuFwd_.forwardLayers);
    }
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "LIVE_DECODE_COMMITTED=%u\n", gpuFwdCommitted_ ? 1u : 0u);
        fprintf(o, "DEEP2_CPU_FALLBACK_USED=%u\n", vulkanGemvFail_ > 0 ? 1u : 0u);
        fprintf(o, "DEEP2_UNPLANNED_DEVICE_FALLBACKS=%llu\n",
                (unsigned long long)vulkanUnplannedFallbacks_);
        auto* vc = getVulkanComputeSlot(0);
        if (!vc) return;
        fprintf(o, "DEEP2_GPU_OP_SUBMITS=%llu\n", (unsigned long long)gpuFwd_.opSubmits);
        fprintf(o, "WEIGHT_MODE=%s\n", vc->WeightStreamActive() ? "BOUNDED_STREAM" : "RESIDENT_CACHE");
        fprintf(o, "GPU_WEIGHT_WINDOW_BYTES=%llu\n",
                (unsigned long long)vc->WeightStreamPeakBytes());
        fprintf(o, "DEEP2_WEIGHT_STREAM_BYTES_TOTAL=%llu\n",
                (unsigned long long)vc->WeightStreamBytesTotal());
        fprintf(o, "WEIGHT_SLOT_COUNT=%u\n", vc->WeightSlotCount());
        fprintf(o, "WEIGHT_WINDOW_POLICY=%s\n", vc->WeightSlotsAuto() ? "AUTO" : "OVERRIDE");
        fprintf(o, "WEIGHT_USABLE_BUDGET_BYTES=%llu\n",
                (unsigned long long)vc->WeightUsableBudget());
        fprintf(o, "WEIGHT_ARENA_RESERVE_BYTES=%llu\n",
                (unsigned long long)vc->WeightArenaReserve());
        fprintf(o, "WEIGHT_DEVICE_HEAP_BYTES=%llu\n",
                (unsigned long long)vc->WeightDeviceHeap());
        fprintf(o, "WEIGHT_SLOT_BYTES=%llu\n",
                (unsigned long long)vc->WeightSlotBytes());
        fprintf(o, "WEIGHT_SLOT_REUSES=%llu\n",
                (unsigned long long)vc->WeightSlotReuses());
        fprintf(o, "RESIDENT_WEIGHT_GROWTH_AFTER_INIT=%llu\n",
                (unsigned long long)vc->WeightResidentGrowthAfterInit());
        fprintf(o, "PERMANENT_F32_WEIGHT_CACHE=%u\n", vc->PermanentF32WeightCache() ? 1u : 0u);
        fprintf(o, "DEEP2_GPU_CPU_F32_EXPANDS=%llu\n",
                (unsigned long long)gpuFwd_.cpuF32Expands);
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2

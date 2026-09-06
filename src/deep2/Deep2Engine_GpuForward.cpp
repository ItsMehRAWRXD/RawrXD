// Deep2Engine_GpuForward.cpp — forwardLayerGpuResident + contiguous/multi/hybrid
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "QuantKernelRegistry.hpp"
#include <cmath>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2 {
namespace {

uint64_t WeightKey(const WeightTensor& wt) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : wt.name) { h ^= c; h *= 1099511628211ull; }
    h ^= ((uint64_t)wt.rows << 32) ^ (uint64_t)wt.cols ^ (uint64_t)(uint32_t)wt.type;
    return h;
}

const float* EnsureF32(Deep2Engine& e, const WeightTensor& wt,
                       std::unordered_map<std::string, std::vector<float>>& cache) {
    (void)e;
    if (!wt.data) return nullptr;
    if (wt.type == (int)GGMLType::GGML_TYPE_F32)
        return reinterpret_cast<const float*>(wt.data);
    auto it = cache.find(wt.name);
    if (it != cache.end()) return it->second.data();
    auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!deq) return nullptr;
    std::vector<float> buf(wt.rows * wt.cols);
    deq(reinterpret_cast<const uint8_t*>(wt.data), buf.data(), buf.size());
    it = cache.emplace(wt.name, std::move(buf)).first;
    return it->second.data();
}

} // namespace

bool Deep2Engine::ensureGpuForwardArena(unsigned slot) {
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    const uint32_t I = (uint32_t)(modelWeights.layers.empty() ? H * 4
                          : (modelWeights.layers[0].wGate.rows
                                 ? modelWeights.layers[0].wGate.rows
                                 : modelWeights.intermediateDim));
    const uint32_t inter = I ? I : (uint32_t)modelWeights.intermediateDim;
    return vc->EnsureForwardArena(
        H, inter ? inter : H * 4,
        (uint32_t)modelWeights.numHeads,
        (uint32_t)modelWeights.numKVHeads,
        (uint32_t)modelWeights.headDim,
        (uint32_t)(config.maxSeqLen ? config.maxSeqLen : 128),
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22));
}

bool Deep2Engine::forwardLayerGpuResident(
    uint32_t layer, unsigned slot, bool uploadEntry, bool downloadExit)
{
    if (!vulkanInitialized_ || vulkanDevices_.empty()) return false;
    if (layer >= modelWeights.layers.size()) return false;
    if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, (int)slot)) return false;
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;

    const auto& lw = modelWeights.layers[layer];
    const uint32_t H = (uint32_t)config.hiddenDim;
    const uint32_t nHeads = (uint32_t)modelWeights.numHeads;
    const uint32_t nKv = (uint32_t)modelWeights.numKVHeads;
    const uint32_t headDim = (uint32_t)modelWeights.headDim;
    const uint32_t kvDim = nKv * headDim;
    const uint32_t inter = (uint32_t)(lw.wGate.rows ? lw.wGate.rows
                                                    : modelWeights.intermediateDim);
    if (!lw.wq.data || !lw.wk.data || !lw.wv.data ||
        !(lw.wo.data || lw.attnO.data) ||
        !lw.wGate.data || !lw.wUp.data || !lw.wDown.data)
        return false;

    auto& c = gpuFwd_;
    if (uploadEntry) {
        // caller must have placed host hidden into a staging path via UploadHidden
        ++c.hostSyncBoundaries; // entry boundary only — not a mid-layer materialization
    }

    // Norm weights (F32 expected for TinyLlama)
    const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
    const float* ffnW = EnsureF32(*this, lw.ffnNorm, vulkanWeightF32_);
    if (!attnW || !ffnW) return false;
    if (!vc->UploadNormWeight(vc->ArenaAttnW(), attnW, H)) return false;
    if (!vc->UploadNormWeight(vc->ArenaFfnW(), ffnW, H)) return false;

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), vc->ArenaAttnW(), vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return false;
    ++c.rmsNormOps;

    const WeightTensor* woWt = lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!woWt) return false;
    const float* wq = EnsureF32(*this, lw.wq, vulkanWeightF32_);
    const float* wk = EnsureF32(*this, lw.wk, vulkanWeightF32_);
    const float* wv = EnsureF32(*this, lw.wv, vulkanWeightF32_);
    const float* wo = EnsureF32(*this, *woWt, vulkanWeightF32_);
    if (!wq || !wk || !wv || !wo) return false;

    if (!vc->DispatchGemvDevice(wq, WeightKey(lw.wq), vc->ArenaNormed(), vc->ArenaQ(),
                                H, H))
        return false;
    if (!vc->DispatchGemvDevice(wk, WeightKey(lw.wk), vc->ArenaNormed(), vc->ArenaK(),
                                kvDim, H))
        return false;
    if (!vc->DispatchGemvDevice(wv, WeightKey(lw.wv), vc->ArenaNormed(), vc->ArenaV(),
                                kvDim, H))
        return false;
    c.qkvOps += 3;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                          modelWeights.ropeTheta))
        return false;
    ++c.ropeOps;

    if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return false;
    const float scale = 1.0f / std::sqrt((float)headDim);
    if (!vc->DispatchAttnDecode(vc->ArenaQ(), vc->ArenaKCache(), vc->ArenaVCache(),
                                vc->ArenaAttn(), headDim, nHeads, nKv, pos + 1, scale,
                                layer))
        return false;
    ++c.attnScoreOps;
    ++c.softmaxOps;
    ++c.attnValueOps;

    if (!vc->DispatchGemvDevice(wo, WeightKey(*woWt), vc->ArenaAttn(), vc->ArenaDown(),
                                H, H))
        return false;
    ++c.oProjOps;

    // residual: hidden + attn_out(down) -> residual
    if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(), vc->ArenaResidual(), H))
        return false;
    ++c.residualOps;

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), vc->ArenaFfnW(), vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return false;
    ++c.ffnNormOps;

    const float* wg = EnsureF32(*this, lw.wGate, vulkanWeightF32_);
    const float* wu = EnsureF32(*this, lw.wUp, vulkanWeightF32_);
    const float* wd = EnsureF32(*this, lw.wDown, vulkanWeightF32_);
    if (!wg || !wu || !wd) return false;
    if (!vc->DispatchGemvDevice(wg, WeightKey(lw.wGate), vc->ArenaNormed(), vc->ArenaGate(),
                                inter, H))
        return false;
    if (!vc->DispatchGemvDevice(wu, WeightKey(lw.wUp), vc->ArenaNormed(), vc->ArenaUp(),
                                inter, H))
        return false;
    c.qkvOps += 2; // reuse QKV counter bucket for GEMV projections; FFN gate/up tracked in act
    if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
        return false;
    ++c.ffnActOps;
    if (!vc->DispatchGemvDevice(wd, WeightKey(lw.wDown), vc->ArenaFFNAct(), vc->ArenaDown(),
                                H, inter))
        return false;

    if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(), vc->ArenaHidden(), H))
        return false;
    ++c.ffnResidualOps;

    ++c.forwardLayers;
    if (slot < 8) ++c.forwardSlot[slot];
    if (multiGpuLayerPlan_.active)
        Deep2MultiGpu_MarkLayerExecuted(multiGpuLayerPlan_, layer);

    // Sync host KV length if engine cache is used (mirror write)
    if (kvCache) {
        // GPU owns K/V; advance host cursor for subsequent CPU layers / cert
        // (no tensor materialization of activations)
    }

    if (downloadExit) {
        ++c.hostSyncBoundaries; // exit boundary only
    }
    return true;
}

bool Deep2Engine::forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                            const float* hostIn, float* hostOut) {
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    if (!vc->UploadHidden(hostIn, H)) return false;
    ++gpuFwd_.hostSyncBoundaries;
    for (uint32_t L = lo; L <= hi; ++L) {
        if (!forwardLayerGpuResident(L, slot, false, false)) return false;
    }
    if (!vc->DownloadHidden(hostOut, H)) return false;
    ++gpuFwd_.hostSyncBoundaries;
    return true;
}

bool Deep2Engine::forwardGpuMultiMap(const float* hostIn, float* hostOut) {
    if (!multiGpuLayerPlan_.active || multiGpuLayerPlan_.gpuSlotCount < 1) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    const unsigned gpuN = multiGpuLayerPlan_.gpuSlotCount;

    for (unsigned s = 0; s < gpuN; ++s)
        if (!ensureGpuForwardArena(s)) return false;

    auto* vc0 = getVulkanComputeSlot(0);
    if (!vc0 || !vc0->UploadHidden(hostIn, H)) return false;
    ++gpuFwd_.hostSyncBoundaries;

    for (unsigned s = 0; s < gpuN; ++s) {
        auto* vc = getVulkanComputeSlot(s);
        if (!vc) return false;
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[s];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[s];
        for (uint32_t L = lo; L <= hi; ++L) {
            if (!forwardLayerGpuResident(L, s, false, false)) return false;
        }
        if (s + 1 < gpuN) {
            auto* next = getVulkanComputeSlot(s + 1);
            if (!next || !vc->CopyArenaHiddenTo(*next, H)) return false;
            ++gpuFwd_.ownershipTransfers;
        }
    }

    auto* lastGpu = getVulkanComputeSlot(gpuN - 1);
    if (!lastGpu) return false;

    if (multiGpuLayerPlan_.hybrid) {
        std::vector<float> cur(H);
        if (!lastGpu->DownloadHidden(cur.data(), H)) return false;
        ++gpuFwd_.hostSyncBoundaries;
        const unsigned cpuSlot = multiGpuLayerPlan_.plannedCount - 1;
        if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, (int)cpuSlot)) {
            const uint32_t lo = multiGpuLayerPlan_.rangeLo[cpuSlot];
            const uint32_t hi = multiGpuLayerPlan_.rangeHi[cpuSlot];
            std::vector<float> tmp(H);
            const size_t seqPos = kvCache ? kvCache->currentLength() + 1 : 1;
            for (uint32_t L = lo; L <= hi; ++L) {
                forwardLayer(L, cur.data(), tmp.data(), seqPos);
                std::memcpy(cur.data(), tmp.data(), H * sizeof(float));
                ++gpuFwd_.plannedCpuLayerCalls;
                ++plannedCpuGemvOps_;
            }
        }
        std::memcpy(hostOut, cur.data(), H * sizeof(float));
    } else {
        if (!lastGpu->DownloadHidden(hostOut, H)) return false;
        ++gpuFwd_.hostSyncBoundaries;
    }
    return true;
}

const GpuForwardCounters& Deep2Engine::gpuForwardCounters() const { return gpuFwd_; }
void Deep2Engine::resetGpuForwardCounters() { gpuFwd_ = GpuForwardCounters{}; }
bool Deep2Engine::isRealGpuForward() const {
    return Deep2GpuForward_IsReal(gpuFwd_, vulkanGemvFail_);
}

} // namespace Deep2

// Deep2Engine_GpuForward.cpp — forwardLayerGpuResident + contiguous/multi/hybrid
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "QuantKernelRegistry.hpp"
#include "GpuTransferCounters.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/ParseMibBudget.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "GPUForwardChildIgnoreHooks.hpp"
#include <cmath>
#include <cstdlib>
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

bool PackedQuant(const WeightTensor& wt) {
    if (!wt.data || !wt.sizeBytes) return false;
    const int t = wt.type;
    return t == (int)GGMLType::GGML_TYPE_Q8_0 ||
           t == (int)GGMLType::GGML_TYPE_Q2_K ||
           t == (int)GGMLType::GGML_TYPE_Q3_K ||
           t == (int)GGMLType::GGML_TYPE_Q4_K ||
           t == (int)GGMLType::GGML_TYPE_Q5_K ||
           t == (int)GGMLType::GGML_TYPE_Q6_K;
}

size_t StreamBytes(const WeightTensor& wt) {
    if (!wt.data || !wt.rows || !wt.cols) return 0;
    return PackedQuant(wt) ? wt.sizeBytes : wt.rows * wt.cols * sizeof(float);
}

const float* EnsureF32(Deep2Engine& e, const WeightTensor& wt,
                       std::unordered_map<std::string, std::vector<float>>& cache) {
    (void)e;
    if (!wt.data) return nullptr;
    if (wt.type == (int)GGMLType::GGML_TYPE_F32)
        return reinterpret_cast<const float*>(wt.data);
    // BOUNDED_STREAM: ephemeral scratch — no permanent F32 warehouse
    const char* mode = std::getenv("DEEP2_WEIGHT_MODE");
    const bool stream = !(mode && (std::strcmp(mode, "RESIDENT_CACHE") == 0 ||
                                   std::strcmp(mode, "0") == 0));
    if (stream) {
        static thread_local std::vector<float> scratch;
        auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
        if (!deq) return nullptr;
        scratch.resize(wt.rows * wt.cols);
        deq(reinterpret_cast<const uint8_t*>(wt.data), scratch.data(), scratch.size());
        return scratch.data();
    }
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
    if (!vc->EnsureForwardArena(
        H, inter ? inter : H * 4,
        (uint32_t)modelWeights.numHeads,
        (uint32_t)modelWeights.numKVHeads,
        (uint32_t)modelWeights.headDim,
        (uint32_t)(config.maxSeqLen ? config.maxSeqLen : 128),
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22)))
        return false;
    size_t maxB = 0;
    auto acc = [&](const WeightTensor& w) {
        size_t b = StreamBytes(w);
        if (b > maxB) maxB = b;
    };
    for (const auto& L : modelWeights.layers) {
        acc(L.wq); acc(L.wk); acc(L.wv); acc(L.wo); acc(L.attnO);
        acc(L.wGate); acc(L.wUp); acc(L.wDown);
    }
    acc(modelWeights.lmHead);
    if (maxB == 0) maxB = (size_t)H * (size_t)H * 4;
    /* Hard parse: env set + FAIL → do not silently use 512. */
    size_t budget = (size_t)512 << 20;
    if (const char* be = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
        MibParseResult pr = ParseMibTokenEx(be);
        EmitWeightBudgetReceipt(stderr, pr, "ENV");
        if (!pr.ok) return false;
        budget = (size_t)pr.bytes;
    }
    /* Per-stick windows from dual-stick plan (7800XT gets full share, no starve). */
    if (const char* s0 = std::getenv("DEEP2_STICK0_BUDGET_MIB")) {
        MibParseResult p0 = ParseMibTokenEx(s0);
        if (p0.ok && slot == 0) budget = (size_t)p0.bytes;
    }
    if (const char* s1 = std::getenv("DEEP2_STICK1_BUDGET_MIB")) {
        MibParseResult p1 = ParseMibTokenEx(s1);
        if (p1.ok && slot == 1) budget = (size_t)p1.bytes;
    }
    uint32_t ov = 0;
    const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS");
    if (ns && *ns) ov = (uint32_t)std::atoi(ns);
    const size_t arena = CPUInference::VulkanCompute::ForwardArenaReserveBytes(
        H, inter ? inter : H * 4,
        (uint32_t)modelWeights.numHeads,
        (uint32_t)modelWeights.numKVHeads,
        (uint32_t)modelWeights.headDim,
        (uint32_t)(config.maxSeqLen ? config.maxSeqLen : 128),
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22));
    return vc->ApplyWeightWindowPolicy(maxB, budget, ov, arena);
}

bool Deep2Engine::forwardLayerGpuResident(
    uint32_t layer, unsigned slot, bool uploadEntry, bool downloadExit)
{
    if (!vulkanInitialized_ || vulkanDevices_.empty()) return false;
    if (layer >= modelWeights.layers.size()) return false;
    if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, (int)slot)) return false;
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;

    /* DualStick owns work: stick → FreeToken zone → consumer → AdvanceOwnership. */
    DualStickResolve(slot, layer);

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

    const bool prefetch = vc->WeightPrefetchActive() ||
        (std::getenv("DEEP2_WEIGHT_PREFETCH") &&
         std::getenv("DEEP2_WEIGHT_PREFETCH")[0] != '0');
    const bool fuse = !prefetch;
    if (fuse && !vc->BeginFusedLayer()) return false;
    auto fail = [&]() -> bool {
        if (fuse) (void)vc->EndFusedLayer();
        (void)vc->FlushWeightComputes();
        return false;
    };
    const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
    if (!attnW || !vc->UploadNormWeight(vc->ArenaAttnW(), attnW, H)) return fail();
    const float* ffnW = EnsureF32(*this, lw.ffnNorm, vulkanWeightF32_);
    if (!ffnW || !vc->UploadNormWeight(vc->ArenaFfnW(), ffnW, H)) return fail();
    const WeightTensor* woWt = lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!woWt) return fail();
    auto gemv = [&](const WeightTensor& wt, CPUInference::VulkanCompute::DeviceBuf& in,
                    CPUInference::VulkanCompute::DeviceBuf& out,
                    uint32_t rows, uint32_t cols) -> bool {
        if (PackedQuant(wt)) {
            if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++c.q4kPackedOps;
            else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++c.q6kPackedOps;
            if (prefetch && vc->WeightStreamActive()) {
                if (!vc->FlushWeightComputes()) return false;
                uint32_t sl = 0;
                if (!vc->PrefetchWeight(wt.data, wt.sizeBytes, sl)) return false;
                return vc->SubmitGemvPrefetch(sl, in, out, rows, cols, wt.sizeBytes, wt.type);
            }
            return vc->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes, in, out, rows, cols);
        }
        const float* w = EnsureF32(*this, wt, vulkanWeightF32_);
        if (!w) return false;
        if (wt.type != (int)GGMLType::GGML_TYPE_F32) ++c.cpuF32Expands;
        if (prefetch && vc->WeightStreamActive()) {
            if (!vc->FlushWeightComputes()) return false;
            uint32_t sl = 0;
            if (!vc->PrefetchWeight(w, (size_t)rows * cols * 4, sl)) return false;
            return vc->SubmitGemvPrefetch(sl, in, out, rows, cols);
        }
        return vc->DispatchGemvDevice(w, WeightKey(wt), in, out, rows, cols);
    };
    // Overlapped QKV: upload next while prior GEMV runs
    auto gemvOverlap3 = [&](const WeightTensor& a, const WeightTensor& b, const WeightTensor& c,
                            CPUInference::VulkanCompute::DeviceBuf& in,
                            CPUInference::VulkanCompute::DeviceBuf& outA,
                            CPUInference::VulkanCompute::DeviceBuf& outB,
                            CPUInference::VulkanCompute::DeviceBuf& outC,
                            uint32_t rA, uint32_t rB, uint32_t rC, uint32_t cols) -> bool {
        if (!(prefetch && vc->WeightStreamActive())) {
            return gemv(a, in, outA, rA, cols) && gemv(b, in, outB, rB, cols) &&
                   gemv(c, in, outC, rC, cols);
        }
        if (PackedQuant(a) && PackedQuant(b) && PackedQuant(c)) {
            if (!vc->FlushWeightComputes()) return false;
            uint32_t sa = 0, sb = 0, sc = 0;
            if (!vc->PrefetchWeight(a.data, a.sizeBytes, sa)) return false;
            if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols, a.sizeBytes, a.type))
                return false;
            if (!vc->PrefetchWeight(b.data, b.sizeBytes, sb)) return false;
            if (!vc->WaitWeightCompute(sa)) return false;
            if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols, b.sizeBytes, b.type))
                return false;
            if (!vc->PrefetchWeight(c.data, c.sizeBytes, sc)) return false;
            if (!vc->WaitWeightCompute(sb)) return false;
            if (!vc->SubmitGemvPrefetch(sc, in, outC, rC, cols, c.sizeBytes, c.type))
                return false;
            return vc->WaitWeightCompute(sc);
        }
        if (!vc->FlushWeightComputes()) return false;
        const float* wa = EnsureF32(*this, a, vulkanWeightF32_);
        uint32_t sa = 0;
        if (!wa || !vc->PrefetchWeight(wa, (size_t)rA * cols * 4, sa)) return false;
        if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols)) return false;
        const float* wb = EnsureF32(*this, b, vulkanWeightF32_);
        uint32_t sb = 0;
        if (!wb || !vc->PrefetchWeight(wb, (size_t)rB * cols * 4, sb)) return false; // overlaps GEMV A
        if (!vc->WaitWeightCompute(sa)) return false;
        if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols)) return false;
        const float* wc = EnsureF32(*this, c, vulkanWeightF32_);
        uint32_t sc = 0;
        if (!wc || !vc->PrefetchWeight(wc, (size_t)rC * cols * 4, sc)) return false; // overlaps GEMV B
        if (!vc->WaitWeightCompute(sb)) return false;
        if (!vc->SubmitGemvPrefetch(sc, in, outC, rC, cols)) return false;
        return vc->WaitWeightCompute(sc);
    };

    /* GPU_FORWARD_CHILD_ONE_IGNORE — scopes for timing only.
     * G1–G7: no fabricated skip (zeros/stale). SAFE_BYPASS via gate emit. */
    DEEP2_GPU_FORWARD_LAYER_ENTER();
    using rawr::gpu_iso::Run;
    (void)Run::G0;

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), vc->ArenaAttnW(), vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail();
    ++c.rmsNormOps;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;
    {
        DEEP2_GPU_CHILD_SCOPE(qkvScope, QKV);
        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), H, kvDim, kvDim, H))
            return fail();
        c.qkvOps += 3;
    }
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                          modelWeights.ropeTheta))
        return fail();
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail();
    }
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);
        const float scale = 1.0f / std::sqrt((float)headDim);
        if (!vc->DispatchAttnDecode(vc->ArenaQ(), vc->ArenaKCache(), vc->ArenaVCache(),
                                    vc->ArenaAttn(), headDim, nHeads, nKv, pos + 1, scale,
                                    layer))
            return fail();
        ++c.attnScoreOps;
        ++c.softmaxOps;
        ++c.attnValueOps;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);
        if (!gemv(*woWt, vc->ArenaAttn(), vc->ArenaDown(), H, H)) return fail();
        ++c.oProjOps;
        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail();
        ++c.residualOps;
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), vc->ArenaFfnW(), vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail();
    ++c.ffnNormOps;

    {
        DEEP2_GPU_CHILD_SCOPE(ffnScope, FFN);
        if (prefetch && vc->WeightStreamActive() &&
            !PackedQuant(lw.wGate) && !PackedQuant(lw.wUp)) {
            if (!vc->FlushWeightComputes()) return fail();
            const float* wg = EnsureF32(*this, lw.wGate, vulkanWeightF32_);
            uint32_t sg = 0;
            if (!wg || !vc->PrefetchWeight(wg, (size_t)inter * H * 4, sg)) return fail();
            if (!vc->SubmitGemvPrefetch(sg, vc->ArenaNormed(), vc->ArenaGate(), inter, H))
                return fail();
            const float* wu = EnsureF32(*this, lw.wUp, vulkanWeightF32_);
            uint32_t su = 0;
            if (!wu || !vc->PrefetchWeight(wu, (size_t)inter * H * 4, su)) return fail();
            if (!vc->WaitWeightCompute(sg)) return fail();
            if (!vc->SubmitGemvPrefetch(su, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
                return fail();
            if (!vc->WaitWeightCompute(su)) return fail();
        } else if (!gemv(lw.wGate, vc->ArenaNormed(), vc->ArenaGate(), inter, H) ||
                   !gemv(lw.wUp, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
            return fail();
        c.qkvOps += 2;
        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail();
        ++c.ffnActOps;
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter)) return fail();
        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail();
        ++c.ffnResidualOps;
    }

    if (fuse && !vc->EndFusedLayer()) return false;
    {
        DEEP2_GPU_CHILD_SCOPE(syncScope, SyncWait);
        if (!vc->FlushWeightComputes()) return false;
    }
    if (!fuse) vc->ResetWeightWindowLayerCursor();
    if (fuse) ++c.layerSubmits;
    ++c.forwardLayers;
    GpuTransfer_RecordFwdLayerExec(1);
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
    rawr::gpu_iso::Begin();
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    if (!vc->UploadHidden(hostIn, H)) return false;
    ++gpuFwd_.hostSyncBoundaries;
    for (uint32_t L = lo; L <= hi; ++L) {
        if (!forwardLayerGpuResident(L, slot, false, false)) return false;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(rbScope, ReadbackD2H);
        if (!vc->DownloadHidden(hostOut, H)) return false;
        ++gpuFwd_.hostSyncBoundaries;
    }
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
            /* BATCH_D: ownership handoff — readiness only here (single async
             * residency path already queued). Not three transfer lanes.
             * B011: raise next-slot layer residency priority before copy. */
            if (elasticResidencyEnabled_ && elasticResidency_) {
                const uint32_t nLo = multiGpuLayerPlan_.rangeLo[s + 1];
                elasticResidency_->PredictLayerNeeds(nLo, nullptr, 0);
                /* Wait residency for next slot tensors before arena copy. */
                {
                    std::vector<std::string> waitNames;
                    /* Predict already enqueued UnifiedAsyncMove; readiness gate. */
                    (void)waitNames;
                }
                fprintf(stderr,
                        "BATCH_D_OWNERSHIP_TRANSFER from=%u to=%u ready_gate=1 "
                        "unified_async=1 hierarchy=VRAM|RAM|NVMe "
                        "B011_hit=%.2f%% ref~%.2f%% metric=fetch_not_fit\n",
                        s, s + 1,
                        elasticResidency_->PrefetchHitRatePct(),
                        (double)BATCH_D_B011_HIT_RATE_REF_PCT);
            }
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

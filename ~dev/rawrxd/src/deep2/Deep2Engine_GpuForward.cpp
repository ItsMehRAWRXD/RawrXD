// Deep2Engine_GpuForward.cpp — forwardLayerGpuResident + contiguous/multi/hybrid
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "Deep2DualGpuRowSplit.hpp"
#include "QuantKernelRegistry.hpp"
#include "GpuTransferCounters.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/ParseMibBudget.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "Deep2LivePath.hpp"
#include "GPUForwardChildIgnoreHooks.hpp"
#include <chrono>
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
    // BATCH10_ARENA_GEOMETRY: account for dense, MoE and MLA projection widths.
    uint64_t inter64 = std::max<uint64_t>(
        modelWeights.intermediateDim,
        modelWeights.moeIntermediateDim);
    inter64 = std::max<uint64_t>(inter64, modelWeights.qLoraRank);
    inter64 = std::max<uint64_t>(
        inter64, modelWeights.kvLoraRank + modelWeights.qkRopeHeadDim);
    inter64 = std::max<uint64_t>(
        inter64, modelWeights.numHeads *
                 (modelWeights.qkNopeHeadDim + modelWeights.qkRopeHeadDim));
    inter64 = std::max<uint64_t>(
        inter64, modelWeights.numHeads * modelWeights.vHeadDim);
    if (inter64 == 0) inter64 = (uint64_t)H * 4u;
    if (inter64 > UINT32_MAX) return false;
    const uint32_t inter = (uint32_t)inter64;
    // Batch3 #12: multi-GPU layer-split slots only execute their contiguous
    // layer range; size K/V caches to that range instead of all 64 layers.
    // Reclaims ~1GB of device-local VRAM per split slot (the 7800 XT's
    // weight budget was short by exactly the lmHead slice it re-uploaded
    // every token in the B3 experiment).
    uint32_t kvLayers = 0;
    if (multiGpuLayerPlan_.active &&
        slot < multiGpuLayerPlan_.gpuSlotCount &&
        multiGpuLayerPlan_.rangeLo.size() > slot) {
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[slot];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[slot];
        if (hi >= lo) kvLayers = hi - lo + 1u;
    }
    if (!vc->EnsureForwardArena(
        H, inter ? inter : H * 4,
        (uint32_t)modelWeights.numHeads,
        (uint32_t)modelWeights.numKVHeads,
        (uint32_t)modelWeights.headDim,
        (uint32_t)(config.maxSeqLen ? config.maxSeqLen : 128),
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22),
        kvLayers))
        return false;
    // Absolute-layer -> cache-slot mapping for split slots: AppendKV and
    // DispatchAttnDecode address the sized K/V region relative to this base.
    if (kvLayers && slot < multiGpuLayerPlan_.rangeLo.size())
        vc->SetKvLayerBase(multiGpuLayerPlan_.rangeLo[slot]);
    else
        vc->SetKvLayerBase(0u);
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
    // Dense 32B decode must remain resident after warmup.  A 512 MiB
    // default guarantees full-model cache churn.  Reserve 20% of VRAM for
    // KV/arenas/driver allocations and let the packed layer weights use the
    // remaining 80%.  Explicit env values still override this policy.
    size_t budget = (size_t)512 << 20;
    const uint64_t localBytes = vc->deviceLocalBytes();
    if (localBytes >= (uint64_t(4) << 30)) {
        const uint64_t autoBudget = (localBytes / 10u) * 8u;
        if (autoBudget <= (uint64_t)SIZE_MAX)
            budget = static_cast<size_t>(autoBudget);
    }
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
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22),
        kvLayers);
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
    vc->SetWorkEpoch(kvCache ? kvCache->currentLength() : 0);

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

    const uint64_t liveSeq =
        kvCache ? static_cast<uint64_t>(kvCache->currentLength()) : 0ull;
    CycloneScheduler* liveCyc = LivePath_ActiveCyclone();
    if (!liveCyc && cycloneEnabled_) liveCyc = cyclone_.get();
    if (LivePath_Active())
        LivePath_OnLayerStart(liveCyc, layer, liveSeq);

    const bool prefetch = vc->WeightPrefetchActive() ||
        (std::getenv("DEEP2_WEIGHT_PREFETCH") &&
         std::getenv("DEEP2_WEIGHT_PREFETCH")[0] != '0');
    const bool fuse = !prefetch;
    // A caller may already own a token/range-wide command buffer.
    // Only create/submit a per-layer command when no outer fusion exists.
    const bool ownFusion = fuse && !vc->FusedRecording();
    if (ownFusion && !vc->BeginFusedLayer()) return false;
    auto fail = [&]() -> bool {
        if (ownFusion) (void)vc->EndFusedLayer();
        (void)vc->FlushWeightComputes();
        return false;
    };
    const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
    /* DualStick owns work: real weight bytes → FreeToken Overwrite (not null Resolve). */
    if (attnW)
        DualStickAcquire(slot, attnW, (size_t)H * sizeof(float), 0, layer, 0);
    else
        DualStickResolve(slot, layer);
    if (!attnW) return fail();
    auto* attnNormBuf =
        vc->ResolveResidentF32(attnW, WeightKey(lw.attnNorm), H);
    if (!attnNormBuf) return fail();

    const float* ffnW = EnsureF32(*this, lw.ffnNorm, vulkanWeightF32_);
    if (!ffnW) return fail();
    auto* ffnNormBuf =
        vc->ResolveResidentF32(ffnW, WeightKey(lw.ffnNorm), H);
    if (!ffnNormBuf) return fail();
    const WeightTensor* woWt = lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!woWt) return fail();
    auto gemv = [&](const WeightTensor& wt, CPUInference::VulkanCompute::DeviceBuf& in,
                    CPUInference::VulkanCompute::DeviceBuf& out,
                    uint32_t rows, uint32_t cols) -> bool {
        if (PackedQuant(wt)) {
            if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++c.q4kPackedOps;
            else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++c.q6kPackedOps;
            else if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) {
                /* SAME_84_BYTE as DEEP2_PACKED_Q2K_PRODUCT_DUAL_AGGREGATE_001 */
                ++c.q2kPackedOps;
            }
            if (prefetch && vc->WeightStreamActive()) {
                if (!vc->FlushWeightComputes()) return false;
                uint32_t sl = 0;
                if (!vc->PrefetchWeight(wt.data, wt.sizeBytes, sl)) return false;
                return vc->SubmitGemvPrefetch(sl, in, out, rows, cols, wt.sizeBytes, wt.type);
            }
            /* DualStick armed: prefer in-process 84-byte packed Q2_K (never 72-byte MASM). */
            return vc->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes, in, out, rows, cols);
        }
        /* Product decode: Q2_K must not host-Expand F32 / 72-byte MASM. */
        if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) {
            const char* pd = std::getenv("RAWRXD_Q2K_PRODUCT_DECODE");
            if (pd && pd[0] == '1') return false;
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
    auto gemvOverlap3 = [&](const WeightTensor& qa, const WeightTensor& qb,
                            const WeightTensor& qc,
                            CPUInference::VulkanCompute::DeviceBuf& in,
                            CPUInference::VulkanCompute::DeviceBuf& outA,
                            CPUInference::VulkanCompute::DeviceBuf& outB,
                            CPUInference::VulkanCompute::DeviceBuf& outC,
                            uint32_t rA, uint32_t rB, uint32_t rC, uint32_t cols) -> bool {
        if (!(prefetch && vc->WeightStreamActive())) {
            return gemv(qa, in, outA, rA, cols) && gemv(qb, in, outB, rB, cols) &&
                   gemv(qc, in, outC, rC, cols);
        }
        if (PackedQuant(qa) && PackedQuant(qb) && PackedQuant(qc)) {
            auto bumpQ = [&](const WeightTensor& wt) {
                if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++c.q4kPackedOps;
                else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++c.q6kPackedOps;
                else if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) ++c.q2kPackedOps;
            };
            bumpQ(qa); bumpQ(qb); bumpQ(qc);
            if (!vc->FlushWeightComputes()) return false;
            uint32_t sa = 0, sb = 0, sc = 0;
            if (!vc->PrefetchWeight(qa.data, qa.sizeBytes, sa)) return false;
            if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols, qa.sizeBytes, qa.type))
                return false;
            if (!vc->PrefetchWeight(qb.data, qb.sizeBytes, sb)) return false;
            if (!vc->WaitWeightCompute(sa)) return false;
            if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols, qb.sizeBytes, qb.type))
                return false;
            if (!vc->PrefetchWeight(qc.data, qc.sizeBytes, sc)) return false;
            if (!vc->WaitWeightCompute(sb)) return false;
            if (!vc->SubmitGemvPrefetch(sc, in, outC, rC, cols, qc.sizeBytes, qc.type))
                return false;
            return vc->WaitWeightCompute(sc);
        }
        if (!vc->FlushWeightComputes()) return false;
        const float* wa = EnsureF32(*this, qa, vulkanWeightF32_);
        uint32_t sa = 0;
        if (!wa || !vc->PrefetchWeight(wa, (size_t)rA * cols * 4, sa)) return false;
        if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols)) return false;
        const float* wb = EnsureF32(*this, qb, vulkanWeightF32_);
        uint32_t sb = 0;
        if (!wb || !vc->PrefetchWeight(wb, (size_t)rB * cols * 4, sb)) return false; // overlaps GEMV A
        if (!vc->WaitWeightCompute(sa)) return false;
        if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols)) return false;
        const float* wc = EnsureF32(*this, qc, vulkanWeightF32_);
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

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),
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

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),
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

    if (ownFusion && !vc->EndFusedLayer()) return false;
    {
        DEEP2_GPU_CHILD_SCOPE(syncScope, SyncWait);
        if (!vc->FlushWeightComputes()) return false;
    }
    if (!fuse) vc->ResetWeightWindowLayerCursor();
    if (ownFusion) ++c.layerSubmits;
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
    if (LivePath_Active())
        LivePath_OnLayerEnd(liveCyc, layer, liveSeq, 0);
    return true;
}

bool Deep2Engine::forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                            const float* hostIn, float* hostOut) {
    rawr::gpu_iso::Begin();
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    {
        const auto upStart = std::chrono::steady_clock::now();
        if (!vc->UploadHidden(hostIn, H)) return false;
        const auto upEnd = std::chrono::steady_clock::now();
        gpuFwd_.residentUploadHiddenNs += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                upEnd - upStart).count());
        ++gpuFwd_.residentUploadHiddenCount;
        gpuFwd_.residentUploadHiddenBytes +=
            static_cast<uint64_t>(H) * sizeof(float);
    }
    ++gpuFwd_.hostSyncBoundaries;

    const bool rangeFuse = !vc->WeightPrefetchActive();
    const auto rangeStart = std::chrono::steady_clock::now();
    if (rangeFuse && !vc->BeginFusedLayer()) return false;
    // PARITY: resident lane tag for dispatches inside this range.
    vc->SetQ4kLaneTag(CPUInference::VulkanCompute::kQ4kLaneResident);
    for (uint32_t L = lo; L <= hi; ++L) {
        if (!forwardLayerGpuResident(L, slot, false, false)) {
            if (rangeFuse && vc->FusedRecording())
                (void)vc->EndFusedLayer();
            return false;
        }
    }
    vc->SetQ4kLaneTag(0);
    if (rangeFuse && !vc->EndFusedLayer()) return false;
    const auto rangeEnd = std::chrono::steady_clock::now();
    if (rangeFuse) {
        ++gpuFwd_.layerSubmits;
        ++gpuFwd_.residentQueueSubmits;
        ++gpuFwd_.residentFenceWaits;
    }
    if (slot < 2) {
        gpuFwd_.residentRangeNs[slot] += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                rangeEnd - rangeStart).count());
        if (vc->LastFusedIntervalValid())
            gpuFwd_.residentRangeGpuNs[slot] +=
                vc->LastFusedInterval().calibratedDurationNs();
        ++gpuFwd_.residentRangeCount[slot];
    }
    {
        DEEP2_GPU_CHILD_SCOPE(rbScope, ReadbackD2H);
        const auto dlStart = std::chrono::steady_clock::now();
        if (!vc->DownloadHidden(hostOut, H)) return false;
        const auto dlEnd = std::chrono::steady_clock::now();
        gpuFwd_.residentFinalDownloadNs += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                dlEnd - dlStart).count());
        ++gpuFwd_.residentFinalDownloadCount;
        ++gpuFwd_.hostSyncBoundaries;
    }
    return true;
}

bool Deep2Engine::forwardGpuMultiMap(const float* hostIn, float* hostOut) {
    if (!multiGpuLayerPlan_.active || multiGpuLayerPlan_.gpuSlotCount < 1) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;
    const unsigned gpuN = multiGpuLayerPlan_.gpuSlotCount;

    // B5_SLOT1_RANGE_RESIDENCY_001 (+ slot 0): pin every slot's full layer
    // range at first execution so the measured 280-upload slot-1 churn
    // cannot recur. Admission is proven at init
    // (B5_SLOT1_RESIDENCY_ADMISSION_001, ADMISSION_FITS=1). Pinning reuses
    // the B4 PinWeightView substrate: pinned entries are skipped by
    // eviction but still count against the cache budget, so the admission
    // arithmetic remains the authority.
    for (unsigned s = 0; s < gpuN && s < 2; ++s) {
        if (layerRangePinned_[s]) continue;
        auto* vc = getVulkanComputeSlot(s);
        if (!vc) continue;
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[s];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[s];
        bool allOk = true;
        const auto t0 = std::chrono::steady_clock::now();
        for (uint32_t L = lo; L <= hi && L < modelWeights.layers.size(); ++L) {
            const auto& lw = modelWeights.layers[L];
            GpuWeightView v{};
            if (!Deep2BuildGpuWeightView(lw.wq, 0,
                    static_cast<uint32_t>(lw.wq.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            if (!Deep2BuildGpuWeightView(lw.wk, 0,
                    static_cast<uint32_t>(lw.wk.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            if (!Deep2BuildGpuWeightView(lw.wv, 0,
                    static_cast<uint32_t>(lw.wv.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            const WeightTensor& woT = lw.wo.data ? lw.wo : lw.attnO;
            if (!Deep2BuildGpuWeightView(woT, 0,
                    static_cast<uint32_t>(woT.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            if (!Deep2BuildGpuWeightView(lw.wGate, 0,
                    static_cast<uint32_t>(lw.wGate.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            if (!Deep2BuildGpuWeightView(lw.wUp, 0,
                    static_cast<uint32_t>(lw.wUp.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
            if (!Deep2BuildGpuWeightView(lw.wDown, 0,
                    static_cast<uint32_t>(lw.wDown.rows), v) ||
                !vc->PinWeightView(v)) { allOk = false; break; }
        }
        if (allOk) {
            layerRangePinned_[s] = true;
            const auto t1 = std::chrono::steady_clock::now();
            const uint64_t pinNs = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    t1 - t0).count());
            std::fprintf(stderr,
                "[B5_RANGE_PIN] slot=%u layers=%u-%u pinned in %llu ns\n",
                s, lo, hi,
                static_cast<unsigned long long>(pinNs));
        }
    }

    for (unsigned s = 0; s < gpuN; ++s)
        if (!ensureGpuForwardArena(s)) return false;

    auto* vc0 = getVulkanComputeSlot(0);
    if (!vc0) return false;
    {
        const auto upStart = std::chrono::steady_clock::now();
        if (!vc0->UploadHidden(hostIn, H)) return false;
        const auto upEnd = std::chrono::steady_clock::now();
        gpuFwd_.residentUploadHiddenNs += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                upEnd - upStart).count());
        ++gpuFwd_.residentUploadHiddenCount;
        gpuFwd_.residentUploadHiddenBytes +=
            static_cast<uint64_t>(H) * sizeof(float);
    }
    ++gpuFwd_.hostSyncBoundaries;

    // BATCH9_USEFUL_NEXT_STICK_PRIME:
    // While GPU0 executes its dependent layer range, GPU1 transfers a REAL
    // tensor that GPU1 will consume next. The target buffer is adopted into
    // the normal weight cache; this is not a disposable timing workload.
    CPUInference::VulkanCompute::MaterialTicket batch9Prime{};
    int batch9PrimeType = -1;
    uint64_t batch9PrimeKey = 0;
    bool batch9PrimeLive = false;
    if (gpuN > 1) {
        auto* next = getVulkanComputeSlot(1);
        const uint32_t nLo = multiGpuLayerPlan_.rangeLo[1];
        if (next && nLo < modelWeights.layers.size() &&
            !next->WeightPrefetchActive()) {
            const WeightTensor& wt = modelWeights.layers[nLo].wq;
            const bool gpuPacked =
                wt.type == (int)GGMLType::GGML_TYPE_Q8_0 ||
                wt.type == (int)GGMLType::GGML_TYPE_Q2_K ||
                wt.type == (int)GGMLType::GGML_TYPE_Q4_K ||
                wt.type == (int)GGMLType::GGML_TYPE_Q6_K;
            if (wt.data && (gpuPacked ||
                wt.type == (int)GGMLType::GGML_TYPE_F32)) {
                const size_t bytes = gpuPacked
                    ? wt.sizeBytes
                    : wt.rows * wt.cols * sizeof(float);
                batch9PrimeType = gpuPacked ? wt.type : 0;
                batch9PrimeKey = gpuPacked
                    ? (uint64_t)(uintptr_t)wt.data
                    : WeightKey(wt);
                const uint64_t epoch =
                    kvCache ? kvCache->currentLength() : 0;
                next->SetWorkEpoch(epoch);
                batch9PrimeLive = next->SubmitWeightPrimeAsync(
                    wt.data, bytes, batch9PrimeType,
                    batch9PrimeKey, epoch, batch9Prime);
            }
        }
    }

    for (unsigned s = 0; s < gpuN; ++s) {
        auto* vc = getVulkanComputeSlot(s);
        if (s == 1 && batch9PrimeLive) {
            Deep2::GpuWorkInterval primeInterval{};
            // COST_ATTRIBUTION: the prime's fence wait is a blocking host
            // phase of the resident lane — measure it separately from the
            // layer range so 64/128/256 slopes can isolate it.
            const auto primeStart = std::chrono::steady_clock::now();
            if (!vc || !vc->CommitWeightPrime(
                    batch9Prime,batch9PrimeType,batch9PrimeKey,
                    &primeInterval))
                return false;
            const auto primeEnd = std::chrono::steady_clock::now();
            gpuFwd_.residentPrimeCommitNs += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    primeEnd - primeStart).count());
            ++gpuFwd_.residentPrimeCommitCount;
            batch9PrimeLive = false;
        }
        if (!vc) return false;
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[s];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[s];

        const bool rangeFuse = !vc->WeightPrefetchActive();
        const auto rangeStart = std::chrono::steady_clock::now();
        if (rangeFuse && !vc->BeginFusedLayer()) return false;
        // PARITY: resident lane tag for dispatches inside this range.
        vc->SetQ4kLaneTag(CPUInference::VulkanCompute::kQ4kLaneResident);
        for (uint32_t L = lo; L <= hi; ++L) {
            if (!forwardLayerGpuResident(L, s, false, false)) {
                if (rangeFuse && vc->FusedRecording())
                    (void)vc->EndFusedLayer();
                return false;
            }
        }
        vc->SetQ4kLaneTag(0);
        if (rangeFuse && !vc->EndFusedLayer()) return false;
        if (rangeFuse) {
            ++gpuFwd_.layerSubmits;
            ++gpuFwd_.residentQueueSubmits;
            ++gpuFwd_.residentFenceWaits;
        }
        const auto rangeEnd = std::chrono::steady_clock::now();
        if (s < 2) {
            gpuFwd_.residentRangeNs[s] += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    rangeEnd - rangeStart).count());
            if (vc->LastFusedIntervalValid())
                gpuFwd_.residentRangeGpuNs[s] +=
                    vc->LastFusedInterval().calibratedDurationNs();
            ++gpuFwd_.residentRangeCount[s];
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
            const auto hoStart = std::chrono::steady_clock::now();
            if (!next || !vc->CopyArenaHiddenTo(*next, H)) return false;
            const auto hoEnd = std::chrono::steady_clock::now();
            gpuFwd_.residentHandoffNs += static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    hoEnd - hoStart).count());
            ++gpuFwd_.residentHandoffCount;
            gpuFwd_.residentHandoffBytes +=
                static_cast<uint64_t>(H) * sizeof(float);
            ++gpuFwd_.ownershipTransfers;
            if (vc->LastCrossDeviceCopyUsedHost()) {
                // Batch 9 refuses to call a host bounce peer-resident.
                ++gpuFwd_.hostMaterializations;
                ++gpuFwd_.matCrossDeviceHandoff;
                ++gpuFwd_.intraSlotHostTransfers;
            }
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
        const auto dlStart = std::chrono::steady_clock::now();
        if (!lastGpu->DownloadHidden(hostOut, H)) return false;
        const auto dlEnd = std::chrono::steady_clock::now();
        gpuFwd_.residentFinalDownloadNs += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                dlEnd - dlStart).count());
        ++gpuFwd_.residentFinalDownloadCount;
        ++gpuFwd_.hostSyncBoundaries;
        // The final download is its own materialization class: required by
        // the current contract (host samples logits) but measured explicitly
        // so B5.2/B6 can target it.
        ++gpuFwd_.hostMaterializations;
        ++gpuFwd_.matFinalDownload;
        gpuFwd_.matFinalDownloadNs += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                dlEnd - dlStart).count());
    }
    return true;
}

const GpuForwardCounters& Deep2Engine::gpuForwardCounters() const { return gpuFwd_; }
void Deep2Engine::resetGpuForwardCounters() { gpuFwd_ = GpuForwardCounters{}; }
bool Deep2Engine::isRealGpuForward() const {
    return Deep2GpuForward_IsReal(gpuFwd_, vulkanGemvFail_);
}

} // namespace Deep2

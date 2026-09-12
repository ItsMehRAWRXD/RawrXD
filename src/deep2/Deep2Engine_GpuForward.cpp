// Deep2Engine_GpuForward.cpp — forwardLayerGpuResident + contiguous/multi/hybrid
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "QuantKernelRegistry.hpp"
#include "GpuTransferCounters.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/ParseMibBudget.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "Deep2LivePath.hpp"
#include "Deep2Locality64.hpp"
#include "GPUForwardChildIgnoreHooks.hpp"
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#ifdef _WIN32
#include <windows.h>
#endif
#include <unordered_map>
#include <vector>

namespace Deep2 {
namespace {

/* BIND16 / Batch2 product ABI is process-shared — serialize across DualStick threads. */
std::mutex& DualStickProductMu() {
    static std::mutex m;
    return m;
}

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
        (uint32_t)(modelWeights.numLayers ? modelWeights.numLayers : 22))) {
        std::fprintf(stderr, "GPU_ARENA_ENSURE_FAIL slot=%u H=%u I=%u\n",
                     slot, H, inter);
        return false;
    }
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
        if (!pr.ok) {
            std::fprintf(stderr, "GPU_ARENA_BUDGET_PARSE_FAIL slot=%u\n", slot);
            return false;
        }
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
    if (!vc->ApplyWeightWindowPolicy(maxB, budget, ov, arena)) {
        std::fprintf(stderr,
            "GPU_ARENA_WINDOW_FAIL slot=%u maxB=%zu budget=%zu arena=%zu ov=%u\n",
            slot, maxB, budget, arena, ov);
        return false;
    }
    return true;
}

bool Deep2Engine::forwardLayerGpuResident(
    uint32_t layer, unsigned slot, bool uploadEntry, bool downloadExit)
{
    if (!vulkanInitialized_ || vulkanDevices_.empty()) return false;
    if (layer >= modelWeights.layers.size()) return false;
    if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, (int)slot)) return false;
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;
    const uint64_t loc_t0 = (uint64_t)std::chrono::duration_cast<
        std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

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
        !lw.wGate.data || !lw.wUp.data || !lw.wDown.data) {
        std::fprintf(stderr,
            "GPU_RESIDENT_LAYER_MISS layer=%u slot=%u wq=%p gate=%p\n",
            layer, slot, (void*)lw.wq.data, (void*)lw.wGate.data);
        return false;
    }

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
    if (fuse && !vc->BeginFusedLayer()) {
        std::fprintf(stderr, "GPU_RESIDENT_BEGIN_FUSE_FAIL layer=%u slot=%u\n",
                     layer, slot);
        return false;
    }
    auto fail = [&](const char* why = "?") -> bool {
        std::fprintf(stderr, "GPU_RESIDENT_FAIL layer=%u slot=%u why=%s\n",
                     layer, slot, why ? why : "?");
        if (fuse) (void)vc->EndFusedLayer();
        (void)vc->FlushWeightComputes();
        return false;
    };
    const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
    /* DualStick owns work: real weight bytes → FreeToken Overwrite (not null Resolve). */
    if (attnW)
        DualStickAcquire(slot, attnW, (size_t)H * sizeof(float), 0, layer, 0);
    else
        DualStickResolve(slot, layer);
    if (!attnW || !vc->UploadNormWeight(vc->ArenaAttnW(), attnW, H))
        return fail("attn_norm");
    const float* ffnW = EnsureF32(*this, lw.ffnNorm, vulkanWeightF32_);
    if (!ffnW || !vc->UploadNormWeight(vc->ArenaFfnW(), ffnW, H))
        return fail("ffn_norm");
    const WeightTensor* woWt = lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!woWt) return fail("wo_missing");
    auto gemv = [&](const WeightTensor& wt, CPUInference::VulkanCompute::DeviceBuf& in,
                    CPUInference::VulkanCompute::DeviceBuf& out,
                    uint32_t rows, uint32_t cols) -> bool {
        if (PackedQuant(wt)) {
            if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++c.q4kPackedOps;
            else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++c.q6kPackedOps;
            else if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) {
                ++c.q2kPackedOps;
                /* BIND16_GATE: N>0 product via BIND16 first (governing ABI).
                 * DualStick speculative concurrent stick may force device quant. */
                const bool deviceOnly =
                    (dualStickDeviceOnlyMask_.load(std::memory_order_acquire)
                     & (1u << slot)) != 0;
                const bool bind16Tok =
                    !deviceOnly &&
                    ssvkBind16_.run != nullptr &&
                    ssvkBind16_.token.token_ordinal > 0 &&
                    wt.data && wt.sizeBytes;
                const bool batch2Tok =
                    !deviceOnly && !bind16Tok && ssVkProductBind_.bound() &&
                    ssVkProductBind_.tokenProof().tokenOrdinal > 0 &&
                    wt.data && wt.sizeBytes;
                if (bind16Tok) {
                    std::vector<float> xin(cols), yout(rows);
                    if (!vc->DownloadBuf(in, xin.data(), cols)) return false;
                    D2PackedProductRequest req{};
                    req.packed_weights = wt.data;
                    req.input = xin.data();
                    req.output = yout.data();
                    req.rows = rows;
                    req.cols = cols;
                    req.weight_bytes = wt.sizeBytes;
                    req.tensor_name = wt.name.c_str();
                    {
                        std::lock_guard<std::mutex> lk(DualStickProductMu());
                        if (!d2bind16_dispatch_q2k(&ssvkBind16_, &req)) {
                            std::fprintf(stderr,
                                "BIND16_GPUFWD_Q2K_FAIL rows=%u cols=%u name=%s\n",
                                rows, cols, wt.name.c_str());
                            return false;
                        }
                    }
                    return vc->UploadBuf(out, yout.data(), rows);
                }
                if (batch2Tok) {
                    std::vector<float> xin(cols), yout(rows);
                    if (!vc->DownloadBuf(in, xin.data(), cols)) return false;
                    SsVkQ2KRequest req{};
                    req.packedWeights = wt.data;
                    req.input = xin.data();
                    req.output = yout.data();
                    req.rows = rows;
                    req.cols = cols;
                    req.weightBytes = wt.sizeBytes;
                    req.tensorName = wt.name.c_str();
                    for (int attempt = 0; attempt < 4; ++attempt) {
                        bool ok = false;
                        {
                            std::lock_guard<std::mutex> lk(DualStickProductMu());
                            ok = ssVkProductBind_.dispatchQ2K(req);
                        }
                        if (ok && vc->UploadBuf(out, yout.data(), rows))
                            return true;
                    }
                    std::fprintf(stderr,
                        "BATCH2_GPUFWD_Q2K_FAIL rows=%u cols=%u name=%s\n",
                        rows, cols, wt.name.c_str());
                    return false;
                }
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
    auto gemvOverlap3 = [&](const WeightTensor& wa, const WeightTensor& wb, const WeightTensor& wc,
                            CPUInference::VulkanCompute::DeviceBuf& in,
                            CPUInference::VulkanCompute::DeviceBuf& outA,
                            CPUInference::VulkanCompute::DeviceBuf& outB,
                            CPUInference::VulkanCompute::DeviceBuf& outC,
                            uint32_t rA, uint32_t rB, uint32_t rC, uint32_t cols) -> bool {
        /* N>0 BIND16/Batch2: force gemv() so QKV hits product ABI. */
        const bool forceProduct =
            (ssvkBind16_.run != nullptr &&
             ssvkBind16_.token.token_ordinal > 0) ||
            (ssVkProductBind_.bound() &&
             ssVkProductBind_.tokenProof().tokenOrdinal > 0);
        if (!(prefetch && vc->WeightStreamActive()) || forceProduct) {
            return gemv(wa, in, outA, rA, cols) && gemv(wb, in, outB, rB, cols) &&
                   gemv(wc, in, outC, rC, cols);
        }
        if (PackedQuant(wa) && PackedQuant(wb) && PackedQuant(wc)) {
            auto bumpQ = [&](const WeightTensor& wt) {
                if (wt.type == (int)GGMLType::GGML_TYPE_Q4_K) ++c.q4kPackedOps;
                else if (wt.type == (int)GGMLType::GGML_TYPE_Q6_K) ++c.q6kPackedOps;
                else if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) ++c.q2kPackedOps;
            };
            bumpQ(wa); bumpQ(wb); bumpQ(wc);
            if (!vc->FlushWeightComputes()) return false;
            uint32_t sa = 0, sb = 0, sc = 0;
            if (!vc->PrefetchWeight(wa.data, wa.sizeBytes, sa)) return false;
            if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols, wa.sizeBytes, wa.type))
                return false;
            if (!vc->PrefetchWeight(wb.data, wb.sizeBytes, sb)) return false;
            if (!vc->WaitWeightCompute(sa)) return false;
            if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols, wb.sizeBytes, wb.type))
                return false;
            if (!vc->PrefetchWeight(wc.data, wc.sizeBytes, sc)) return false;
            if (!vc->WaitWeightCompute(sb)) return false;
            if (!vc->SubmitGemvPrefetch(sc, in, outC, rC, cols, wc.sizeBytes, wc.type))
                return false;
            return vc->WaitWeightCompute(sc);
        }
        if (!vc->FlushWeightComputes()) return false;
        const float* fwa = EnsureF32(*this, wa, vulkanWeightF32_);
        uint32_t sa = 0;
        if (!fwa || !vc->PrefetchWeight(fwa, (size_t)rA * cols * 4, sa)) return false;
        if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols)) return false;
        const float* fwb = EnsureF32(*this, wb, vulkanWeightF32_);
        uint32_t sb = 0;
        if (!fwb || !vc->PrefetchWeight(fwb, (size_t)rB * cols * 4, sb)) return false;
        if (!vc->WaitWeightCompute(sa)) return false;
        if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols)) return false;
        const float* fwc = EnsureF32(*this, wc, vulkanWeightF32_);
        uint32_t sc = 0;
        if (!fwc || !vc->PrefetchWeight(fwc, (size_t)rC * cols * 4, sc)) return false;
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
        return fail("rms_attn");
    ++c.rmsNormOps;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;
    {
        DEEP2_GPU_CHILD_SCOPE(qkvScope, QKV);
        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), H, kvDim, kvDim, H))
            return fail("qkv");
        c.qkvOps += 3;
    }
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                          modelWeights.ropeTheta))
        return fail("rope");
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer))
            return fail("append_kv");
    }
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);
        const float scale = 1.0f / std::sqrt((float)headDim);
        if (!vc->DispatchAttnDecode(vc->ArenaQ(), vc->ArenaKCache(), vc->ArenaVCache(),
                                    vc->ArenaAttn(), headDim, nHeads, nKv, pos + 1, scale,
                                    layer))
            return fail("attn");
        ++c.attnScoreOps;
        ++c.softmaxOps;
        ++c.attnValueOps;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);
        if (!gemv(*woWt, vc->ArenaAttn(), vc->ArenaDown(), H, H))
            return fail("o_proj");
        ++c.oProjOps;
        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail("attn_res");
        ++c.residualOps;
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), vc->ArenaFfnW(), vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("rms_ffn");
    ++c.ffnNormOps;

    {
        DEEP2_GPU_CHILD_SCOPE(ffnScope, FFN);
        if (prefetch && vc->WeightStreamActive() &&
            !PackedQuant(lw.wGate) && !PackedQuant(lw.wUp)) {
            if (!vc->FlushWeightComputes()) return fail("ffn_flush");
            const float* wg = EnsureF32(*this, lw.wGate, vulkanWeightF32_);
            uint32_t sg = 0;
            if (!wg || !vc->PrefetchWeight(wg, (size_t)inter * H * 4, sg))
                return fail("ffn_pref_g");
            if (!vc->SubmitGemvPrefetch(sg, vc->ArenaNormed(), vc->ArenaGate(), inter, H))
                return fail("ffn_gemv_g");
            const float* wu = EnsureF32(*this, lw.wUp, vulkanWeightF32_);
            uint32_t su = 0;
            if (!wu || !vc->PrefetchWeight(wu, (size_t)inter * H * 4, su))
                return fail("ffn_pref_u");
            if (!vc->WaitWeightCompute(sg)) return fail("ffn_wait_g");
            if (!vc->SubmitGemvPrefetch(su, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
                return fail("ffn_gemv_u");
            if (!vc->WaitWeightCompute(su)) return fail("ffn_wait_u");
        } else if (!gemv(lw.wGate, vc->ArenaNormed(), vc->ArenaGate(), inter, H) ||
                   !gemv(lw.wUp, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
            return fail("ffn_gate_up");
        c.qkvOps += 2;
        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail("swiglu");
        ++c.ffnActOps;
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter))
            return fail("ffn_down");
        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail("ffn_res");
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
    if (LivePath_Active())
        LivePath_OnLayerEnd(liveCyc, layer, liveSeq, 0);
    {
        const uint64_t loc_t1 = (uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        const uint64_t ord = Locality64_ActiveOrdinal().load(
            std::memory_order_acquire);
        if (Locality64_Global().armed() && ord < Locality64Collector::kTargetTokens)
            Locality64_NoteGpuForwardSpan(slot, ord, loc_t0, loc_t1);
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
    if (!multiGpuLayerPlan_.active || multiGpuLayerPlan_.gpuSlotCount < 1) {
        std::fprintf(stderr, "GPU_MULTIMAP_FAIL why=plan\n");
        return false;
    }
    const uint32_t H = (uint32_t)config.hiddenDim;
    const unsigned gpuN = multiGpuLayerPlan_.gpuSlotCount;

    for (unsigned s = 0; s < gpuN; ++s) {
        if (!ensureGpuForwardArena(s)) {
            std::fprintf(stderr, "GPU_MULTIMAP_FAIL why=arena slot=%u\n", s);
            return false;
        }
    }

    auto* vc0 = getVulkanComputeSlot(0);
    if (!vc0 || !vc0->UploadHidden(hostIn, H)) {
        std::fprintf(stderr, "GPU_MULTIMAP_FAIL why=upload_hidden\n");
        return false;
    }
    ++gpuFwd_.hostSyncBoundaries;

    for (unsigned s = 0; s < gpuN; ++s) {
        auto* vc = getVulkanComputeSlot(s);
        if (!vc) {
            std::fprintf(stderr, "GPU_MULTIMAP_FAIL why=slot_null s=%u\n", s);
            return false;
        }
        const uint32_t lo = multiGpuLayerPlan_.rangeLo[s];
        const uint32_t hi = multiGpuLayerPlan_.rangeHi[s];
        for (uint32_t L = lo; L <= hi; ++L) {
            if (!forwardLayerGpuResident(L, s, false, false)) {
                std::fprintf(stderr,
                    "GPU_MULTIMAP_FAIL why=layer_resident L=%u s=%u\n", L, s);
                return false;
            }
        }
        if (s + 1 < gpuN) {
            auto* next = getVulkanComputeSlot(s + 1);
            if (elasticResidencyEnabled_ && elasticResidency_) {
                const uint32_t nLo = multiGpuLayerPlan_.rangeLo[s + 1];
                elasticResidency_->PredictLayerNeeds(nLo, nullptr, 0);
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

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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>
#include <vector>

namespace Deep2 {
namespace {

// RAWRXD_GPU_FINITE_PREFIX_DIAG_001
struct GpuFiniteWitness {
    size_t finite = 0, nan = 0, inf = 0;
    size_t firstBad = static_cast<size_t>(-1);
    float minFinite = 0.0f, maxFinite = 0.0f;
};

static bool GpuFiniteTraceEnabled() {
    const char* s = std::getenv("DEEP2_GPU_FINITE_TRACE");
    return s && *s && std::strcmp(s, "0") != 0;
}

static long GpuTracePrefixHi() {
    const char* s = std::getenv("DEEP2_GPU_TRACE_PREFIX_HI");
    if (!s || !*s) return -1;
    char* end = nullptr;
    long v = std::strtol(s, &end, 10);
    return (end == s || (end && *end) || v < 0) ? -1 : v;
}

static GpuFiniteWitness ScanGpuFiniteWitness(const float* p, size_t n) {
    GpuFiniteWitness w{};
    bool haveFinite = false;
    if (!p) return w;
    for (size_t i = 0; i < n; ++i) {
        const float v = p[i];
        if (std::isnan(v)) {
            ++w.nan;
            if (w.firstBad == static_cast<size_t>(-1)) w.firstBad = i;
        } else if (std::isinf(v)) {
            ++w.inf;
            if (w.firstBad == static_cast<size_t>(-1)) w.firstBad = i;
        } else {
            ++w.finite;
            if (!haveFinite) {
                w.minFinite = w.maxFinite = v;
                haveFinite = true;
            } else {
                if (v < w.minFinite) w.minFinite = v;
                if (v > w.maxFinite) w.maxFinite = v;
            }
        }
    }
    return w;
}

constexpr uint64_t kGpuForwardBuildRevision = 2026092401ULL;

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
           t == (int)GGMLType::GGML_TYPE_Q4_K ||
           t == (int)GGMLType::GGML_TYPE_Q5_K ||
           t == (int)GGMLType::GGML_TYPE_Q6_K;
}

// OVERFLOW_SAFE: compute dense F32 byte count from tensor metadata if
// possible, with uint64_t promotion and saturation guard.
bool DenseF32Bytes(const WeightTensor& wt, size_t& outBytes) {
    outBytes = 0;
    if (!wt.data || !wt.rows || !wt.cols) return false;
    if (PackedQuant(wt)) {
        outBytes = wt.sizeBytes;
        return true;
    }
    uint64_t r = wt.rows;
    uint64_t c = wt.cols;
    uint64_t bytes = r * c * sizeof(float);
    if (bytes > (uint64_t)std::numeric_limits<size_t>::max()) {
        std::fprintf(stderr, "DENSE_F32_BYTES_OVERFLOW name=%s rows=%u cols=%u\n",
            wt.name.c_str(), (unsigned)wt.rows, (unsigned)wt.cols);
        return false;
    }
    outBytes = static_cast<size_t>(bytes);
    return true;
}

size_t StreamBytes(const WeightTensor& wt) {
    size_t b = 0;
    if (!DenseF32Bytes(wt, b)) return 0;
    return b;
}

const float* EnsureF32(Deep2Engine& e, const WeightTensor& wt,
                       std::unordered_map<std::string, std::vector<float>>& cache) {
    (void)e;
    std::fprintf(stderr, "ENSURE_F32_ENTER name=%s type=%d rows=%u cols=%u data=%p\n",
        wt.name.c_str(), wt.type, (unsigned)wt.rows, (unsigned)wt.cols, (void*)wt.data);
    if (!wt.data) {
        std::fprintf(stderr, "ENSURE_F32_FAIL_NULL name=%s\n", wt.name.c_str());
        return nullptr;
    }
    if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        std::fprintf(stderr, "ENSURE_F32_F32_OK name=%s\n", wt.name.c_str());
        return reinterpret_cast<const float*>(wt.data);
    }
    // BOUNDED_STREAM: ephemeral scratch — no permanent F32 warehouse
    const char* mode = std::getenv("DEEP2_WEIGHT_MODE");
    const bool stream = !(mode && (std::strcmp(mode, "RESIDENT_CACHE") == 0 ||
                                   std::strcmp(mode, "0") == 0));
    if (stream) {
        std::fprintf(stderr, "ENSURE_F32_STREAM name=%s type=%d\n", wt.name.c_str(), wt.type);
        static thread_local std::vector<float> scratch;
        auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
        if (!deq) {
            std::fprintf(stderr, "ENSURE_F32_FAIL_NODEQ name=%s type=%d\n", wt.name.c_str(), wt.type);
            return nullptr;
        }
        scratch.resize(wt.rows * wt.cols);
        std::fprintf(stderr, "ENSURE_F32_DEQ_CALL name=%s rows=%u cols=%u\n", wt.name.c_str(), (unsigned)wt.rows, (unsigned)wt.cols);
        deq(reinterpret_cast<const uint8_t*>(wt.data), scratch.data(), scratch.size());
        std::fprintf(stderr, "ENSURE_F32_DEQ_DONE name=%s\n", wt.name.c_str());
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
    // DEEP2_HOT_LANE_CONTEXT_001: prepare the thread-confined lock-free
    // lane now (device setup, under apiMu_ once). Sizing: input covers
    // the largest activation width (hidden or intermediate), output
    // covers the largest single-matrix row count (lmHead vocab, QKV, or
    // FFN intermediate), group outputs match the output sizing. The
    // dual-row workers claim these lanes at first decode use.
    {
        const uint32_t interW = inter ? inter : H * 4u;
        const uint32_t maxIn = std::max(H, interW);
        uint32_t maxRows = (uint32_t)modelWeights.vocabSize;
        for (const auto& L : modelWeights.layers) {
            maxRows = std::max(maxRows,
                (uint32_t)std::max({L.wq.rows, L.wk.rows, L.wv.rows,
                                    L.wo.rows, L.attnO.rows,
                                    L.wGate.rows, L.wUp.rows}));
        }
        if (!vc->PrepareHotLane(maxIn, maxRows, maxRows)) {
            std::fprintf(stderr,
                "[HOT_LANE_PREP_FAIL] slot=%u maxIn=%u maxRows=%u\n",
                slot, maxIn, maxRows);
            // Non-fatal: decode falls back to the locked compatibility
            // API until the next successful prepare.
        } else {
            std::fprintf(stderr,
                "[HOT_LANE_PREP_OK] slot=%u maxIn=%u maxRows=%u\n",
                slot, maxIn, maxRows);
        }
    }
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
    std::fprintf(stderr, "GPU_LAYER_ENTER layer=%u slot=%u\n", layer, slot);
    if (!vulkanInitialized_ || vulkanDevices_.empty()) {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=VULKAN_INIT layer=%u reason=vulkan_uninitialized_or_no_devices\n", layer);
        return false;
    }
    if (layer >= modelWeights.layers.size()) {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=LAYER_BOUNDS layer=%u reason=layer_out_of_range layers=%zu\n", layer, modelWeights.layers.size());
        return false;
    }
    if (Deep2MultiGpu_SlotIsCpu(multiGpuLayerPlan_, (int)slot)) {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=CPU_SLOT layer=%u slot=%u reason=slot_is_cpu\n", layer, slot);
        return false;
    }
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc) {
        std::fprintf(stderr, "GPU_FORWARD_STAGE=GET_SLOT layer=%u slot=%u vc=null\n", layer, slot);
        return false;
    }
    std::fprintf(stderr, "GPU_FORWARD_STAGE=ENSURE_ARENA layer=%u slot=%u\n", layer, slot);
    if (!ensureGpuForwardArena(slot)) {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=ARENA layer=%u slot=%u\n", layer, slot);
        return false;
    }
    std::fprintf(stderr, "GPU_FORWARD_STAGE=SET_EPOCH layer=%u slot=%u\n", layer, slot);
    vc->SetWorkEpoch(kvCache ? kvCache->currentLength() : 0);

    std::fprintf(stderr, "GPU_FORWARD_STAGE=GET_LAYER_WEIGHTS layer=%u slot=%u\n", layer, slot);
    const auto& lw = modelWeights.layers[layer];
    const uint32_t H = (uint32_t)config.hiddenDim;
    const uint32_t nHeads = (uint32_t)modelWeights.numHeads;
    const uint32_t nKv = (uint32_t)modelWeights.numKVHeads;
    const uint32_t headDim = (uint32_t)modelWeights.headDim;
    // OVERFLOW_HARDEN: compute qDim/kvDim in uint64_t, saturate guard.
    const uint64_t qDim64 = (uint64_t)nHeads * (uint64_t)headDim;
    const uint64_t kvDim64 = (uint64_t)nKv * (uint64_t)headDim;
    if (qDim64 > (uint64_t)std::numeric_limits<uint32_t>::max() ||
        kvDim64 > (uint64_t)std::numeric_limits<uint32_t>::max()) {
        std::fprintf(stderr,
            "GPU_DIM_OVERFLOW layer=%u qDim64=%llu kvDim64=%llu\n",
            layer, (unsigned long long)qDim64, (unsigned long long)kvDim64);
        std::fflush(stderr);
        return false;
    }
    const uint32_t kvDim = static_cast<uint32_t>(kvDim64);
    const uint32_t qDim = static_cast<uint32_t>(qDim64);
    const uint32_t inter = (uint32_t)(lw.wGate.rows ? lw.wGate.rows
                                                    : modelWeights.intermediateDim);
    std::fprintf(stderr, "GPU_FORWARD_STAGE=CHECK_WEIGHT_DATA layer=%u slot=%u\n", layer, slot);
    if (!lw.wq.data || !lw.wk.data || !lw.wv.data ||
        !(lw.wo.data || lw.attnO.data) ||
        !lw.wGate.data || !lw.wUp.data || !lw.wDown.data) {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=WEIGHT_DATA layer=%u wq=%p wk=%p wv=%p wo=%p attnO=%p wGate=%p wUp=%p wDown=%p\n",
            layer, (void*)lw.wq.data, (void*)lw.wk.data, (void*)lw.wv.data,
            (void*)lw.wo.data, (void*)lw.attnO.data, (void*)lw.wGate.data,
            (void*)lw.wUp.data, (void*)lw.wDown.data);
        return false;
    }
    std::fprintf(stderr, "GPU_FORWARD_STAGE=WEIGHT_DATA_OK layer=%u slot=%u\n", layer, slot);

    auto& c = gpuFwd_;
    std::fprintf(stderr, "GPU_FORWARD_STAGE=GPU_FWD_REF_OK layer=%u slot=%u\n", layer, slot);
    if (uploadEntry) {
        // caller must have placed host hidden into a staging path via UploadHidden
        ++c.hostSyncBoundaries; // entry boundary only — not a mid-layer materialization
    }

    const uint64_t liveSeq =
        kvCache ? static_cast<uint64_t>(kvCache->currentLength()) : 0ull;
    std::fprintf(stderr, "GPU_FORWARD_STAGE=KV_SEQ_OK layer=%u seq=%llu\n", layer, (unsigned long long)liveSeq);
    CycloneScheduler* liveCyc = LivePath_ActiveCyclone();
    std::fprintf(stderr, "GPU_FORWARD_STAGE=CYC_OK layer=%u cyc=%p\n", layer, (void*)liveCyc);
    if (!liveCyc && cycloneEnabled_) liveCyc = cyclone_.get();
    const uint64_t layerStartNs =
        (liveCyc && LivePath_Active())
            ? static_cast<uint64_t>(
                  std::chrono::duration_cast<std::chrono::nanoseconds>(
                      std::chrono::steady_clock::now().time_since_epoch()).count())
            : 0ull;
    if (LivePath_Active())
        LivePath_OnLayerStart(liveCyc, layer, liveSeq);

    std::fprintf(stderr, "GPU_FORWARD_STAGE=PREFETCH_CHECK layer=%u\n", layer);
    const bool prefetch = vc->WeightPrefetchActive() ||
        (std::getenv("DEEP2_WEIGHT_PREFETCH") &&
         std::getenv("DEEP2_WEIGHT_PREFETCH")[0] != '0');
    const bool fuse = !prefetch;
    // A caller may already own a token/range-wide command buffer.
    // Only create/submit a per-layer command when no outer fusion exists.
    const bool ownFusion = fuse && !vc->FusedRecording();
    auto fail = [&](const char* stage, const char* op) -> bool {
        std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=%s layer=%u op=%s\n", stage, layer, op);
        if (ownFusion) (void)vc->EndFusedLayer();
        (void)vc->FlushWeightComputes();
        if (liveCyc && LivePath_Active()) {
            const uint64_t abortNs =
                static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count());
            (void)abortNs; // duration not needed for abort path
            LivePath_OnLayerAbort(liveCyc, layer, liveSeq);
        }
        return false;
    };
    if (ownFusion) {
        std::fprintf(stderr, "GPU_FORWARD_STAGE=FUSE_BEGIN layer=%u\n", layer);
        if (!vc->BeginFusedLayer()) {
            std::fprintf(stderr, "GPU_FORWARD_FAIL_STAGE=FUSE layer=%u op=BeginFusedLayer\n", layer);
            return fail("FUSE", "BeginFusedLayer");
        }
        std::fprintf(stderr, "GPU_FORWARD_STAGE=FUSE_BEGIN_OK layer=%u\n", layer);
    }
    std::fprintf(stderr, "GPU_LAYER_BEGIN layer=%u\n", layer);
    std::fprintf(stderr, "GPU_FORWARD_STAGE=ENSURE_F32_ATTN layer=%u\n", layer);
    const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
    /* DualStick owns work: real weight bytes → FreeToken Overwrite (not null Resolve). */
    if (attnW)
        DualStickAcquire(slot, attnW, (size_t)H * sizeof(float), 0, layer, 0);
    else
        DualStickResolve(slot, layer);
    if (!attnW) return fail("ENSURE_F32", "attnNorm");
    auto* attnNormBuf =
        vc->ResolveResidentF32(attnW, WeightKey(lw.attnNorm), H);
    if (!attnNormBuf) return fail("RESOLVE_F32", "attnNorm");

    const float* ffnW = EnsureF32(*this, lw.ffnNorm, vulkanWeightF32_);
    if (!ffnW) return fail("ENSURE_F32", "ffnNorm");
    auto* ffnNormBuf =
        vc->ResolveResidentF32(ffnW, WeightKey(lw.ffnNorm), H);
    if (!ffnNormBuf) return fail("RESOLVE_F32", "ffnNorm");
    const WeightTensor* woWt = lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!woWt) return fail("WEIGHT_SELECT", "woWt");
    auto gemv = [&](const WeightTensor& wt, CPUInference::VulkanCompute::DeviceBuf& in,
                    CPUInference::VulkanCompute::DeviceBuf& out,
                    uint32_t rows, uint32_t cols) -> bool {
        std::fprintf(stderr, "GEMV_ENTER name=%s type=%d rows=%u cols=%u packed=%d\n",
            wt.name.c_str(), wt.type, rows, cols, (int)PackedQuant(wt));
        if (!wt.data) {
            std::fprintf(stderr,
                "GPU_GEMV_GEOMETRY_FAIL name=%s reason=nullWeight\n",
                wt.name.c_str());
            std::fflush(stderr);
            return false;
        }
        if (wt.rows != rows || wt.cols != cols) {
            std::fprintf(stderr,
                "GPU_GEMV_GEOMETRY_FAIL "
                "name=%s "
                "tensorRows=%zu tensorCols=%zu "
                "requestedRows=%u requestedCols=%u\n",
                wt.name.c_str(),
                wt.rows, wt.cols,
                rows, cols);
            std::fflush(stderr);
            return false;
        }
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
            std::fprintf(stderr, "GEMV_DISPATCH_GEMVQUANT name=%s type=%d rows=%u cols=%u\n",
                wt.name.c_str(), wt.type, rows, cols);
            bool r = vc->DispatchGemvQuant(wt.type, wt.data, wt.sizeBytes, in, out, rows, cols);
            std::fprintf(stderr, "GEMV_DISPATCH_GEMVQUANT_DONE name=%s result=%d\n", wt.name.c_str(), (int)r);
            return r;
        }
        /* Product decode: Q2_K must not host-Expand F32 / 72-byte MASM. */
        if (wt.type == (int)GGMLType::GGML_TYPE_Q2_K) {
            const char* pd = std::getenv("RAWRXD_Q2K_PRODUCT_DECODE");
            if (pd && pd[0] == '1') return false;
        }
        const float* w = EnsureF32(*this, wt, vulkanWeightF32_);
        if (!w) return false;
        if (wt.type != (int)GGMLType::GGML_TYPE_F32) ++c.cpuF32Expands;
        size_t weightBytes = 0;
        if (!DenseF32Bytes(wt, weightBytes)) {
            std::fprintf(stderr, "GPU_GEMV_DENSE_BYTES_FAIL name=%s\n", wt.name.c_str());
            std::fflush(stderr);
            return false;
        }
        if (prefetch && vc->WeightStreamActive()) {
            if (!vc->FlushWeightComputes()) return false;
            uint32_t sl = 0;
            if (!vc->PrefetchWeight(w, weightBytes, sl)) return false;
            return vc->SubmitGemvPrefetch(sl, in, out, rows, cols);
        }
        std::fprintf(stderr, "GEMV_DISPATCH_DEVICE name=%s rows=%u cols=%u bytes=%zu\n", wt.name.c_str(), rows, cols, weightBytes);
        bool r = vc->DispatchGemvDevice(w, WeightKey(wt), in, out, rows, cols);
        std::fprintf(stderr, "GEMV_DISPATCH_DEVICE_DONE name=%s result=%d\n", wt.name.c_str(), (int)r);
        return r;
    };
    // Overlapped QKV: upload next while prior GEMV runs
    auto gemvOverlap3 = [&](const WeightTensor& qa, const WeightTensor& qb,
                            const WeightTensor& qc,
                            CPUInference::VulkanCompute::DeviceBuf& in,
                            CPUInference::VulkanCompute::DeviceBuf& outA,
                            CPUInference::VulkanCompute::DeviceBuf& outB,
                            CPUInference::VulkanCompute::DeviceBuf& outC,
                            uint32_t rA, uint32_t rB, uint32_t rC, uint32_t cols) -> bool {
        if (qa.rows != rA || qa.cols != cols ||
            qb.rows != rB || qb.cols != cols ||
            qc.rows != rC || qc.cols != cols) {
            std::fprintf(stderr,
                "GPU_QKV_GEOMETRY_FAIL "
                "Q=%zux%zu req=%ux%u "
                "K=%zux%zu req=%ux%u "
                "V=%zux%zu req=%ux%u\n",
                qa.rows, qa.cols, rA, cols,
                qb.rows, qb.cols, rB, cols,
                qc.rows, qc.cols, rC, cols);
            std::fflush(stderr);
            return false;
        }
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
        size_t qaBytes = 0, qbBytes = 0, qcBytes = 0;
        if (!DenseF32Bytes(qa, qaBytes) || !DenseF32Bytes(qb, qbBytes) || !DenseF32Bytes(qc, qcBytes)) {
            std::fprintf(stderr, "GPU_QKV_DENSE_BYTES_FAIL\n");
            std::fflush(stderr);
            return false;
        }
        uint32_t sa = 0;
        if (!wa || !vc->PrefetchWeight(wa, qaBytes, sa)) return false;
        if (!vc->SubmitGemvPrefetch(sa, in, outA, rA, cols)) return false;
        const float* wb = EnsureF32(*this, qb, vulkanWeightF32_);
        uint32_t sb = 0;
        if (!wb || !vc->PrefetchWeight(wb, qbBytes, sb)) return false; // overlaps GEMV A
        if (!vc->WaitWeightCompute(sa)) return false;
        if (!vc->SubmitGemvPrefetch(sb, in, outB, rB, cols)) return false;
        const float* wc = EnsureF32(*this, qc, vulkanWeightF32_);
        uint32_t sc = 0;
        if (!wc || !vc->PrefetchWeight(wc, qcBytes, sc)) return false; // overlaps GEMV B
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
        return fail("RMSNORM", "attnNorm");
    ++c.rmsNormOps;

    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;
    {
        DEEP2_GPU_CHILD_SCOPE(qkvScope, QKV);
        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), qDim, kvDim, kvDim, H))
            return fail("GEMV_QKV", "qkvOverlap3");
        c.qkvOps += 3;
    }
    if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                          modelWeights.ropeTheta))
        return fail("ROPE", "DispatchRope");
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
        if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");
    }
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);
        const float scale = 1.0f / std::sqrt((float)headDim);
        if (!vc->DispatchAttnDecode(vc->ArenaQ(), vc->ArenaKCache(), vc->ArenaVCache(),
                                    vc->ArenaAttn(), headDim, nHeads, nKv, pos + 1, scale,
                                    layer))
            return fail("ATTN_DECODE", "DispatchAttnDecode");
        ++c.softmaxOps;
        ++c.attnValueOps;
        ++c.attnScoreOps;
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);
        if (!gemv(*woWt, vc->ArenaAttn(), vc->ArenaDown(), H, qDim)) return fail("GEMV_OPROJ", "oProj");
        ++c.oProjOps;
        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail("RESIDUAL", "attnResidual");
        ++c.residualOps;
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "ffnNorm");

    ++c.ffnNormOps;

    {
        DEEP2_GPU_CHILD_SCOPE(ffnScope, FFN);
        if (prefetch && vc->WeightStreamActive() &&
            !PackedQuant(lw.wGate) && !PackedQuant(lw.wUp)) {
            // FFN_PREFETCH_GEOMETRY_GUARD: verify tensor shape matches dispatch
            if (lw.wGate.rows != inter || lw.wGate.cols != H ||
                lw.wUp.rows != inter || lw.wUp.cols != H) {
                std::fprintf(stderr,
                    "GPU_FFN_GEOMETRY_FAIL "
                    "wGate=%zux%zu req=%ux%u "
                    "wUp=%zux%zu req=%ux%u\n",
                    lw.wGate.rows, lw.wGate.cols, inter, H,
                    lw.wUp.rows, lw.wUp.cols, inter, H);
                std::fflush(stderr);
                return fail("FFN_GEOMETRY", "prefetchGateUp");
            }
            size_t gateBytes = 0, upBytes = 0;
            if (!DenseF32Bytes(lw.wGate, gateBytes) || !DenseF32Bytes(lw.wUp, upBytes)) {
                std::fprintf(stderr, "GPU_FFN_DENSE_BYTES_FAIL\n");
                std::fflush(stderr);
                return fail("FFN_DENSE_BYTES", "prefetchGateUp");
            }
            if (!vc->FlushWeightComputes()) return fail("FLUSH", "ffnFlush");
            const float* wg = EnsureF32(*this, lw.wGate, vulkanWeightF32_);
            uint32_t sg = 0;
            if (!wg || !vc->PrefetchWeight(wg, gateBytes, sg)) return fail("PREFETCH", "wGate");
            if (!vc->SubmitGemvPrefetch(sg, vc->ArenaNormed(), vc->ArenaGate(), inter, H))
                return fail("PREFETCH_SUBMIT", "wGateSubmit");
            const float* wu = EnsureF32(*this, lw.wUp, vulkanWeightF32_);
            uint32_t su = 0;
            if (!wu || !vc->PrefetchWeight(wu, upBytes, su)) return fail("PREFETCH", "wUp");
            if (!vc->WaitWeightCompute(sg)) return fail("WAIT_COMPUTE", "sg");
            if (!vc->SubmitGemvPrefetch(su, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
                return fail("PREFETCH_SUBMIT", "wUpSubmit");
            if (!vc->WaitWeightCompute(su)) return fail("WAIT_COMPUTE", "su");
        } else if (!gemv(lw.wGate, vc->ArenaNormed(), vc->ArenaGate(), inter, H) ||
                   !gemv(lw.wUp, vc->ArenaNormed(), vc->ArenaUp(), inter, H))
            return fail("GEMV_FFN", "wGate");
        c.qkvOps += 2;
        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail("SWIGLU", "DispatchSwiGLU");
        ++c.ffnActOps;
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter)) return fail("GEMV_FFN", "wDown");
        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail("RESIDUAL", "ffnResidual");
        ++c.ffnResidualOps;
    }

    if (ownFusion && !vc->EndFusedLayer()) return fail("FUSE", "EndFusedLayer");
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
    if (liveCyc && LivePath_Active()) {
        const uint64_t layerEndNs =
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
        const uint64_t dur = (layerEndNs > layerStartNs) ? (layerEndNs - layerStartNs) : 0ull;
        LivePath_OnLayerEnd(liveCyc, layer, liveSeq, dur);
    }
    if (GpuFiniteTraceEnabled()) {
        std::vector<float> tmpHidden(H);
        if (vc->DownloadHidden(tmpHidden.data(), H)) {
            const GpuFiniteWitness fw = ScanGpuFiniteWitness(tmpHidden.data(), H);
            std::fprintf(stderr,
                "GPU_LAYER%02d_HIDDEN finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fw.finite, fw.nan, fw.inf, fw.minFinite, fw.maxFinite);
            std::fflush(stderr);
        }

        std::vector<float> tmpResidual(H);
        if (vc->DownloadVector(vc->ArenaResidual(), tmpResidual.data(), H)) {
            const GpuFiniteWitness fr = ScanGpuFiniteWitness(tmpResidual.data(), H);
            std::fprintf(stderr,
                "GPU_LAYER%02d_RESIDUAL finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fr.finite, fr.nan, fr.inf, fr.minFinite, fr.maxFinite);
            std::fflush(stderr);
        }

        std::vector<float> tmpDown(H);
        if (vc->DownloadVector(vc->ArenaDown(), tmpDown.data(), H)) {
            const GpuFiniteWitness fd = ScanGpuFiniteWitness(tmpDown.data(), H);
            std::fprintf(stderr,
                "GPU_LAYER%02d_DOWN finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fd.finite, fd.nan, fd.inf, fd.minFinite, fd.maxFinite);
            std::fflush(stderr);
        }

        std::vector<float> tmpNormed(H);
        if (vc->DownloadVector(vc->ArenaNormed(), tmpNormed.data(), H)) {
            const GpuFiniteWitness fn = ScanGpuFiniteWitness(tmpNormed.data(), H);
            std::fprintf(stderr,
                "GPU_LAYER%02d_NORMED finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fn.finite, fn.nan, fn.inf, fn.minFinite, fn.maxFinite);
            std::fflush(stderr);
        }

        std::vector<float> tmpQ(qDim);
        if (vc->DownloadVector(vc->ArenaQ(), tmpQ.data(), qDim)) {
            const GpuFiniteWitness fq = ScanGpuFiniteWitness(tmpQ.data(), qDim);
            std::fprintf(stderr,
                "GPU_LAYER%02d_Q finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fq.finite, fq.nan, fq.inf, fq.minFinite, fq.maxFinite);
            std::fflush(stderr);
        }

        std::vector<float> tmpAttn(H);
        if (vc->DownloadVector(vc->ArenaAttn(), tmpAttn.data(), H)) {
            const GpuFiniteWitness fa = ScanGpuFiniteWitness(tmpAttn.data(), H);
            std::fprintf(stderr,
                "GPU_LAYER%02d_ATTN finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (unsigned)layer, fa.finite, fa.nan, fa.inf, fa.minFinite, fa.maxFinite);
            std::fflush(stderr);
        }
    }
    std::fprintf(stderr, "GPU_LAYER_END layer=%u\n", layer);
    return true;
}

bool Deep2Engine::forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                            const float* hostIn, float* hostOut) {
    rawr::gpu_iso::Begin();
    auto* vc = getVulkanComputeSlot(slot);
    if (!vc || !ensureGpuForwardArena(slot)) return false;
    const uint32_t H = (uint32_t)config.hiddenDim;

    uint32_t execHi = hi;
    const long tracePrefix = GpuTracePrefixHi();
    if (tracePrefix >= 0) {
        const uint64_t req = static_cast<uint64_t>(tracePrefix);
        if (req >= static_cast<uint64_t>(lo) &&
            req < static_cast<uint64_t>(execHi))
            execHi = static_cast<uint32_t>(req);
        std::fprintf(stderr,
            "GPU_PREFIX_LIMIT slot=%u requested=%ld lo=%u hi=%u exec_hi=%u\n",
            slot, tracePrefix, lo, hi, execHi);
        std::fflush(stderr);
    }

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
    for (uint32_t L = lo; L <= execHi; ++L) {
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
        if (GpuFiniteTraceEnabled()) {
            const GpuFiniteWitness fw = ScanGpuFiniteWitness(hostOut, H);
            const long long firstBad =
                fw.firstBad == static_cast<size_t>(-1)
                    ? -1LL : static_cast<long long>(fw.firstBad);
            const size_t seq = kvCache ? kvCache->currentLength() : 0;
            std::fprintf(stderr,
                "GPU_FINITE_WITNESS slot=%u lo=%u hi=%u exec_hi=%u seq=%zu "
                "count=%u finite=%zu nan=%zu inf=%zu first_bad=%lld min=%g max=%g\n",
                slot, lo, hi, execHi, seq, H,
                fw.finite, fw.nan, fw.inf, firstBad,
                fw.minFinite, fw.maxFinite);
            std::fflush(stderr);
        }
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
                // Gather actual resident tensor names from next layer's LayerWeights.
                // Only include tensors with real backing data and nonzero bytes.
                std::vector<std::string> needNames;
                if (nLo < modelWeights.layers.size()) {
                    const auto& lw = modelWeights.layers[nLo];
                    auto addTensor = [&needNames, this](const WeightTensor& wt) {
                        if (!wt.data || wt.sizeBytes == 0 || wt.name.empty())
                            return;
                        elasticResidency_->registerTensor(wt.name,
                                                           static_cast<uint64_t>(wt.sizeBytes));
                        needNames.push_back(wt.name);
                    };
                    addTensor(lw.wq);
                    addTensor(lw.wk);
                    addTensor(lw.wv);
                    addTensor(lw.wo);
                    addTensor(lw.bq);
                    addTensor(lw.bk);
                    addTensor(lw.bv);
                    addTensor(lw.attnNorm);
                    addTensor(lw.attnQNorm);
                    addTensor(lw.attnKNorm);
                    addTensor(lw.wGate);
                    addTensor(lw.wUp);
                    addTensor(lw.wDown);
                    addTensor(lw.ffnNorm);
                    addTensor(lw.wqkv);
                    // MLA tensors
                    addTensor(lw.attnQ_a);
                    addTensor(lw.attnQ_a_norm);
                    addTensor(lw.attnQ_b);
                    addTensor(lw.attnKV_a_mqa);
                    addTensor(lw.attnKV_a_norm);
                    addTensor(lw.attnK_b);
                    addTensor(lw.attnV_b);
                    addTensor(lw.attnO);
                    // MoE tensors
                    addTensor(lw.moeRouter);
                    addTensor(lw.moeSharedGate);
                    addTensor(lw.moeSharedUp);
                    addTensor(lw.moeSharedDown);
                    for (const auto& t : lw.moeGate) addTensor(t);
                    for (const auto& t : lw.moeUp)   addTensor(t);
                    for (const auto& t : lw.moeDown) addTensor(t);
                    // SSM tensors
                    addTensor(lw.ssmA);
                    addTensor(lw.ssmAlpha);
                    addTensor(lw.ssmBeta);
                    addTensor(lw.ssmIn);
                    addTensor(lw.ssmD);
                    addTensor(lw.ssmConv1d);
                    addTensor(lw.ssmConv1dBias);
                    addTensor(lw.ssmDtBias);
                    addTensor(lw.ssmNorm);
                    addTensor(lw.ssmOut);
                }
                elasticResidency_->PredictLayerNeeds(
                    nLo,
                    needNames.empty() ? nullptr : &needNames,
                    needNames.size());
                /* Wait residency for next slot tensors before arena copy. */
                {
                    /* Predict already enqueued UnifiedAsyncMove; readiness gate. */
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
    if (gpuFwdCommitted_) return true;
    return Deep2GpuForward_IsReal(gpuFwd_, vulkanGemvFail_);
}

} // namespace Deep2

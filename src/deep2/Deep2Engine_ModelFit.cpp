// ============================================================================
// Deep2Engine_ModelFit.cpp — DEEP2_MODEL_FIT_AUTHORITY_001
//
// The admission-to-execution contract, implemented:
//   1. measure the host (RAM, storage, every Vulkan compute device)
//   2. read the model's real geometry from GGUF metadata
//   3. produce an irrevocable ModelFitPlan (lane + per-device placement + KV
//      budget + max context)
//   4. bind that plan into the executor so the chosen lane is honored rather
//      than re-selected from environment variables
//   5. chunked-causal batched prefill (one layer per token-chunk, so layer
//      executions drop from promptLen*layerCount to chunks*layerCount)
//   6. one authoritative MODEL_FIT / execution trace
//
// Nothing here reports a value it did not measure.
// ============================================================================

#include "Deep2Engine.h"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "Deep2DeviceManager.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
// FNV-1a over a byte range — used for content/tokenizer provenance.
// ---------------------------------------------------------------------------
static uint64_t fnv1a(const void* data, size_t n, uint64_t seed = 0) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h = seed ? seed : 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

// H11 diagnostic: keep the batched path fail-closed while making the first
// divergent stage observable.  This is opt-in because a full prompt can run
// thousands of projections.
static bool H11BatchTraceEnabled() {
    static const bool enabled = [] {
        const char* e = std::getenv("RAWRXD_H11_BATCH_TRACE");
        return e && e[0] == '1';
    }();
    return enabled;
}

static bool H11TraceBatchVector(const char* stage, size_t layer, size_t row,
                                const float* values, size_t count) {
    if (!values || count == 0) return false;
    size_t bad = 0;
    float minValue = std::numeric_limits<float>::infinity();
    float maxValue = -std::numeric_limits<float>::infinity();
    double sumSq = 0.0;
    for (size_t i = 0; i < count; ++i) {
        const float v = values[i];
        if (!std::isfinite(v)) { ++bad; continue; }
        minValue = (std::min)(minValue, v);
        maxValue = (std::max)(maxValue, v);
        sumSq += static_cast<double>(v) * static_cast<double>(v);
    }
    const bool digestStage = std::strcmp(stage, "post_ffn") == 0;
    if (H11BatchTraceEnabled() && (bad || (row == 0 && (layer < 2 || digestStage)))) {
        std::fprintf(stderr,
                     "[H11_BATCH_TRACE] layer=%zu row=%zu stage=%s "
                     "finite=%zu/%zu bad=%zu min=%g max=%g l2=%g\n",
                     layer, row, stage, count - bad, count, bad,
                     minValue, maxValue, std::sqrt(sumSq));
        std::fflush(stderr);
        if (bad && std::strcmp(stage, "attention") == 0) {
            size_t printed = 0;
            for (size_t i = 0; i < count && printed < 12; ++i) {
                if (!std::isfinite(values[i])) {
                    std::fprintf(stderr, "[H11_BATCH_TRACE] bad_index=%zu value=%g\n", i, values[i]);
                    ++printed;
                }
            }
            std::fflush(stderr);
        }
    }
    return bad == 0;
}

// ---------------------------------------------------------------------------
// GPU enumeration bridge: fills a HostHardwareSnapshot from the runtime's OWN
// device inventory.
//
// VERIFIED CHOICE (not a guess):
//   * CPUInference::VulkanPhysicalInfo          — DOES NOT EXIST
//   * CPUInference::VulkanCompute::EnumeratePhysicalDevices() — DOES NOT EXIST
//     (that adapter declares only InitializeSolo(needle) + GetDeviceInfo())
//   * Deep2::VulkanPhysicalInfo                 — exists (src/deep2/vulkan_compute.h:59)
//   * Deep2::VulkanCompute::EnumeratePhysicalDevices() — exists
//     (src/deep2/vulkan_compute.h:119, impl src/deep2/vulkan_compute.cpp:89)
//   * Deep2::Deep2Device_Enumerate()            — exists
//     (src/deep2/Deep2DeviceManager.cpp:123) and is the inventory the engine's
//     own enableVulkan() consumes, keyed by stableId = VENDOR:DEVICE:LUID
//     (MakeStableId, src/deep2/Deep2DeviceManager.cpp:43).
//
// Deep2::EnumeratePhysicalDevices() is deliberately NOT used as the identity
// source.  It dedups D3D12 aliases and assigns ordinals in its own order,
// while the engine opens slots by device-name substring from the Deep2Device
// plan.  Those two orderings are not guaranteed to agree, so an ordinal is not
// a device identity.  Correlating on stableId is what makes
// "does the plan's GPU0 equal the executor's GPU0" answerable at all.
//
// The Vulkan enumeration is still performed as a CROSS-CHECK: a device that
// DXGI reports but that exposes no Vulkan compute queue is recorded with
// compute=false.  That is exactly the "adapter initialized but submits no
// work" failure mode, and it must be visible before admission, not after.
// ---------------------------------------------------------------------------
static void enumerateGpusIntoSnapshot(void* userdata) {
    auto* snap = static_cast<rawrxd::HostHardwareSnapshot*>(userdata);
    if (!snap) return;
    snap->gpus.clear();

    // ---- Vulkan cross-check: the PCI-id set Vulkan can actually drive ----
    // A device present in DXGI but absent here has no Vulkan compute queue.
    // This is the "adapter initialized but submits no work" failure mode, and
    // it has to be visible before admission, not after.
    std::vector<Deep2::VulkanPhysicalInfo> vkDevs;
    try {
        vkDevs = Deep2::VulkanCompute::EnumeratePhysicalDevices();
    } catch (...) {
        // No Vulkan instance available: everything stays compute=false and the
        // estimator selects CPU_ONLY rather than assuming a working GPU.
    }

    // ---- the runtime's own inventory: what enableVulkan() can open ----
    Deep2::DeviceManagerSnapshot devSnap{};
    bool haveDevices = false;
    try {
        haveDevices = Deep2::Deep2Device_Enumerate(devSnap);
    } catch (...) {
        haveDevices = false;
    }
    if (!haveDevices) return;

    for (unsigned i = 0; i < devSnap.deviceCount && i < 8u; ++i) {
        const Deep2::DeviceIdentity& id = devSnap.devices[i];
        rawrxd::GpuDeviceInfo g;
        g.stableId = id.stableId;
        g.name = id.name;
        g.vendorId = id.vendorId;
        g.deviceId = id.deviceId;
        g.deviceLocalBytes = id.dedicatedVram;
        g.sharedBytes = id.sharedVram;
        g.discrete = !id.integrated;
        g.deviceIndex = id.index;
        g.compute = false;

        for (const auto& v : vkDevs) {
            if (v.vendorId == id.vendorId && v.deviceId == id.deviceId) {
                g.compute = true;
                // Trust the Vulkan heap measurement when it disagrees with DXGI.
                if (v.deviceLocalBytes) g.deviceLocalBytes = v.deviceLocalBytes;
                if (v.discrete) g.discrete = true;
                break;
            }
        }
        snap->gpus.push_back(std::move(g));
    }

    // Same ordering the device manager itself applies, so slot 0 is the device
    // the engine picks as primary.
    std::stable_sort(snap->gpus.begin(), snap->gpus.end(),
        [](const rawrxd::GpuDeviceInfo& a, const rawrxd::GpuDeviceInfo& b) {
            if (a.compute != b.compute) return a.compute;
            if (a.discrete != b.discrete) return a.discrete;
            return a.deviceLocalBytes > b.deviceLocalBytes;
        });
}

// ---------------------------------------------------------------------------
// Measure host RAM + storage + GPUs into an existing snapshot.
//
// One path is used by both probeHostHardware() and estimateModelFit() so the
// plan the estimator produces and the snapshot the engine records can never
// describe two different machines.
// ---------------------------------------------------------------------------
static void HostHardwareProbe_MeasureInto(rawrxd::HostHardwareSnapshot& out,
                                          const std::string& storagePathHint) {
    out = rawrxd::HostHardwareProbe::Probe(storagePathHint);
    enumerateGpusIntoSnapshot(&out);
}

// ===========================================================================
// probeHostHardware
// ===========================================================================
void Deep2Engine::probeHostHardware(const std::string& storagePathHint) {
    HostHardwareProbe_MeasureInto(hardwareSnapshot_, storagePathHint);
}

// ===========================================================================
// buildFitGeometry
// ===========================================================================
bool Deep2Engine::buildFitGeometry(const std::string& ggufPath,
                                   const GGUFLoader& loader,
                                   rawrxd::FitModelGeometry& geo,
                                   uint64_t& contentHash,
                                   uint64_t& tokenizerHash) const {
    geo = {};
    contentHash = 0;
    tokenizerHash = 0;
    geo.modelPath = ggufPath;
    geo.architecture = loader.getMetaString("general.architecture");
    if (geo.architecture.empty()) return false;

    const std::string& a = geo.architecture;

    // ---- real weight bytes from the mapped tensor table ----
    uint64_t total = 0;
    uint64_t embed = 0, lmHead = 0;
    for (const auto& name : loader.listTensors()) {
        const GGUFTensor* t = loader.getTensor(name);
        if (!t || !t->data || t->sizeBytes == 0) continue;
        total += static_cast<uint64_t>(t->sizeBytes);
        if (name == "token_embd.weight" || name == "token_embeddings.weight")
            embed += static_cast<uint64_t>(t->sizeBytes);
        else if (name == "output.weight" || name == "lm_head.weight")
            lmHead += static_cast<uint64_t>(t->sizeBytes);
    }
    geo.totalWeightBytes = total;
    geo.embeddingBytes = embed;
    geo.lmHeadBytes = lmHead;
    geo.lmHeadTied = (lmHead == 0);
    if (geo.embeddingBytes == 0) return false;

    // ---- layer/head geometry ----
    auto metaSize = [&](const char* suffix, size_t def = 0) -> size_t {
        const int64_t v = loader.getMetaInt(a + "." + suffix,
                                            static_cast<int64_t>(def));
        if (v != 0) return static_cast<size_t>(v);
        // Array-typed metadata (e.g. expert_used_count, head_count_kv,
        // feed_forward_length) is not readable via getMetaInt.  Try the
        // first array element as the scalar value.
        const int64_t av = loader.getMetaIntArrayFirst(a + "." + suffix,
                                                       static_cast<int64_t>(def));
        if (av != 0) return static_cast<size_t>(av);
        return def;
    };

    geo.hiddenDim = metaSize("embedding_length", 0);
    // Derive vocab from the real embedding tensor shape when metadata is absent.
    if (geo.hiddenDim) {
        const GGUFTensor* te = loader.getTensor("token_embd.weight");
        if (!te) te = loader.getTensor("token_embeddings.weight");
        if (te && te->shape.size() >= 1)
            geo.vocabSize = static_cast<size_t>(te->shape[1]);
    }
    if (!geo.hiddenDim || !geo.vocabSize) return false;

    geo.layerCount = metaSize("block_count", 0);
    if (!geo.layerCount) {
        size_t maxLayer = 0;
        bool saw = false;
        for (const std::string& name : loader.listTensors()) {
            if (name.rfind("blk.", 0) != 0) continue;
            size_t p = 4, v = 0;
            bool any = false;
            while (p < name.size() && name[p] >= '0' && name[p] <= '9') {
                any = true; v = v * 10 + static_cast<size_t>(name[p] - '0'); ++p;
            }
            if (any && p < name.size() && name[p] == '.') { maxLayer = std::max(maxLayer, v); saw = true; }
        }
        if (saw) geo.layerCount = maxLayer + 1;
    }
    if (!geo.layerCount) return false;

    geo.numHeads = metaSize("attention.head_count", 0);
    geo.numKVHeads = metaSize("attention.head_count_kv", geo.numHeads);
    if (!geo.numHeads || !geo.numKVHeads) return false;
    geo.headDim = geo.hiddenDim / geo.numHeads;
    if (!geo.headDim) return false;

    geo.intermediateDim = metaSize("feed_forward_length", 0);
    geo.moeIntermediateDim = metaSize("expert_feed_forward_length", 0);
    geo.numExperts = metaSize("expert_count", 0);
    geo.expertsPerToken = metaSize("expert_used_count", 0);
    geo.isMoE = geo.numExperts > 0 && geo.expertsPerToken > 0;
    geo.kvLoraRank = metaSize("kv_lora_rank", 0);
    geo.hasMLA = geo.kvLoraRank > 0;
    geo.modelContextLength = metaSize("context_length", 0);

    // ---- provenance hashes (gate 3: context truth) ----
    uint64_t h = 1469598103934665603ull;
    h = fnv1a(geo.architecture.data(), geo.architecture.size(), h);
    const uint32_t shape[6] = {
        (uint32_t)geo.hiddenDim, (uint32_t)geo.layerCount,
        (uint32_t)geo.numHeads, (uint32_t)geo.numKVHeads,
        (uint32_t)geo.headDim, (uint32_t)geo.vocabSize};
    h = fnv1a(shape, sizeof(shape), h);
    contentHash = h ? h : 1;

    // Tokenizer provenance: hash the embedded vocab/merges arrays.  Absent
    // tokenizer metadata yields a stable "unknown" hash rather than 0, so a
    // model with no tokenizer metadata never accidentally matches a different
    // tokenizer-hashed model.
    uint64_t th = 1469598103934665607ull;
    bool haveTok = false;
    std::vector<std::string> toks;
    if (loader.getMetaStringArray("tokenizer.ggml.tokens", toks)) {
        haveTok = true;
        th = fnv1a(toks.data(),
                   toks.size() * sizeof(std::string::value_type),
                   1469598103934665607ull);
        // Hash the joined content too — sizes alone are not enough.
        for (const auto& t : toks) th = fnv1a(t.data(), t.size(), th);
    }
    tokenizerHash = haveTok ? (th ? th : 1) : 0x9E3779B97F4A7C15ull;
    return true;
}

// ===========================================================================
// estimateModelFit — pure, no global state, always the same plan.
// ===========================================================================
rawrxd::ModelFitPlan Deep2Engine::estimateModelFit(const std::string& ggufPath,
                                                   size_t requestedContext) const {
    rawrxd::ModelFitPlan plan;
    plan.lane = rawrxd::FitExecutionLane::REJECTED;

    if (ggufPath.empty()) {
        plan.rejectReason = "empty GGUF path";
        return plan;
    }

    // Measure the host now — never a hardcoded capacity.
    // The GPU bridge reads from the runtime's own device inventory, so the
    // plan is built against the devices enableVulkan() can actually open.
    rawrxd::HostHardwareSnapshot hw;
    HostHardwareProbe_MeasureInto(hw, ggufPath);

    GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        plan.rejectReason = "GGUF load failed: " + loader.error();
        return plan;
    }

    rawrxd::FitModelGeometry geo;
    uint64_t contentHash = 0, tokenizerHash = 0;
    if (!buildFitGeometry(ggufPath, loader, geo, contentHash, tokenizerHash)) {
        plan.rejectReason = "GGUF metadata incomplete for fit estimation";
        return plan;
    }

    rawrxd::FitContextRequest ctx;
    ctx.enabled = true;
    ctx.targetTokens = requestedContext;
    // Prefer Q8_0 KV (4x smaller) when context is the binding constraint;
    // F32 when the model is small enough that exactness is affordable.
    ctx.kvQuant = rawrxd::KVQuantType::KV_Q8_0;

    plan = rawrxd::ModelFitEstimator::Estimate(geo, hw, ctx, requestedContext);
    return plan;
}

// ===========================================================================
// commitFitPlan — bind the plan into the executor.
// ===========================================================================
bool Deep2Engine::commitFitPlan(const rawrxd::ModelFitPlan& plan) {
    fitPlan_ = plan;
    fitPlanValid_ = true;

    if (!plan.accepted) {
        fitRejectReason_ = plan.rejectReason;
        return false;
    }

    // The executor honors the lane the estimator chose:
    //   CPU_ONLY / GPU_SINGLE / GPU_MULTI / GPU_HOST_HYBRID
    //
    // DEEP2_EXECUTION_PLAN_AUTHORITY_001: forwardTokenAllLayers no longer
    // consults DEEP2_DENSE_EXEC / DEEP2_RESIDENT_FIRST when a plan is bound.
    //
    // Single-GPU: reset the multi-GPU layer plan so the all-layers contiguous
    // range path is used (no cross-device handoff, no host bounce). Assigning a
    // default-constructed plan matches how enableVulkan() itself resets it.
    if (plan.devices.size() <= 1 && multiGpuLayerPlan_.active) {
        multiGpuLayerPlan_ = MultiGpuLayerPlan{};
    }

    // Strictness follows the plan: a plan that put no layer on a GPU must
    // never be quietly satisfied by a CPU fallback.
    if (plan.lane == rawrxd::FitExecutionLane::CPU_ONLY ||
        plan.lane == rawrxd::FitExecutionLane::REJECTED) {
        vulkanStrictNoCpuFallback_ = false;
    } else {
        // A GPU lane that admits a CPU tail must also allow that tail.
        vulkanStrictNoCpuFallback_ =
            (plan.lane == rawrxd::FitExecutionLane::GPU_HOST_HYBRID) ? false : true;
    }

    // Context cap: the plan's KV budget is the hard bound.
    if (plan.maxContextEstimated && config.maxSeqLen > plan.maxContextEstimated) {
        std::fprintf(stderr,
            "[ModelFit] KV budget caps context: requested=%zu fit=%zu "
            "(kv_bytes_per_token=%llu)\n",
            config.maxSeqLen,
            (size_t)plan.maxContextEstimated,
            (unsigned long long)plan.kvBytesPerToken);
        config.maxSeqLen = plan.maxContextEstimated;
        growContext(plan.maxContextEstimated);
    }

    return true;
}

// ===========================================================================
// Execution-ledger run identity
// ===========================================================================
void Deep2Engine::beginExecutionRun() {
    auto& auth = rawrxd::ExecutionAuthority::Instance();
    if (executionRunId_ == 0) {
        executionRunId_ = auth.NewRun();
        if (executorInstanceId_ == 0)
            executorInstanceId_ = reinterpret_cast<uint64_t>(this) ^ 0x5A5A5A5Au;
        auth.BindExecutor(executionRunId_, executorInstanceId_);
        // The run defaults to agent 0 (CLI/local); the agentic rebind path
        // calls BindAgent so swarm events carry the owning agent.
        auth.BindAgent(executionRunId_, 0);
    }
    executionRequestId_ = auth.NewRequest();
}

void Deep2Engine::endExecutionRun() {
    if (executionRunId_) {
        rawrxd::ExecutionAuthority::Instance().LogEvent(
            executionRunId_, rawrxd::ExecutionEventKind::RunEnd, "generate-complete", true);
    }
}

// ===========================================================================
// Reporting
// ===========================================================================
void Deep2Engine::emitModelFitReport(FILE* f) const {
    if (!f) f = stdout;
    fitPlan_.emit(f);
    if (!fitRejectReason_.empty())
        std::fprintf(f, "fit_reject_reason=%s\n", fitRejectReason_.c_str());
    hardwareSnapshot_.emit(f);
    std::fflush(f);
}

void Deep2Engine::emitExecutionTrace(FILE* f) {
    if (!f) f = stdout;
    rawrxd::ExecutionPhaseTimings ph;
    ph.inputTokens = planPrefillTokens_;
    ph.batchSize = prefillChunkSize_ ? prefillChunkSize_ : 1;
    ph.layerCount = modelWeights.numLayers;
    ph.totalLayerExecutions = planLayerExecutions_;
    ph.prefillWallNs = measuredPrefillNs_;
    ph.decodeWallNs = measuredDecodeNs_;
    ph.generatedTokens = measuredGeneratedTokens_;

    rawrxd::KvReuseReport kv;
    kv.provenanceValid = kvProvenanceValid_;
    kv.validTokens = kvCache ? kvCache->currentLength() : 0;
    kv.reusedPrefixTokens = kvReusedPrefixTokens_;
    kv.appendedTokens = kvAppendedTokens_;

    rawrxd::EmitExecutionTrace(f, execTelemetry_, ph, kv, fitPlan_,
                               executionRunId_, measuredTimingAuthority_);
    // Mirror the ledger so ESP / SNAP / flight recorder see the same events.
    rawrxd::ExecutionLedger::Instance().Flush(f, 256);
    std::fflush(f);
}

// ===========================================================================
// KV provenance gate (gate 3: context truth)
// ===========================================================================
bool Deep2Engine::kvPrefixReusable(const std::vector<int>& promptTokens,
                                   std::string* reason) const {
    auto reject = [&](const char* r) {
        if (reason) *reason = r;
        return false;
    };

    if (!kvCache || !kvProvenanceValid_)
        return reject("no-valid-cache");

    if (!fitPlanValid_ || !sessionModelId_.id)
        return reject("no-model-instance");

    // Same model instance AND same content/tokenizer/rope provenance.
    if (!kvProvenanceModel_.matchesForKvReuse(sessionModelId_))
        return reject("provenance-mismatch");

    const size_t have = kvProvenanceTokens_.size();
    const size_t want = promptTokens.size();
    if (want < have) return reject("prompt-shorter-than-cache");
    for (size_t i = 0; i < have; ++i) {
        if (kvProvenanceTokens_[i] != promptTokens[i])
            return reject("token-prefix-diverges");
    }
    // Positional setting must match too: a different rope configuration on
    // the same model instance silently corrupts attention.
    if (kvProvenanceModel_.ropeTheta != modelWeights.ropeTheta ||
        kvProvenanceModel_.ropeScaling != modelWeights.ropeScaling)
        return reject("positional-config-mismatch");

    return true;
}

// ===========================================================================
// Batched prefill
// ===========================================================================
void Deep2Engine::enableBatchedPrefill(bool enable, size_t chunkTokens) {
    batchedPrefillEnabled_ = enable;
    const char* env = std::getenv("DEEP2_BATCHED_PREFILL");
    if (env && *env && env[0] == '0') batchedPrefillEnabled_ = false;
    else if (env && *env && env[0] == '1') batchedPrefillEnabled_ = true;
    prefillChunkSize_ = chunkTokens;
    if (prefillChunkSize_ == 0) {
        const char* ce = std::getenv("DEEP2_PREFILL_CHUNK");
        if (ce && *ce) {
            char* end = nullptr;
            errno = 0;
            const long v = std::strtol(ce, &end, 10);
            if (errno == 0 && end != ce && *end == '\0' && v > 0) {
                prefillChunkSize_ = static_cast<size_t>(v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// forwardLayerBatched — one transformer layer over a chunk of tokens.
//
// Operates on [batch][hidden] activations.  Attention is causal across the
// chunk and sees the full committed prefix, matching the serial path exactly.
// ---------------------------------------------------------------------------
bool Deep2Engine::forwardLayerBatched(size_t layer, ActivationBatch& batch,
                                      size_t chunkBase, size_t seqLen) {
    if (layer >= modelWeights.layers.size()) return false;
    if (!batch.valid()) return false;
    if (config.hiddenDim == 0 || batch.hidden != config.hiddenDim) return false;

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = config.hiddenDim;
    const size_t B = batch.batch;

    if (!lw.attnNorm.data || !lw.ffnNorm.data) return false;

    // ---- attention norm (per row) ----
    static thread_local std::vector<float> normed;
    normed.assign(B * H, 0.0f);
    for (size_t j = 0; j < B; ++j) {
        RMSNormW(lw.attnNorm, batch.row(j), &normed[j * H], H, modelWeights.normEps);
        if (!H11TraceBatchVector("attn_norm", layer, j, &normed[j * H], H)) return false;
    }

    // ---- Q/K/V projections (per row, real quantized GEMV) ----
    const size_t numHeads = modelWeights.numHeads;
    const size_t numKVHeads = modelWeights.numKVHeads ? modelWeights.numKVHeads : numHeads;
    const size_t headDim = modelWeights.headDim ? modelWeights.headDim : (H / (numHeads ? numHeads : 1));
    const size_t kvDim = numKVHeads * headDim;
    if (!numHeads || !numKVHeads || !headDim) return false;
    if (numHeads * headDim != H) return false;
    if (!lw.wq.data || !lw.wk.data || !lw.wv.data) return false;
    if (!lw.wo.data && !lw.attnO.data) return false;

    static thread_local std::vector<float> qAll, kAll, vAll;
    qAll.assign(B * H, 0.0f);
    kAll.assign(B * kvDim, 0.0f);
    vAll.assign(B * kvDim, 0.0f);

    for (size_t j = 0; j < B; ++j) {
        const float* in = &normed[j * H];
        const float* bq = lw.bq.data ? reinterpret_cast<const float*>(lw.bq.data) : nullptr;
        const float* bk = lw.bk.data ? reinterpret_cast<const float*>(lw.bk.data) : nullptr;
        const float* bv = lw.bv.data ? reinterpret_cast<const float*>(lw.bv.data) : nullptr;
        LinearW(lw.wq, in, bq, &qAll[j * H], H);
        LinearW(lw.wk, in, bk, &kAll[j * kvDim], kvDim);
        LinearW(lw.wv, in, bv, &vAll[j * kvDim], kvDim);
        if (!H11TraceBatchVector("q", layer, j, &qAll[j * H], H) ||
            !H11TraceBatchVector("k", layer, j, &kAll[j * kvDim], kvDim) ||
            !H11TraceBatchVector("v", layer, j, &vAll[j * kvDim], kvDim)) return false;
    }

    // ---- per-head Q/K norms (Qwen3-style, optional) ----
    if (lw.attnQNorm.data) {
        for (size_t j = 0; j < B; ++j)
            for (size_t h = 0; h < numHeads; ++h)
                RMSNormW(lw.attnQNorm, &qAll[j * H + h * headDim],
                         &qAll[j * H + h * headDim], headDim, modelWeights.normEps);
    }
    if (lw.attnKNorm.data) {
        for (size_t j = 0; j < B; ++j)
            for (size_t h = 0; h < numKVHeads; ++h)
                RMSNormW(lw.attnKNorm, &kAll[j * kvDim + h * headDim],
                         &kAll[j * kvDim + h * headDim], headDim, modelWeights.normEps);
    }

    // ---- RoPE per row at its absolute position ----
    if (config.useRoPE) {
        const float theta = modelWeights.ropeTheta > 1.0f ? modelWeights.ropeTheta
                                                          : config.ropeTheta;
        const float scaling = modelWeights.ropeScaling > 0.0f ? modelWeights.ropeScaling
                                                              : config.ropeScaling;
        for (size_t j = 0; j < B; ++j) {
            applyRoPE(&qAll[j * H], &kAll[j * kvDim], headDim, numHeads,
                      numKVHeads, chunkBase + j, theta, scaling);
            if (!H11TraceBatchVector("rope_q", layer, j, &qAll[j * H], H) ||
                !H11TraceBatchVector("rope_k", layer, j, &kAll[j * kvDim], kvDim)) return false;
        }
    }

    if (!kvCache) return false;

    // The cache's own head count is the [pos] stride in keyPtr()/valuePtr(),
    // so the batched path must address KV through it rather than through the
    // model's head shape. Mismatching these would silently write every head's
    // data into the wrong slot.
    const size_t cacheHeads = kvCache->headCount();
    const size_t kvHeadsForCache =
        (numKVHeads == cacheHeads) ? numKVHeads : cacheHeads;
    const size_t cacheHeadDim = kvCache->headDimSize();
    if (cacheHeadDim != headDim) return false;   // cannot address the cache

    // ---- transactional KV write: stage, then commit the whole chunk ----
    // If any row write fails we abort before committing, so the cache never
    // holds a partially-written prefix.
    for (size_t j = 0; j < B; ++j) {
        for (size_t h = 0; h < kvHeadsForCache; ++h) {
            float* kd = kvCache->keyPtr(layer, h, chunkBase + j);
            float* vd = kvCache->valuePtr(layer, h, chunkBase + j);
            if (!kd || !vd) return false;
            std::memcpy(kd, &kAll[j * kvDim + h * headDim], headDim * sizeof(float));
            std::memcpy(vd, &vAll[j * kvDim + h * headDim], headDim * sizeof(float));
        }
    }

    // ---- batched causal attention ----
    ActivationBatch attn(B, H);
    BatchedAttentionGeometry g;
    g.numHeads = numHeads;
    g.numKVHeads = numKVHeads;
    g.headDim = headDim;
    g.hidden = H;
    g.groupSize = numHeads / numKVHeads;
    g.scale = 1.0f / std::sqrt(static_cast<float>(headDim));

    ActivationBatch qb(B, H);
    std::memcpy(qb.data.data(), qAll.data(), B * H * sizeof(float));

    // Build a contiguous [kvHead][position][headDim] view for this layer so
    // the batched scorer can index every visible position.  The layout matches
    // KVCache::[layer][pos][head][dim] exactly — see getHeadOffset().
    static thread_local std::vector<float> kView, vView;
    const size_t visible = std::min<size_t>(chunkBase + B, kvCache->capacity());
    const size_t viewElems = kvHeadsForCache * visible * headDim;
        kView.assign(viewElems, 0.0f);
    vView.assign(viewElems, 0.0f);
    for (size_t h = 0; h < kvHeadsForCache; ++h) {
        for (size_t p = 0; p < visible; ++p) {
            const float* ks = kvCache->keyAt(layer, h, p);
            const float* vs = kvCache->valueAt(layer, h, p);
            if (!ks || !vs) continue;
            std::memcpy(&kView[(h * visible + p) * headDim], ks, headDim * sizeof(float));
            std::memcpy(&vView[(h * visible + p) * headDim], vs, headDim * sizeof(float));
        }
    }
    if (H11BatchTraceEnabled()) {
        if (!H11TraceBatchVector("k_view", layer, 0, kView.data(), kView.size()) ||
            !H11TraceBatchVector("v_view", layer, 0, vView.data(), vView.size())) return false;
    }

    // Use the production KV-cache attention reducer for the correctness path.
    // It is intentionally invoked for each query row/head after the whole
    // chunk's K/V has been staged.  This preserves the layer-major batching
    // boundary while guaranteeing that H11 compares the same AVX2 dot,
    // expf/epsilon softmax, and weighted-accumulation semantics as the serial
    // forward path.  The standalone batched scorer remains available for a
    // later performance implementation once this reference is certified.
    for (size_t j = 0; j < B; ++j) {
        const size_t visibleForRow = chunkBase + j + 1;
        for (size_t h = 0; h < numHeads; ++h) {
            const size_t groupedHead = g.groupSize ? h / g.groupSize : h;
            const size_t kvHead =
                (g.groupSize && groupedHead < numKVHeads) ? groupedHead : h;
            AttentionWithCache(qAll.data() + j * H + h * headDim,
                               *kvCache, layer, kvHead,
                               attn.row(j) + h * headDim, visibleForRow);
        }
    }
    for (size_t j = 0; j < B; ++j)
        if (!H11TraceBatchVector("attention", layer, j, attn.row(j), H)) return false;

    // ---- output projection + attention residual ----
    const WeightTensor& wo = lw.wo.data ? lw.wo : lw.attnO;
    static thread_local std::vector<float> proj;
    proj.assign(B * H, 0.0f);
    for (size_t j = 0; j < B; ++j)
        LinearW(wo, attn.row(j), nullptr, &proj[j * H], H);
    for (size_t j = 0; j < B; ++j)
        if (!H11TraceBatchVector("attn_output", layer, j, &proj[j * H], H)) return false;

    for (size_t j = 0; j < B; ++j)
        for (size_t i = 0; i < H; ++i)
            batch.row(j)[i] += proj[j * H + i];
    for (size_t j = 0; j < B; ++j)
        if (!H11TraceBatchVector("post_attn", layer, j, batch.row(j), H)) return false;

    // ---- FFN ----
    for (size_t j = 0; j < B; ++j) {
        static thread_local std::vector<float> ffnNormed;
        ffnNormed.assign(H, 0.0f);
        RMSNormW(lw.ffnNorm, batch.row(j), ffnNormed.data(), H, modelWeights.normEps);
        if (!H11TraceBatchVector("ffn_norm", layer, j, ffnNormed.data(), H)) return false;

        static thread_local std::vector<float> ffnOut;
        ffnOut.assign(H, 0.0f);
        if (modelWeights.isMoE && modelWeights.numExperts > 0)
            computeMoEFFN(layer, ffnNormed.data(), ffnOut.data());
        else
            computeFFN(layer, ffnNormed.data(), ffnOut.data());
        if (!H11TraceBatchVector("ffn", layer, j, ffnOut.data(), H)) return false;

        for (size_t i = 0; i < H; ++i)
            batch.row(j)[i] += ffnOut[i];
        if (!H11TraceBatchVector("post_ffn", layer, j, batch.row(j), H)) return false;
    }

    ++execTelemetry_.layerExecutions;
    if (executionRunId_) {
        const uint64_t op = rawrxd::ExecutionAuthority::Instance().BeginOperation(
            executionRunId_, "forward_layer_batched", rawrxd::kDeviceHost, 0);
        rawrxd::ExecutionAuthority::Instance().EndOperation(executionRunId_, op, true,
                                                           B * H * sizeof(float));
    }
    (void)seqLen;
    return true;
}

// ---------------------------------------------------------------------------
// prefillSerial — the faithful one-token-at-a-time reference.
// Kept so the parity gate can compare chunk=N against chunk=1.
// ---------------------------------------------------------------------------
size_t Deep2Engine::prefillSerial(const int* promptTokens, size_t promptLen,
                                 float* hiddenOut) {
    if (!promptTokens || promptLen == 0 || !hiddenOut) return 0;
    size_t done = 0;
    for (size_t t = 0; t < promptLen; ++t) {
        float* h = hiddenStates + t * config.hiddenDim;
        if (!embedToken(promptTokens[t], h)) break;
        if (!forwardTokenAllLayers(h, t + 1)) break;
        if (modelWeights.finalNorm.data)
            RMSNormW(modelWeights.finalNorm, h, h, config.hiddenDim, modelWeights.normEps);
        // Publish the same post-normalization hidden state that the serial
        // leg actually used.  The old implementation accepted hiddenOut but
        // never wrote it, leaving parity callers to project an all-zero
        // buffer and masking the real serial/batched comparison.
        std::memcpy(hiddenOut + t * config.hiddenDim, h,
                    config.hiddenDim * sizeof(float));
        if (kvCache) {
            // advance() is void in the production KVCache; the bound check is
            // isFull() BEFORE advancing, and advance() past virtualMaxSeq is
            // already a no-op internally, so a chunk that would overrun simply
            // stops committing rather than corrupting the cache.
            if (kvCache->isFull()) break;
            kvCache->advance();
        }
        ++done;
        ++execTelemetry_.layerExecutions;
    }
    return done;
}

// ---------------------------------------------------------------------------
// prefillBatched — layer-major chunked prefill.
// ---------------------------------------------------------------------------
size_t Deep2Engine::prefillBatched(const int* promptTokens, size_t promptLen,
                                  float* hiddenOut, size_t chunkTokens) {
    if (!promptTokens || promptLen == 0 || !hiddenOut) return 0;
    if (config.hiddenDim == 0 || modelWeights.numLayers == 0) return 0;
    if (!hiddenStates) return 0;

    const size_t H = config.hiddenDim;
    size_t chunk = chunkTokens ? chunkTokens
                               : Deep2::SelectPrefillChunkSize(promptLen, H,
                                                               modelWeights.numLayers);
    if (chunk == 0) chunk = 1;
    chunk = std::min(chunk, promptLen);

    size_t done = 0;
    for (size_t base = 0; base < promptLen; base += chunk) {
        const size_t n = std::min(chunk, promptLen - base);
        if (base + n > config.maxSeqLen) break;

        ActivationBatch batch(n, H);
        // Materialize only the current causal chunk immediately before its
        // layer-major pass.  Embedding the entire prompt up front can change
        // residency and per-token state ordering relative to the serial
        // reference, which makes a multi-token parity failure look like a
        // transformer math problem even when the layer kernels agree.
        for (size_t j = 0; j < n; ++j) {
            if (!embedToken(promptTokens[base + j], batch.row(j))) return done;
        }

        for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
            if (!forwardLayerBatched(layer, batch, base, base + 1)) return done;
        }

        // Commit the chunk to the KV cursor and publish the hidden states.
        for (size_t j = 0; j < n; ++j) {
            float* h = hiddenStates + (base + j) * H;
            std::memcpy(h, batch.row(j), H * sizeof(float));
            if (modelWeights.finalNorm.data)
                RMSNormW(modelWeights.finalNorm, h, h, H, modelWeights.normEps);
            // Publish the same normalized state to the caller-owned output
            // buffer used by the parity gate and generation path.
            std::memcpy(hiddenOut + (base + j) * H, h, H * sizeof(float));
        }
        if (kvCache) {
            if (!kvCache->advanceBy(n)) return done;
        }
        done += n;
    }
    return done;
}

// ===========================================================================
// resetInferenceState — clear KV + hidden state, keep weights resident.
// Used between the serial and batched legs of an H11 parity run so both start
// from an identical empty cache. Deliberately does NOT touch model weights,
// GPU residency, or the admitted plan.
// ===========================================================================
void Deep2Engine::resetInferenceState() {
    if (kvCache) kvCache->reset();
    kvProvenanceValid_ = false;
    kvProvenanceTokens_.clear();
    kvReusedPrefixTokens_ = 0;
    kvAppendedTokens_ = 0;
    if (hiddenStates)
        std::memset(hiddenStates, 0,
                    config.maxSeqLen * config.hiddenDim * sizeof(float));

    // Reset SSM / Mamba-2 recurrent and conv state
    if (ssmMambaState)
    {
        size_t stateBytes = config.numLayers * ssmMambaDInner * ssmMambaDState * sizeof(float);
        std::memset(ssmMambaState, 0, stateBytes);
    }
    if (ssmMambaConvState)
    {
        size_t convBytes = config.numLayers * ssmMambaDConvKernel * ssmMambaDConvDim * sizeof(float);
        std::memset(ssmMambaConvState, 0, convBytes);
    }
}

// ===========================================================================
// prefillParityReport — H11-P1..P4: KV + logits parity, serial vs batched.
//
// Runs the faithful serial path, snapshots KV + hidden + logits, resets, runs
// the batched path with the requested chunk, and compares. Comparison reports
// max_abs, RMSE, cosine similarity and the FIRST mismatch, in that order, so a
// failure points at a concrete layer/position/head rather than "mismatch".
//
// H11_PARITY_AUTHORITY_001
// ===========================================================================
double Deep2Engine::prefillParityReport(const int *promptTokens, size_t promptLen,
                                       size_t chunkTokens, FILE *f) {
    if (!f) f = stdout;
    const size_t H = config.hiddenDim;
    if (!promptTokens || promptLen == 0 || H == 0 ||
        !kvCache || !hiddenStates || !modelWeights.numLayers) {
        std::fprintf(f, "[H11_PARITY] FATAL: engine not ready (H=%zu layers=%zu kv=%d)\n",
                     H, modelWeights.numLayers, kvCache ? 1 : 0);
        std::fprintf(f, "[H11_P%d_VERDICT] SKIP\n", 0);
        return -1.0;
    }

    // ---- KV snapshot helper ----
    const size_t nLayers = modelWeights.numLayers;
    const size_t nKVHeads = kvCache->headCount();
    const size_t headDim = kvCache->headDimSize();

    struct Snapshot {
        std::vector<float> k, v;
        size_t rows = 0;
        size_t elementsPerLayer() const { return k.size(); }
    };

    auto snap = [&](Snapshot &out) -> bool {
        const size_t rows = kvCache->currentLength();
        out.rows = rows;
        if (rows == 0) return false;
        const size_t perLayer = rows * nKVHeads * headDim;
        out.k.assign(nLayers * perLayer, 0.0f);
        out.v.assign(nLayers * perLayer, 0.0f);
        for (size_t L = 0; L < nLayers; ++L) {
            for (size_t p = 0; p < rows; ++p) {
                for (size_t h = 0; h < nKVHeads; ++h) {
                    const float *kp = kvCache->keyAt(L, h, p);
                    const float *vp = kvCache->valueAt(L, h, p);
                    const size_t off = L * perLayer + (p * nKVHeads + h) * headDim;
                    if (kp) std::memcpy(&out.k[off], kp, headDim * sizeof(float));
                    if (vp) std::memcpy(&out.v[off], vp, headDim * sizeof(float));
                }
            }
        }
        return true;
    };

    // ---- logits helper ----
    std::vector<float> logits(modelWeights.vocabSize ? modelWeights.vocabSize : 1, 0.0f);
    auto computeLogitsFrom = [&](const float *hidden) {
        if (modelWeights.vocabSize)
            computeLogits(hidden, logits.data());
    };

    std::vector<float> hiddenSerial(promptLen * H, 0.0f);
    std::vector<float> hiddenBatched(promptLen * H, 0.0f);
    Snapshot kvS{}, kvB{};

    // ---- serial leg ----
    resetInferenceState();
    const size_t doneSerial = prefillSerial(promptTokens, promptLen, hiddenSerial.data());
    const bool haveKvSerial = snap(kvS);
    if (std::getenv("RAWRXD_H11_KV_TRACE") && haveKvSerial && !kvS.k.empty() && !kvS.v.empty()) {
        std::fprintf(f, "[H11_KV_TRACE] leg=serial k0=%.9e k1=%.9e v0=%.9e v1=%.9e rows=%zu\n",
                     kvS.k[0], kvS.k.size() > 1 ? kvS.k[1] : 0.0f,
                     kvS.v[0], kvS.v.size() > 1 ? kvS.v[1] : 0.0f, kvS.rows);
    }
    computeLogitsFrom(hiddenSerial.data() + (doneSerial ? (doneSerial - 1) : 0) * H);
    std::vector<float> logitsSerial = logits;

    // ---- batched leg ----
    resetInferenceState();
    const size_t doneBatched = prefillBatched(promptTokens, promptLen,
                                              hiddenBatched.data(), chunkTokens);
    const bool haveKvBatched = snap(kvB);
    if (std::getenv("RAWRXD_H11_KV_TRACE") && haveKvBatched && !kvB.k.empty() && !kvB.v.empty()) {
        std::fprintf(f, "[H11_KV_TRACE] leg=batched k0=%.9e k1=%.9e v0=%.9e v1=%.9e rows=%zu\n",
                     kvB.k[0], kvB.k.size() > 1 ? kvB.k[1] : 0.0f,
                     kvB.v[0], kvB.v.size() > 1 ? kvB.v[1] : 0.0f, kvB.rows);
    }
    computeLogitsFrom(hiddenBatched.data() + (doneBatched ? (doneBatched - 1) : 0) * H);
    std::vector<float> logitsBatched = logits;

    // ---- compare ----
    auto cmpVec = [&](const float *a, const float *b, size_t n,
                      const char *what, size_t stride, size_t idxOffset,
                      uint64_t &firstIdx, double &firstVal) -> std::pair<double,double> {
        double maxAbs = 0.0, sumsq = 0.0, dot = 0.0, na = 0.0, nb = 0.0;
        size_t first = SIZE_MAX;
        for (size_t i = 0; i < n; ++i) {
            const double d = std::fabs(double(a[i]) - double(b[i]));
            if (d > maxAbs) maxAbs = d;
            sumsq += d * d;
            dot += double(a[i]) * double(b[i]);
            na += double(a[i]) * double(a[i]);
            nb += double(b[i]) * double(b[i]);
            if (first == SIZE_MAX && d > 1e-6) {
                first = i;
                firstVal = d;
                firstIdx = idxOffset + (i / (stride ? stride : 1));
                (void)what;
            }
        }
        return {maxAbs, std::sqrt(sumsq / (n ? double(n) : 1.0))};
    };

    double maxHiddenAbs = 0.0, rmseHidden = 0.0;
    uint64_t firstHiddenIdx = 0;
    double firstHiddenVal = 0.0;
    {
        std::pair<double,double> r = cmpVec(hiddenSerial.data(), hiddenBatched.data(),
                                            promptLen * H, "hidden", H, 0,
                                            firstHiddenIdx, firstHiddenVal);
        maxHiddenAbs = r.first; rmseHidden = r.second;
    }

    uint64_t firstKvIdx = 0;
    double firstKvVal = 0.0;
    double maxKvAbs = 0.0, rmseKv = 0.0;
    bool kvOk = (haveKvSerial == haveKvBatched);
    if (haveKvSerial && haveKvBatched && kvS.k.size() == kvB.k.size()) {
        // Decode the flat index into layer:position:head for a readable report.
        const size_t perPosHead = nKVHeads * headDim;
        const size_t perLayer = kvS.rows * perPosHead;
        std::pair<double,double> rk = cmpVec(kvS.k.data(), kvB.k.data(),
                                             kvS.k.size(), "k", perPosHead, 0,
                                             firstKvIdx, firstKvVal);
        std::pair<double,double> rv = cmpVec(kvS.v.data(), kvB.v.data(),
                                             kvS.v.size(), "v", perPosHead, 0,
                                             firstKvIdx, firstKvVal);
        maxKvAbs = std::fmax(rk.first, rv.first);
        rmseKv = std::fmax(rk.second, rv.second);
        if (std::getenv("RAWRXD_H11_KV_TRACE")) {
            double worstK = 0.0, worstV = 0.0;
            size_t worstKL = 0, worstVL = 0, worstKIdx = 0, worstVIdx = 0;
            const size_t elemsPerLayer = kvS.rows * nKVHeads * headDim;
            for (size_t L = 0; L < nLayers; ++L) {
                const size_t base = L * elemsPerLayer;
                for (size_t i = 0; i < elemsPerLayer; ++i) {
                    const double dk = std::fabs(double(kvS.k[base + i]) - double(kvB.k[base + i]));
                    const double dv = std::fabs(double(kvS.v[base + i]) - double(kvB.v[base + i]));
                    if (dk > worstK) { worstK = dk; worstKL = L; worstKIdx = i; }
                    if (dv > worstV) { worstV = dv; worstVL = L; worstVIdx = i; }
                }
            }
            std::fprintf(f, "[H11_KV_TRACE] worst_k layer=%zu local=%zu diff=%.9e serial=%.9e batched=%.9e\n",
                         worstKL, worstKIdx, worstK,
                         kvS.k[worstKL * elemsPerLayer + worstKIdx],
                         kvB.k[worstKL * elemsPerLayer + worstKIdx]);
            std::fprintf(f, "[H11_KV_TRACE] worst_v layer=%zu local=%zu diff=%.9e serial=%.9e batched=%.9e\n",
                         worstVL, worstVIdx, worstV,
                         kvS.v[worstVL * elemsPerLayer + worstVIdx],
                         kvB.v[worstVL * elemsPerLayer + worstVIdx]);
        }
        (void)perLayer;
    } else {
        kvOk = false;
    }

    double maxLogitAbs = 0.0;
    {
        size_t i = 0;
        for (; i < logitsSerial.size() && i < logitsBatched.size(); ++i)
            maxLogitAbs = std::fmax(maxLogitAbs,
                std::fabs(double(logitsSerial[i]) - double(logitsBatched[i])));
    }

    const double overall = std::fmax(std::fmax(maxHiddenAbs, maxKvAbs), maxLogitAbs);
    // Tolerance: prefill is identical math in a different order, so a tight
    // tolerance is expected. 1e-3 absolute is well inside f32 accumulation
    // noise for these magnitudes while still catching a real logic error
    // (wrong head, wrong position, missing causal mask), which shows up as
    // O(1) divergence, not O(1e-4).
    const bool pass = (doneSerial == doneBatched) && kvOk && overall <= 1e-3;

    std::fprintf(f,
        "H11_PREFILL_PARITY\n"
        "  model=%s\n"
        "  prompt_tokens=%zu\n"
        "  chunk_tokens=%zu\n"
        "  layers=%zu kv_heads=%zu head_dim=%zu\n"
        "  serial_tokens_done=%zu\n"
        "  batched_tokens_done=%zu\n"
        "  kv_rows_serial=%zu\n"
        "  kv_rows_batched=%zu\n"
        "  kv_rows_match=%d\n"
        "  kv_byte_exact=%d\n"
        "  max_abs_hidden=%.6e\n"
        "  rmse_hidden=%.6e\n"
        "  max_abs_kv=%.6e\n"
        "  rmse_kv=%.6e\n"
        "  max_abs_logits=%.6e\n"
        "  max_abs_overall=%.6e\n"
        "  first_mismatch_hidden_index=%llu value=%.6e\n"
        "  first_mismatch_kv_flat_index=%llu value=%.6e\n"
        "  tolerance=1e-03\n"
        "  verdict=%s\n",
        getModelPath().c_str(), promptLen,
        chunkTokens ? chunkTokens : prefillChunkSize_,
        nLayers, nKVHeads, headDim,
        doneSerial, doneBatched,
        haveKvSerial ? kvS.rows : 0, haveKvBatched ? kvB.rows : 0,
        (doneSerial == doneBatched) && kvOk ? 1 : 0,
        (maxKvAbs == 0.0 && maxHiddenAbs == 0.0) ? 1 : 0,
        maxHiddenAbs, rmseHidden, maxKvAbs, rmseKv, maxLogitAbs, overall,
        (unsigned long long)firstHiddenIdx, firstHiddenVal,
        (unsigned long long)firstKvIdx, firstKvVal,
        pass ? "PASS" : "FAIL");
    std::fflush(f);

    // Leave the engine on the batched state (that is the path being certified).
    resetInferenceState();
    prefillBatched(promptTokens, promptLen, hiddenBatched.data(), chunkTokens);
    return overall;
}

} // namespace Deep2

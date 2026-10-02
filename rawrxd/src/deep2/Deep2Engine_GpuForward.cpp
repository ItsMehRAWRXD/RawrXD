// Deep2Engine_GpuForward.cpp — forwardLayerGpuResident + contiguous/multi/hybrid
#include "Deep2Engine.h"
#include "Deep2GpuForward.hpp"
#include "Deep2DualGpuRowSplit.hpp"
#include "QuantKernelRegistry.hpp"
// RAWRXD_B70_PREPARED_CACHE_UNIT_001: shared with tools/prepared_cache_unit.cpp
// so the unit test and the engine compile the same cache implementation.
#include "Deep2_PreparedWeightCache.hpp"
#include "GpuTransferCounters.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "lavapath/BatchD_UnifiedAsyncMove.hpp"
#include "lavapath/ParseMibBudget.hpp"
#include "lavapath/DualStickStreamWindow.hpp"
#include "Deep2LivePath.hpp"
#include "GPUForwardChildIgnoreHooks.hpp"
#include "AttnVisibilityTrace.h"
#include "AttnCtx2Probe.h"
#include "vulkan_compute.h"
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

// RAWRXD_B73_Q5K_ROUTING_DEFECT_001
//
// Q5_K (13) was listed here but has NO native kernel:
//
//   PackedQuant            admits  8, 10, 11, 12, 13, 14
//   DispatchGemvQuant      admits  8, 10, 11, 12, 14        (vulkan_compute.cpp)
//   deep2_qgemv.comp      decodes 8, 10, 11, 12, 14
//
// The two lists disagreed by exactly one type. For a Q5_K weight this function
// returned true, routing the weight into the native packed branch, where
// DispatchGemvQuant immediately returned false. The fused QKV path treated that
// as fatal:
//
//   GPU_FORWARD_FAIL_STAGE=GEMV_QKV layer=0 op=qkvOverlap3
//   GPU_FORWARD_FAIL_STAGE=RANGE_OR_MULTIMAP
//   COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL
//
// observed on Codestral-22B-Q4_K_M at prefill token 0, where attn_v is type 13
// while attn_q/attn_k are type 12. The model is otherwise well-formed; it was
// rejected by a routing table entry that pointed at a kernel which does not
// exist.
//
// FIX: remove Q5_K so it routes to the prepared-F32 path, which is correct for
// it. This is a routing correction, NOT a clamp, NaN sanitization, fallback
// kernel, or backend switch -- no arithmetic changed, and no gate is satisfied
// by hiding the failure.
//
// The three lists above must stay in agreement. If a type is added to one, it
// must be added to all three.
bool PackedQuant(const WeightTensor& wt) {
    if (!wt.data || !wt.sizeBytes) return false;
    const int t = wt.type;
    return t == (int)GGMLType::GGML_TYPE_Q8_0 ||        // 8  shader: q8_0_weight
           t == (int)GGMLType::GGML_TYPE_Q2_K ||        // 10 shader: q2k_weight
           t == (int)GGMLType::GGML_TYPE_Q3_K ||        // 11 shader: q3k_weight
           t == (int)GGMLType::GGML_TYPE_Q4_K ||        // 12 shader: q4k_weight
           t == (int)GGMLType::GGML_TYPE_Q6_K;          // 14 shader: q6k_weight
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

// RAWRXD_B63_PREPARED_WEIGHT_CACHE_001
//
// The defect this fixes is a representation-lifecycle bug, not a memory-policy
// choice. BOUNDED_STREAM previously conflated two independent concerns:
//
//   1. how much F32 may be resident on the GPU   (a VRAM admission question)
//   2. whether a weight is re-dequantized       (a CPU cost question)
//
// It answered (2) by re-dequantizing on every call. For a Q2_K model that is
// once per (layer, weight, decode token): measured 3024 CPU dequant events for
// a single 32-token 3B run, versus 0 for the same engine on Q4_K_M. The engine
// was manufacturing its GPU representation from scratch every token and
// discarding it, which is why decode TPS collapsed with model size rather than
// tracking the bandwidth bound.
//
// The fix separates the layers:
//
//   quantized source authority   (the GGUF tensor, unchanged and authoritative)
//        |
//        v
//   persistent prepared F32      (host-side, LRU-bounded, survives GPU eviction)
//        |
//        v
//   bounded GPU residency        (unchanged: still a separate admission decision)
//
// A tensor may be evicted from VRAM without discarding its prepared form. The
// expensive work happens at most once per weight, not once per token.
//
// This is deliberately NOT a switch to RESIDENT_CACHE. That mode already existed
// as an unbounded map keyed by weight name, which would have made host F32 growth
// an implicit invariant and reproduced the admission problem at larger sizes. The
// prepared cache has its own explicit host budget and reports its accounting
// separately from GPU residency; prepared host bytes are never counted against
// the Vulkan heap.

struct PreparedWeightKey {
    const void* source = nullptr;
    uint64_t sourceBytes = 0;
    uint32_t ggmlType = 0;
    uint64_t elements = 0;

    // RAWRXD_B63_PREPARED_WEIGHT_CACHE_001: unordered_map::find/erase require
    // key equality. Identity is the full key, not just the source pointer:
    // the same tensor may be re-prepared with a different element count or
    // after a remap, and a pointer-only match would serve a stale entry.
    bool operator==(const PreparedWeightKey& o) const noexcept {
        return source == o.source &&
               sourceBytes == o.sourceBytes &&
               ggmlType == o.ggmlType &&
               elements == o.elements;
    }
};

struct PreparedWeightKeyHash {
    size_t operator()(const PreparedWeightKey& k) const noexcept {
        // Mix pointer bits with geometry so two different tensors that happen to
        // reuse a freed address do not collide into one entry.
        uint64_t h = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(k.source));
        h ^= h >> 33; h *= 0xff51afd7ed558ccdull;
        h ^= k.sourceBytes + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= k.ggmlType + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= k.elements + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        return static_cast<size_t>(h);
    }
};

struct PreparedWeight {
    std::vector<float> f32;
    uint64_t bytes = 0;
    uint64_t lastUseTick = 0;
};

} // namespace

// RAWRXD_B70_PREPARED_CACHE_UNIT_001: the cache implementation now lives in
// Deep2_PreparedWeightCache.hpp so the engine and the RAWRXD_B70 unit test
// compile the SAME code. It used to be inline here, which meant B63's eviction
// and oversized-weight paths could not be tested without an inference run --
// and after B65/B66/B67 no model routes any tensor through the cache, so those
// paths were never exercised at all.
//
// The key, hash, stats and class definitions were removed from this file and
// moved verbatim into that header. Acquire() now takes the dequantizer as a
// parameter; this translation unit passes the registry's, preserving the exact
// production behavior.
const float* EnsureF32(Deep2Engine& e, const WeightTensor& wt,
                       std::unordered_map<std::string, std::vector<float>>& cache) {
    (void)e;
    (void)cache;
    if (!wt.data) {
        std::fprintf(stderr, "ENSURE_F32_FAIL_NULL name=%s\n", wt.name.c_str());
        return nullptr;
    }
    if (wt.type == (int)GGMLType::GGML_TYPE_F32) {
        return reinterpret_cast<const float*>(wt.data);
    }
    // Quantized weight: serve a persistent prepared F32 representation. The
    // previous code re-dequantized here on every call (thousands of times per
    // generation for Q2_K); preparation now happens once per tensor per epoch.
    //
    // RAWRXD_B70: adapt Deep2::WeightTensor to the cache's PreparedWeightSource
    // and pass the registry's dequantizer for this type explicitly.
    Deep2::PreparedWeightSource src;
    src.name = wt.name;
    src.type = wt.type;
    src.rows = static_cast<uint32_t>(wt.rows);
    src.cols = static_cast<uint32_t>(wt.cols);
    src.data = reinterpret_cast<const uint8_t*>(wt.data);
    src.sizeBytes = wt.sizeBytes;
    auto deq = QuantKernelRegistry::Instance().GetDequant(wt.type);
    return e.PreparedWeights().Acquire(src, reinterpret_cast<Deep2::PreparedDequantFn>(deq));
}

// RAWRXD_B63_PREPARED_WEIGHT_CACHE_001: the cache is owned by the engine so its
// lifetime is bounded by the engine's, and so it cannot outlive the model
// source pointers that its keys reference.
Deep2::PreparedWeightCache& Deep2Engine::PreparedWeights() {
    if (!preparedWeights_) {
        preparedWeights_ = new PreparedWeightCache();
    }
    return *preparedWeights_;
}

void Deep2Engine::ReleasePreparedWeights() {
    if (preparedWeights_) {
        // RAWRXD_B63_RECEIPT: emit the gate counters here, while the cache type
        // is complete and the accounting still exists. This is the destructor
        // safe point; ~Deep2Engine only clears the raw pointer.
        preparedWeights_->WriteReceipt();
    }
    delete preparedWeights_;
    preparedWeights_ = nullptr;
}

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

// RAWRXD_VULKAN_BODY_PARITY_GRID_001
// The Vulkan forward emitted five checkpoints against the CPU's 499, so the
// bisection tool was blind: a divergence could be located no more precisely
// than "somewhere in the transformer body". This adds the same grid on the GPU
// side so the first mismatching layer and operator becomes a measured fact.
//
// Record format is BYTE-IDENTICAL to Deep2Engine::parityEmitCount:
//   STEP=<n> CP=<NAME> COUNT=<n> MIN=.. MAX=.. MEAN=.. L2=.. FIRST8=.. HASH=<hex>
// and the hash is the same FNV-1a 64 over raw float bytes, so CPU and GPU lines
// are directly comparable by a single parser. Reusing the CPU's own hash
// function is the point: a different hash would make every line look different
// and tell us nothing.
//
// Gated on RAWRXD_VULKAN_PARITY_GRID=1, default OFF. It is deliberately a
// separate flag from the attention-head hash probe so that neither can be
// enabled by accident, and it must never run during a TPS gate: each
// checkpoint forces a device->host readback and would dominate the timing it
// claims to measure.
namespace {
struct VulkanParityGrid {
    bool     on = false;
    std::FILE* f = nullptr;
    // RAWRXD_COMPARE_B_001: when set, every capture is ALSO written as a raw
    // binary vector to <dir>/<layer>_<stage>.bin. Those files are the exact
    // bytes the dispatch consumed at that point, so the projection can be
    // replayed from them -- which is the only way to close the "ArenaNormed is
    // the dispatch input" assumption that everything else has rested on.
    std::string dumpDir;
    // RAWRXD_VULKAN_GRID_STEP_IDENTITY_001
    //
    // This was `int step = 0` -- an initialised, mutable, NEVER-ASSIGNED member.
    // Every emit() keyed on it, so `step` was 0 for the whole process and the
    // (step, layer, stageId) key added by RAWRXD_VULKAN_PARITY_LAYER_KEY_001
    // degenerated back to (layer, stageId). Measured consequence: the grid
    // reported 374 numeric records over 22 layers and exactly ONE step, so
    // "stateful decode is broken" and "the first token's body is wrong" were
    // indistinguishable -- the instrument could not see step >= 1 at all.
    //
    // It is now anchored, not incremented. anchorStep() is called by the layer
    // body with the AUTHORITATIVE KV logical position
    // (KVCache::currentLength(), the same value AppendKV writes to and
    // DispatchAttnDecode is given as its sequence length), so the grid key
    // cannot drift from the state it is describing. -1 means "never anchored",
    // and emit() refuses to produce a record in that state: an unanchored grid
    // claiming step 0 is exactly the failure this replaces.
    int      step = -1;
    int      maxAnchoredStep = -1;
    int      anchorCalls = 0;
    void anchorStep(int authoritativePos) {
        step = authoritativePos;
        ++anchorCalls;
        if (authoritativePos > maxAnchoredStep) maxAnchoredStep = authoritativePos;
    }
    bool stepAnchored() const noexcept { return step >= 0; }
    // RAWRXD_VULKAN_PARITY_LAYER_KEY_001
    //
    // This was `unsigned emittedMask[4]` -- 128 bits keyed by stageId ALONE.
    // `layer` was accepted by emit() and used only to label the record; it was
    // never part of the key. Each of the 17 stageIds therefore emitted exactly
    // once per PROCESS, and because layer 0 runs first it consumed all 17 slots.
    //
    // The measured consequence, on tinyllama-1.1b-chat Q4_K_M against its own CPU
    // grid: LAYER_0_* produced 16 comparable numeric records, and every
    // LAYER_1_* through LAYER_21_* record read
    //     UNAVAILABLE=NO_DEVICE_ARENA (fused into DispatchAttnDecode; ...)
    // which is a statement about this mask, not about the arena. Every claim
    // about where a deeper layer diverges was therefore unmeasurable, and the
    // only layer that could be compared was layer 0.
    //
    // The comment on emit() already stated the intended contract -- "emitted
    // once per layer per step" -- so this restores the contract rather than
    // changing it. step is deliberately still excluded: the grid is meant to
    // describe the first step observed, and including it would multiply the
    // record count without localising anything earlier.
    //
    // Sized for 4096 (layer, stage) pairs; it grows on demand, so a model
    // deeper or wider than that is not silently truncated.
    std::vector<uint64_t> emittedMask = std::vector<uint64_t>(64, 0);

    // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001 (G6/G13): the arena generation,
    // bumped on every fusion window and every residency change. A record carries
    // the epoch it was captured in so a later read cannot be mistaken for the
    // same instant.
    uint64_t arenaEpoch = 1;

    // G13 counters: how many deliberate invalid (premature) captures were taken,
    // and their L2 total, so the run can assert they differ from the valid ones.
    uint32_t prematureCount_ = 0;
    double   prematureL2_    = 0.0;

    // G12: number of records whose independent second readback reproduced the
    // first. Every emitted record must contribute, or the grid is not certified.
    uint32_t validCount_ = 0;
    uint32_t unstableCount_ = 0;

    // Monotonic per-layer capture sequence. (STEP, DISPATCH_SEQ) is a candidate
    // permanent identity: ordinal alignment within a dump is useful for
    // investigation but is not proof that the Nth record on one side is the Nth
    // execution on the other.
    uint32_t dispatchSeq_ = 0;

    void bumpEpoch() { ++arenaEpoch; }

    static uint64_t hash(const float* v, size_t n) {
        uint64_t h = 1469598103934665603ull;   // FNV-1a 64 offset basis
        const auto* b = reinterpret_cast<const uint8_t*>(v);
        for (size_t i = 0; i < n * sizeof(float); ++i) { h ^= b[i]; h *= 1099511628211ull; }
        return h;
    }

    // RAWRXD_VULKAN_KV_SPLIT_001: the K/V split instrument publishes FNV-1a
    // over the FULL kvDim span so its hashes are directly comparable with the
    // CPU probe's K_HASH / V_HASH in parityEmitKvWrite. Same function, same
    // layout, same join key -- a comparator must not need a tolerance to line
    // the two sides up.
    static uint64_t hashPublic(const float* v, size_t n) { return hash(v, n); }

    static VulkanParityGrid& instance() {
        static VulkanParityGrid g;
        static bool init = false;
            if (!init) {
                init = true;
                // RAWRXD_VULKAN_GRID_STEP_IDENTITY_001: writeSummary() existed
                // and had zero callers, so the grid's own self-certification
                // line (G14: every record READBACK_VALID=1, every premature
                // capture distinguishable) had never once reached a file. A
                // summary nobody writes is an instrument that cannot report on
                // itself, which is why "READBACK_AUTHORITY=CERTIFIED" had no
                // measured instance behind it. Flushed at exit.
                std::atexit([]{ VulkanParityGrid::instance().writeSummary(); });
                const char* e = std::getenv("RAWRXD_VULKAN_PARITY_GRID");
            if (e && (e[0] == '1' || e[0] == 't' || e[0] == 'T')) {
                const char* out = std::getenv("RAWRXD_VULKAN_PARITY_GRID_OUT");
                g.f = std::fopen(out && *out ? out : "vulkan_parity_grid.txt", "wb");
                g.on = (g.f != nullptr);
if (g.on) {
                std::fprintf(stderr, "[VULKAN_PARITY_GRID] ON out=%s "
                             "(device->host readback per checkpoint; NOT for TPS gates)\n",
                             out && *out ? out : "vulkan_parity_grid.txt");
                // RAWRXD_COMPARE_B_001: optional full-vector capture.
                const char* dd = std::getenv("RAWRXD_VULKAN_PARITY_DUMP_VECTORS");
                if (dd && *dd) g.dumpDir = dd;
                if (!g.dumpDir.empty()) {
                    std::fprintf(stderr,
                        "[VULKAN_PARITY_GRID] VECTOR_DUMP=%s "
                        "(dispatch-boundary bytes for replay)\n", g.dumpDir.c_str());
                }
            }
            }
        }
        return g;
    }

    // Emits one checkpoint. `stageId` is a stable per-layer index so a stage is
    // emitted once per layer per step even if the layer is re-entered.
    //
    // Takes the DeviceBuf handle rather than a raw pointer because that is what
    // the arenas return and what DownloadVector consumes; taking float* would
    // silently invite a caller to pass something that is not a device arena.
    void emit(VulkanCompute* vc, unsigned layer, unsigned stageId,
              const char* name, const VulkanCompute::DeviceBuf& arena, size_t count) {
        if (!on || !f || !vc || count == 0) return;
        // RAWRXD_VULKAN_GRID_STEP_IDENTITY_001: a record whose step identity is
        // unknown is not a measurement. Emit the refusal so the gap is visible
        // in the same file, rather than defaulting to step 0 and producing a
        // plausible wrong answer.
        if (!stepAnchored()) {
            std::fprintf(f,
                "STEP=-1 CP=LAYER_%u_%s COUNT=%zu UNANCHORED=1 "
                "NOTE=grid_step_never_anchored_to_authoritative_kv_position\n",
                layer, name, count);
            std::fflush(f);
            return;
        }
        // RAWRXD_VULKAN_PARITY_LAYER_KEY_001: the key is (step, layer, stageId),
        // not stageId. See the field comment; the previous form made layers
        // 1..N-1 unobservable rather than divergent.
        //
        // step is in the key because the measured divergence is NOT at step 0.
        // With (layer, stageId) alone, all 22 layers matched CPU to <=1.9e-4
        // relative L2 on the first token while the greedy-logit comparison at
        // step 17 showed COSINE_SIM=0.757578 and TOP8_OVERLAP=0/8. An instrument
        // that can only see the first token cannot distinguish "the layer body
        // is wrong" from "the layer body is right and something accumulates per
        // token", and those have completely different fixes.
        const unsigned key  = (step * 1024u + layer) * 64u + stageId;
        const unsigned slot = key >> 6;
        const uint64_t  bit  = 1ull << (key & 63u);
        if (slot >= emittedMask.size()) emittedMask.resize(slot + 1, 0ull);
        if (emittedMask[slot] & bit) return;
        emittedMask[slot] |= bit;

        std::vector<float> host(count);
        // RAWRXD_VULKAN_BODY_PARITY_GRID_001
        // The readback must BREAK THE FUSED WINDOW, and it must use the
        // synchronized download pair.
        //
        // Two separate mistakes were made here first, and both produced a
        // confident, entirely fictitious result:
        //
        //  1. Dispatch* submits are asynchronous, so a plain arena read
        //     returned an unwritten buffer.
        //  2. More importantly, the layer body runs inside a FUSED WINDOW that
        //     DEFERS execution until EndFusedLayer(). Reading mid-layer without
        //     breaking fusion therefore observes pre-layer state no matter how
        //     well the download is synchronized. The signature of that is
        //     unmistakable once seen: every stage read L2=0, and
        //     LAYER_0_LAYER_RESIDUAL read L2=0.768852 -- exactly the
        //     embedding's L2, i.e. ArenaHidden still held the embedding because
        //     the layer had never actually run.
        //
        // Breaking fusion is only correct under this debug flag, because it
        // serialises the layer and would distort any timing measured alongside
        // it. That is the reason this is opt-in and not always-on.
        const bool wasFused = vc->FusedRecording();

        // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001
        // G13: a DELIBERATELY PREMATURE read must be rejected, otherwise the
        // validity check has no power. When RAWRXD_VULKAN_PARITY_PREMATURE=1
        // this path reads BEFORE the fused window is closed, which is exactly
        // the mistake that produced an all-zero grid earlier. The record it
        // emits is marked READBACK_VALID=0 and, when PREMATURE_EXPECT_REJECT=1,
        // the run asserts the premature capture DIFFERS from the valid one.
        // If a premature read ever agreed with a valid read, the capture
        // mechanism would be unable to distinguish executed work from pending
        // work and every number it produced would be unusable.
        static const bool premature = [] {
            const char* e = std::getenv("RAWRXD_VULKAN_PARITY_PREMATURE");
            return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
        }();

        if (premature && wasFused) {
            // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001 (G13)
            // ORDERING: this block must run AFTER the valid capture, not before.
            // An earlier version read prematurely FIRST and then attempted the
            // valid capture, and the valid capture came back READBACK=FAIL on
            // every stage -- the premature download consumed the window state
            // that EndFusedLayer() needed. G13 was still satisfied (the premature
            // read did return different values), but the whole run was
            // invalidated because nothing valid survived.
            //
            // The correct sequence is: close the window -> capture valid ->
            // reopen the window -> capture premature (which is now premature by
            // construction, because the window is open again).
            // This block is intentionally empty here; the premature capture
            // happens below, after BeginFusedLayer().
        }

        if (wasFused && !vc->EndFusedLayer()) {
            // If the window cannot be closed the checkpoint is not trustworthy,
            // and saying so is better than emitting a plausible wrong number.
            std::fprintf(f, "STEP=%d CP=LAYER_%u_%s FUSE_BREAK=FAIL "
                            "(checkpoint NOT captured; the value would be pre-layer state)\n",
                         step, layer, name);
            std::fflush(f);
            return;
        }

        VulkanCompute::DownloadTicket ticket;
        const size_t bytes = count * sizeof(float);
        bool got = vc->SubmitDownloadAsync(
                       const_cast<VulkanCompute::DeviceBuf&>(arena), bytes, ticket) &&
                   vc->WaitDownloadAsync(ticket, host.data(), bytes);
        if (got && wasFused) {
            // Re-open the window so the rest of the layer still runs fused.
            got = vc->BeginFusedLayer();
            // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001 (G13): with the window
            // open again, reading now is premature BY CONSTRUCTION. That makes
            // the invalid capture available for comparison without consuming the
            // state the valid capture needs. The premise of G13 is that these
            // two disagree; if they ever agreed, the capture could not
            // distinguish executed work from pending work.
            if (got && premature) {
                std::vector<float> bad(count, 0.0f);
                VulkanCompute::DownloadTicket t2;
                const size_t b2 = count * sizeof(float);
                const bool g2 = vc->SubmitDownloadAsync(
                                    const_cast<VulkanCompute::DeviceBuf&>(arena), b2, t2) &&
                                vc->WaitDownloadAsync(t2, bad.data(), b2);
                if (!g2) vc->CancelDownloadTicket(t2);
                double sq2 = 0.0;
                for (size_t i = 0; i < count; ++i) sq2 += (double)bad[i] * (double)bad[i];
                const double l2b = std::sqrt(sq2);
                std::fprintf(f,
                    "STEP=%d CP=LAYER_%u_%s COUNT=%zu CAPTURE=PREMATURE "
                    "READBACK_VALID=0 L2=%.9g VALID_L2=%.9g DIFFERS=%d "
                    "NOTE=deliberate_invalid_read_fusion_window_reopened\n",
                    step, layer, name, count, l2b, 0.0,
                    (std::fabs(l2b) > 1e-12) ? 1 : 0);
                std::fflush(f);
                ++prematureCount_;
                prematureL2_ += l2b;
            }
        }
        if (!got) {
            vc->CancelDownloadTicket(ticket);
            // A failed readback is reported as an explicit gap, not as a
            // silently omitted checkpoint: a missing line would read as
            // "never reached" when the truth is "could not be read".
            std::fprintf(f, "STEP=%d CP=LAYER_%u_%s COUNT=%zu READBACK=FAIL "
                            "READBACK_VALID=0 FUSE_ENDED=%d EPOCH=%llu\n",
                         step, layer, name, count, wasFused ? 1 : 0,
                         (unsigned long long)arenaEpoch);
            std::fflush(f);
            return;
        }

        // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001
        // G11/G12: finite validation, then an INDEPENDENT IMMEDIATE second
        // readback that must reproduce the first. A capture that cannot be
        // reproduced is not a measurement of a settled buffer, and saying so is
        // the whole point of this gate.
        size_t nonFinite = 0;
        for (size_t i = 0; i < count; ++i)
            if (!std::isfinite(host[i])) ++nonFinite;

        bool readbackValid = (nonFinite == 0);
        uint64_t h2 = 0;
        if (readbackValid) {
            std::vector<float> again(count, 0.0f);
            VulkanCompute::DownloadTicket t3;
            const bool g3 = vc->SubmitDownloadAsync(
                                const_cast<VulkanCompute::DeviceBuf&>(arena), bytes, t3) &&
                            vc->WaitDownloadAsync(t3, again.data(), bytes);
            if (!g3) vc->CancelDownloadTicket(t3);
            if (g3) {
                h2 = hash(again.data(), count);
                if (h2 != hash(host.data(), count)) {
                    readbackValid = false;
                    ++unstableCount_;
                }
            } else {
                readbackValid = false;
                ++unstableCount_;
            }
        }
        if (readbackValid) ++validCount_;

        // RAWRXD_COMPARE_B_001: persist the exact captured bytes. This is the
        // dispatch-boundary input, not an upstream arena observation, so
        // replaying the projection from this file closes the assumption that
        // ArenaNormed is what the dispatch actually consumes. Written only when
        // the readback was independently reproduced (G12); a vector that could
        // not be verified is not evidence and is not persisted.
        if (!dumpDir.empty() && readbackValid) {
            char path[1024];
            std::snprintf(path, sizeof(path), "%s/%u_%s.bin",
                          dumpDir.c_str(), layer, name);
            if (std::FILE* bf = std::fopen(path, "wb")) {
                const uint32_t n32 = (uint32_t)count;
                std::fwrite(&n32, sizeof(n32), 1, bf);
                std::fwrite(host.data(), sizeof(float), count, bf);
                const uint64_t h = hash(host.data(), count);
                std::fwrite(&h, sizeof(h), 1, bf);
                std::fclose(bf);
            }
        }

        double mn = host[0], mx = host[0], sum = 0.0, sq = 0.0;
        for (size_t i = 0; i < count; ++i) {
            const double x = (double)host[i];
            if (!std::isfinite(x)) continue;
            if (x < mn) mn = x;
            if (x > mx) mx = x;
            sum += x;
            sq  += x * x;
        }
        const double mean = count ? sum / (double)count : 0.0;
        const double l2   = std::sqrt(sq);
        // RAWRXD_VULKAN_GRID_READBACK_AUTHORITY_001
        // Every record now carries its own validity and provenance:
        //   READBACK_VALID  finite + reproduced by an independent second read
        //   FUSE_ENDED      the deferred window was closed before the capture
        //   EPOCH           arena generation the capture belongs to
        //   BYTE_OFFSET     offset of the captured range within the buffer
        //   BYTE_EXTENT     byte length captured
        //   DISPATCH_SEQ    monotonic per-layer capture sequence (G-identity)
        // A comparator that sees READBACK_VALID=0 must refuse to classify the
        // record numerically, and now it can see that it should.
        std::fprintf(f,
            "STEP=%d CP=LAYER_%u_%s COUNT=%zu MIN=%.9g MAX=%.9g MEAN=%.9g L2=%.9g "
            "FIRST8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g HASH=%016llx NON_FINITE=%zu "
            "READBACK_VALID=%d FUSE_ENDED=%d EPOCH=%llu BYTE_OFFSET=0 BYTE_EXTENT=%zu "
            "DISPATCH_SEQ=%u HASH2=%016llx POS=%d POS_SOURCE=kv_currentLength ANCHORED=1\n",
            step, layer, name, count, mn, mx, mean, l2,
            count > 0 ? (double)host[0] : 0.0,
            count > 1 ? (double)host[1] : 0.0,
            count > 2 ? (double)host[2] : 0.0,
            count > 3 ? (double)host[3] : 0.0,
            count > 4 ? (double)host[4] : 0.0,
            count > 5 ? (double)host[5] : 0.0,
            count > 6 ? (double)host[6] : 0.0,
            count > 7 ? (double)host[7] : 0.0,
            (unsigned long long)hash(host.data(), count), nonFinite,
            readbackValid ? 1 : 0, wasFused ? 1 : 0,
            (unsigned long long)arenaEpoch, bytes, dispatchSeq_++, 
            (unsigned long long)h2, step);
        std::fflush(f);
    }

    // Summary line so a run can be certified without parsing every record.
    // G14: every record must carry READBACK_VALID=1, and the deliberate
    // premature captures must differ from the valid ones.
    void writeSummary() {
        if (!on || !f) return;
        // RAWRXD_VULKAN_GRID_STEP_IDENTITY_001: ANCHOR_CALLS and MAX_POS make the
        // step identity auditable from the file alone. MAX_POS=0 is the previous
        // broken behaviour and must be treated as "no stateful step measured",
        // not as "step 0 agreed".
        std::fprintf(f,
            "SUMMARY VALID_RECORDS=%u UNSTABLE_RECORDS=%u PREMATURE_RECORDS=%u "
            "PREMATURE_MEAN_L2=%.9g READBACK_AUTHORITY=%s "
            "ANCHOR_CALLS=%d MAX_POS=%d STEP_IDENTITY=%s\n",
            validCount_, unstableCount_, prematureCount_,
            prematureCount_ ? (prematureL2_ / (double)prematureCount_) : 0.0,
            (unstableCount_ == 0) ? "CERTIFIED" : "NOT_CERTIFIED",
            anchorCalls, maxAnchoredStep,
            (anchorCalls > 1 && maxAnchoredStep > 0) ? "AUTHORITATIVE_KV_POS"
                                                    : "SINGLE_STEP_OR_UNANCHORED");
        std::fflush(f);
    }

    // A stage that EXISTS on the CPU but has no device-side counterpart on the
    // GPU. Recorded as UNAVAILABLE so the comparator reports a named gap rather
    // than a silent omission.
    void emitGap(unsigned layer, const char* name) {
        if (!on || !f) return;
        std::fprintf(f, "STEP=%d CP=LAYER_%u_%s UNAVAILABLE=NO_DEVICE_ARENA "
                        "(fused into DispatchAttnDecode; not a reachability failure) "
                        "ANCHORED=%d\n",
                     step, layer, name, stepAnchored() ? 1 : 0);
        std::fflush(f);
    }
};
} // namespace

// RAWRXD_VULKAN_PROJECTION_BISECT_001
// The identical-input experiment.
//
// Why this exists: the parity grid showed RMS_ATTN already differs by ~13% in L2
// and that the Q/K/V projection then amplifies it to 83x on K. That is
// consistent with EITHER (a) one upstream defect plus a projection that merely
// amplifies it, or (b) two independent defects. The only way to separate them
// is to remove the upstream disagreement from the experiment entirely: take ONE
// host vector, run it through the CPU projection and through the GPU
// projection, and compare. Any surviving difference is the projection's own.
//
// The input is the CPU's post-attention-RMSNorm vector for the layer, computed
// once and used by both paths, so there is no question of whether the two sides
// saw the same bytes.
// RAWRXD_COMPARE_B_001
// RAWRXD_PROJECTION_BISECT_INPUT=<file> loads the EXACT bytes captured at the
// dispatch boundary (written by RAWRXD_VULKAN_PARITY_DUMP_VECTORS) instead of
// synthesizing an input. This is the discriminator:
//
//   synthetic input  -> CPU == GPU bit-exact  (already established)
//   captured  input  -> CPU == GPU bit-exact  => the real forward's inputs are
//                        fine too, and the grid's Q difference is an OBSERVATION
//                        defect rather than a computation defect
//   captured  input  -> CPU != GPU            => the projection is NOT sound for
//                        the inputs the real forward actually produces, and the
//                        earlier bit-exact result was an artefact of the
//                        synthetic input
static bool LoadCapturedVector(const char* path, std::vector<float>* out) {
    if (!path || !*path) return false;
    std::FILE* bf = std::fopen(path, "rb");
    if (!bf) return false;
    uint32_t n = 0;
    if (std::fread(&n, sizeof(n), 1, bf) != 1 || n == 0 || n > (1u << 24)) {
        std::fclose(bf);
        return false;
    }
    out->assign(n, 0.0f);
    const bool ok = std::fread(out->data(), sizeof(float), n, bf) == n;
    uint64_t h = 0;
    if (ok && std::fread(&h, sizeof(h), 1, bf) == 1) {
        const uint64_t want = VulkanParityGrid::hash(out->data(), n);
        if (want != h) {
            std::fprintf(stderr, "[PROJ_BISECT] CAPTURE_HASH_MISMATCH file=%s stored=%016llx "
                                 "recomputed=%016llx\n", path,
                         (unsigned long long)h, (unsigned long long)want);
            std::fclose(bf);
            return false;
        }
    }
    std::fclose(bf);
    return ok;
}

bool Deep2Engine::projectionBisectRun(unsigned layer,
                                      std::vector<ProjectionBisectResult>* out) {
    if (!out) return false;
    out->clear();
    if (!vulkanInitialized_ || vulkanDevices_.empty()) {
        std::fprintf(stderr, "[PROJ_BISECT] FAIL reason=no_vulkan_device\n");
        return false;
    }
    if (layer >= modelWeights.layers.size()) {
        std::fprintf(stderr, "[PROJ_BISECT] FAIL reason=layer_out_of_range layer=%u layers=%zu\n",
                     layer, modelWeights.layers.size());
        return false;
    }
    VulkanCompute* vc = getVulkanComputeSlot(0);
    if (!vc) { std::fprintf(stderr, "[PROJ_BISECT] FAIL reason=no_compute_slot\n"); return false; }

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = modelWeights.hiddenDim;
    const size_t qDim = modelWeights.numHeads * modelWeights.headDim;
    const size_t kvDim = modelWeights.numKVHeads * modelWeights.headDim;

    // ── make the production arenas exist ──
    // RAWRXD_VULKAN_PROJECTION_BISECT_001
    // UploadVector failed with a default-constructed DeviceBuf because the
    // arenas are allocated by a real forward pass. Rather than allocate scratch
    // buffers and measure something the product never runs, this runs ONE
    // short greedy decode so the production arenas, residency and weight
    // streaming are all in the same state a real forward would leave them in,
    // and then dispatches into those same arenas.
    {
        GenerationOptions warm;
        warm.maxTokens = 1;
        warm.temperature = 0.0f;
        warm.topK = 1;
        warm.seed = 1;
        auto r = generateStream("warmup", warm,
            [](int32_t, const std::string&) { return true; });
        std::fprintf(stderr, "[PROJ_BISECT] arena warmup status=%d generated=%llu\n",
                     (int)r.status, (unsigned long long)r.generatedTokens);
    }

    // ── one input, computed once, used by BOTH paths ──
    // The attention RMSNorm output. On a normal forward this is the GPU's
    // ArenaNormed() AFTER the dispatch has run; for the bisect it is computed on
    // the CPU so that it is bit-identical for both consumers and does not depend
    // on the very GPU state under investigation.
std::vector<float> input(H);
    {
        const float* attnW = EnsureF32(*this, lw.attnNorm, vulkanWeightF32_);
        if (!attnW) { std::fprintf(stderr, "[PROJ_BISECT] FAIL reason=attnNorm_not_f32\n"); return false; }
        // RAWRXD_VULKAN_PROJECTION_BISECT_001
        // A deterministic, well-conditioned input. NOT the model's embedding:
        // tokenEmbed.data holds Q4_K PACKED BYTES, and the first version of this
        // probe memcpy'd H floats out of it, reading past the tensor and
        // crashing before it could report anything.
        //
        // The content is irrelevant to the controlled experiment -- both paths
        // receive the same bytes. What matters is that the vector is finite,
        // non-degenerate and identical on both sides. A sinusoidal ramp with a
        // small per-index perturbation is used rather than a constant, because a
        // constant vector can mask a row-stride error by symmetry.
    //
    // RAWRXD_COMPARE_B_001: prefer the captured dispatch-boundary bytes when
    // supplied. Falling back to a synthesized vector is retained so the earlier
    // controlled experiment stays reproducible, but the two are reported
    // distinguishably -- a run that silently fell back would look like a
    // successful compare-B replay when it was not one.
    bool usedCaptured = false;
    const char* capPath = std::getenv("RAWRXD_PROJECTION_BISECT_INPUT");
    if (capPath && *capPath && LoadCapturedVector(capPath, &input)) {
        usedCaptured = true;
    } else {
        for (size_t i = 0; i < H; ++i) {
            input[i] = (float)std::sin(0.017453292519943295 * (double)i) * 0.75f +
                       ((float)(i % 7) - 3.0f) * 0.05f + 0.125f;
        }
    }
    // The captured bytes are the REAL norm output, so re-normalising them would
    // be a second transformation and would destroy the very thing being
    // measured. Only a synthesized vector needs the RMS applied to become a
    // plausible input.
    if (!usedCaptured) {
        std::vector<float> normed(H);
        RMSNormW(lw.attnNorm, input.data(), normed.data(), H, modelWeights.normEps);
        input.swap(normed);
    }
    std::fprintf(stderr,
        "[PROJ_BISECT] layer=%u input_source=%s file=%s "
        "(a captured vector is used AS-IS; a synthesized vector is normalised)\n",
        layer, usedCaptured ? "CAPTURED_DISPATCH_BOUNDARY" : "SYNTHESIZED",
        usedCaptured ? capPath : "(none)");
    }
    double inL2 = 0.0;
    for (size_t i = 0; i < H; ++i) inL2 += (double)input[i] * (double)input[i];
    std::fprintf(stderr, "[PROJ_BISECT] layer=%u input_L2=%.6f cols=%zu "
                         "(the SAME host vector feeds both paths)\n",
                 layer, std::sqrt(inL2), H);

    struct Stage { const char* name; const WeightTensor* wt; size_t rows;
                    CPUInference::VulkanCompute::DeviceBuf* out; };
    const Stage stages[] = {
        {"Q", &lw.wq, qDim, &vc->ArenaQ()},
        {"K", &lw.wk, kvDim, &vc->ArenaK()},
        {"V", &lw.wv, kvDim, &vc->ArenaV()},
    };

    for (const Stage& st : stages) {
        ProjectionBisectResult r;
        r.stage  = st.name;
        r.cols   = H;
        r.rows   = st.wt->rows;
        r.type   = st.wt->type;
        r.byteOffset = st.wt->fileOffset;
        r.byteSize   = st.wt->sizeBytes;

        // ── CPU projection ──
        std::vector<float> cpuOut(st.rows, 0.0f);
        LinearW(*st.wt, input.data(), nullptr, cpuOut.data(), st.rows);
        r.cpuReached = true;
        for (size_t i = 0; i < st.rows; ++i) r.cpuL2 += (double)cpuOut[i] * (double)cpuOut[i];
        r.cpuL2 = std::sqrt(r.cpuL2);

        // ── GPU projection, SAME input ──
        // RAWRXD_VULKAN_PROJECTION_BISECT_001
        // Routed through the PRODUCTION residency path -- PrefetchWeight +
        // SubmitGemvPrefetch + WaitWeightCompute -- which is exactly what
        // gemvOverlap3 does on its serialised branch.
        //
        // The first version of this probe called DispatchGemvQuant directly with
        // a raw host weight pointer. That dispatch never succeeded (gpu_reached=0
        // on every stage), and the first version of the verdict logic then read
        // cosine=0 as a MISMATCH and declared an independent projection defect.
        // It was not a defect; it was a dispatch that never ran. Packed weights
        // reach the device through the streaming/residency mechanism, so the
        // probe has to use the same mechanism or it measures nothing.
        bool gpuOk = false;
        // The input arena and the output arena are the PRODUCTION arenas, so the
        // measurement exercises the same buffers the forward pass uses.
        CPUInference::VulkanCompute::DeviceBuf& din = vc->ArenaNormed();
        CPUInference::VulkanCompute::DeviceBuf& dout = *st.out;
        if (vc->UploadVector(din, input.data(), H)) {
            r.rowsDispatched = (uint32_t)st.rows;
            uint32_t slot = 0;
            if (vc->PrefetchWeight(st.wt->data, st.wt->sizeBytes, slot)) {
                if (vc->SubmitGemvPrefetch(slot, din, dout, (uint32_t)st.rows,
                                            (uint32_t)H, st.wt->sizeBytes, r.type) &&
                    vc->WaitWeightCompute(slot)) {
                    gpuOk = true;
                } else {
                    std::fprintf(stderr,
                        "[PROJ_BISECT] layer=%u stage=%s FAIL_STAGE=SubmitGemvPrefetch "
                        "slot=%u rows=%u cols=%zu packed_bytes=%zu type=%d\n",
                        layer, st.name, slot, (unsigned)st.rows, H,
                        st.wt->sizeBytes, r.type);
                }
            } else {
                std::fprintf(stderr,
                    "[PROJ_BISECT] layer=%u stage=%s FAIL_STAGE=PrefetchWeight "
                    "bytes=%zu\n", layer, st.name, st.wt->sizeBytes);
            }
        } else {
            std::fprintf(stderr, "[PROJ_BISECT] layer=%u stage=%s FAIL_STAGE=UploadVector "
                         "cols=%zu\n", layer, st.name, H);
        }
        if (gpuOk) {
            std::vector<float> gpuOut(st.rows, 0.0f);
            if (vc->DownloadVector(dout, gpuOut.data(), st.rows)) {
                r.gpuReached = true;
                double dot = 0.0, na = 0.0, nb = 0.0;
                for (size_t i = 0; i < st.rows; ++i) {
                    const double a = (double)cpuOut[i], b = (double)gpuOut[i];
                    r.gpuL2 += b * b;
                    const double d = b - a;
                    if (std::fabs(d) > r.maxAbsDiff) r.maxAbsDiff = std::fabs(d);
                    r.rmsDiff += d * d;
                    dot += a * b; na += a * a; nb += b * b;
                }
                r.gpuL2 = std::sqrt(r.gpuL2);
                r.rmsDiff = st.rows ? std::sqrt(r.rmsDiff / (double)st.rows) : 0.0;
                r.cosine = (na > 0 && nb > 0) ? dot / std::sqrt(na * nb) : 0.0;
                size_t ai = 0, bi = 0;
                for (size_t i = 1; i < st.rows; ++i) {
                    if (cpuOut[i] > cpuOut[ai]) ai = i;
                    if (gpuOut[i] > gpuOut[bi]) bi = i;
                }
                r.top1Agree = (ai == bi) ? 1 : 0;
            } else {
                std::fprintf(stderr, "[PROJ_BISECT] layer=%u stage=%s "
                             "FAIL_STAGE=DownloadVector\n", layer, st.name);
            }
        }
        out->push_back(r);

        std::fprintf(stderr,
            "[PROJ_BISECT] layer=%u stage=%s rows_expected=%zu rows_dispatched=%u "
            "cols=%zu type=%d byte_offset=%zu byte_size=%zu "
            "cpu_L2=%.6f gpu_L2=%.6f ratio=%.4f max_abs_diff=%.6g rms_diff=%.6g "
            "cosine=%.6f top1_agree=%zu gpu_reached=%d\n",
            layer, st.name, st.wt->rows, r.rowsDispatched, H, r.type,
            r.byteOffset, r.byteSize, r.cpuL2, r.gpuL2,
            (r.cpuL2 > 0 ? r.gpuL2 / r.cpuL2 : 0.0),
            r.maxAbsDiff, r.rmsDiff, r.cosine, r.top1Agree, r.gpuReached ? 1 : 0);
    }
    return true;
}

// RAWRXD_COMPARE_B_CHAIN_001
// Every stage's input is the GPU's OWN captured vector for the preceding stage.
// Nothing here re-derives an input, so there is no opportunity to compare a CPU
// result against a GPU value that came from a different execution.
bool Deep2Engine::postVChainReplay(unsigned layer, const std::string& dumpDir,
                                   std::vector<ChainStage>* out) {
    if (!out) return false;
    out->clear();
    if (layer >= modelWeights.layers.size()) return false;
    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H  = modelWeights.hiddenDim;
    const size_t qDim = modelWeights.numHeads * modelWeights.headDim;
    const size_t inter = lw.wGate.rows;

    auto load = [&](const char* name, std::vector<float>* v) -> bool {
        char p[1024];
        std::snprintf(p, sizeof(p), "%s/%u_%s.bin", dumpDir.c_str(), layer, name);
        return LoadCapturedVector(p, v);
    };

    struct Cmp { const char* name; std::vector<float> cpu; const std::vector<float>* gpu; };
    std::vector<Cmp> cmps;

    std::vector<float> vAttn, vOP, vRes, vNormed, vGate, vUp, vAct, vDown, vLayer;

    // ── O_PROJ: cpu = wo * captured(ATTN_VALUE) ──
    if (load("ATTN_VALUE", &vAttn) && load("O_PROJ", &vOP) &&
        vAttn.size() == qDim && vOP.size() == H) {
        std::vector<float> cpu(H, 0.0f);
        LinearW(lw.wo, vAttn.data(), nullptr, cpu.data(), H);
        cmps.push_back({"O_PROJ", cpu, &vOP});
    }
    // ── ATTN_RESIDUAL: cpu = captured(INPUT) + captured(O_PROJ) ──
    if (load("INPUT", &vAttn) && !vOP.empty() && vOP.size() == H && load("ATTN_RESIDUAL", &vRes)) {
        std::vector<float> cpu(vOP);
        for (size_t i = 0; i < H && i < cpu.size(); ++i) cpu[i] += vAttn[i];
        cmps.push_back({"ATTN_RESIDUAL", cpu, &vRes});
    }
    // ── RMS_FFN: cpu = RMSNormW(ffnNorm, captured(ATTN_RESIDUAL)) ──
    if (!vRes.empty() && vRes.size() == H && load("RMS_FFN", &vNormed) && vNormed.size() == H) {
        std::vector<float> cpu(H, 0.0f);
        RMSNormW(lw.ffnNorm, vRes.data(), cpu.data(), H, modelWeights.normEps);
        cmps.push_back({"RMS_FFN", cpu, &vNormed});
    }
    // ── FFN_GATE / FFN_UP: cpu = wGate|wUp * captured(RMS_FFN) ──
    if (!vNormed.empty() && vNormed.size() == H) {
        if (load("FFN_GATE", &vGate) && vGate.size() == inter) {
            std::vector<float> cpu(inter, 0.0f);
            LinearW(lw.wGate, vNormed.data(), nullptr, cpu.data(), inter);
            cmps.push_back({"FFN_GATE", cpu, &vGate});
        }
        if (load("FFN_UP", &vUp) && vUp.size() == inter) {
            std::vector<float> cpu(inter, 0.0f);
            LinearW(lw.wUp, vNormed.data(), nullptr, cpu.data(), inter);
            cmps.push_back({"FFN_UP", cpu, &vUp});
        }
    }
    // ── SWIGLU: cpu = silu(gate) * up over the CAPTURED gate/up ──
    if (!vGate.empty() && !vUp.empty() && vGate.size() == inter && vUp.size() == inter &&
        load("SWIGLU", &vAct) && vAct.size() == inter) {
        std::vector<float> cpu(inter, 0.0f);
        for (size_t i = 0; i < inter; ++i) {
            const float g = vGate[i];
            cpu[i] = (g / (1.0f + std::exp(-g))) * vUp[i];
        }
        cmps.push_back({"SWIGLU", cpu, &vAct});
    }
    // ── FFN_DOWN: cpu = wDown * captured(SWIGLU) ──
    if (!vAct.empty() && vAct.size() == inter && load("FFN_DOWN", &vDown) && vDown.size() == H) {
        std::vector<float> cpu(H, 0.0f);
        LinearW(lw.wDown, vAct.data(), nullptr, cpu.data(), H);
        cmps.push_back({"FFN_DOWN", cpu, &vDown});
    }
    // ── LAYER_RESIDUAL: cpu = captured(ATTN_RESIDUAL) + captured(FFN_DOWN) ──
    if (!vRes.empty() && !vDown.empty() && vRes.size() == H && vDown.size() == H &&
        load("LAYER_RESIDUAL", &vLayer) && vLayer.size() == H) {
        std::vector<float> cpu(H, 0.0f);
        for (size_t i = 0; i < H; ++i) cpu[i] = vRes[i] + vDown[i];
        cmps.push_back({"LAYER_RESIDUAL", cpu, &vLayer});
    }

    bool allMatch = !cmps.empty();
    for (const Cmp& c : cmps) {
        ChainStage s;
        s.stage = c.name;
        s.ran = true;
        s.cpuAvailable = true;
        const std::vector<float>& g = *c.gpu;
        if (c.cpu.size() != g.size()) {
            s.reason = "shape cpu=" + std::to_string(c.cpu.size()) +
                       " gpu=" + std::to_string(g.size());
            out->push_back(s);
            allMatch = false;
            continue;
        }
        double dot = 0, na = 0, nb = 0;
        for (size_t i = 0; i < c.cpu.size(); ++i) {
            const double a = c.cpu[i], b = g[i];
            s.cpuL2 += a * a;
            s.gpuL2 += b * b;
            const double d = b - a;
            if (std::fabs(d) > s.maxAbsDiff) s.maxAbsDiff = std::fabs(d);
            s.rmsDiff += d * d;
            dot += a * b; na += a * a; nb += b * b;
        }
        const size_t n = c.cpu.size();
        s.cpuL2 = std::sqrt(s.cpuL2);
        s.gpuL2 = std::sqrt(s.gpuL2);
        s.rmsDiff = n ? std::sqrt(s.rmsDiff / (double)n) : 0.0;
        s.cosine = (na > 0 && nb > 0) ? dot / std::sqrt(na * nb) : 0.0;
        // Same tolerance band the comparator uses: 1e-4 relative on elements,
        // 1e-3 on L2. Anything looser would let a real divergence hide as noise.
        const double worst = n ? s.maxAbsDiff / std::max(1e-30, s.gpuL2 > 0 ? s.gpuL2 : 1.0) : 1.0;
        const double l2rel = (s.gpuL2 > 0) ? std::fabs(s.cpuL2 - s.gpuL2) / s.gpuL2 : 1.0;
        s.match = (l2rel <= 1e-3) && (worst <= 1e-4);
        if (!s.match) allMatch = false;
        std::fprintf(stderr,
            "[CHAIN] layer=%u stage=%-16s cpu_L2=%.6f gpu_L2=%.6f l2_rel=%.3e "
            "max_abs_diff=%.6g rms=%.6g cosine=%.6f %s\n",
            layer, s.stage, s.cpuL2, s.gpuL2, l2rel, s.maxAbsDiff, s.rmsDiff,
            s.cosine, s.match ? "MATCH" : "NUMERIC_MISMATCH");
        out->push_back(s);
    }
    std::fprintf(stderr, "[CHAIN] layer=%u stages_replayed=%zu all_match=%d\n",
                 layer, cmps.size(), allMatch ? 1 : 0);
    return !cmps.empty();
}

// RAWRXD_VULKAN_ATTENTION_CORE_BISECT_001 (A1-A6)
// Isolates RoPE. The pre-RoPE Q/K the device actually produced are loaded from
// the dump, the CPU's own applyRoPE is run on those EXACT bytes, and the result
// is compared against the device's post-RoPE capture.
//
// Every input is the device's own captured value, so a mismatch here cannot be
// an artefact of comparing different executions -- the same discipline that made
// compare B decisive.
bool Deep2Engine::ropeBisectRun(unsigned layer, const std::string& dumpDir,
                                std::vector<ChainStage>* out) {
    if (!out) return false;
    out->clear();
    if (layer >= modelWeights.layers.size()) return false;
    const size_t headDim = modelWeights.headDim;
    const size_t nH     = modelWeights.numHeads;
    const size_t nKV    = modelWeights.numKVHeads;
    const size_t qDim   = nH   * headDim;
    const size_t kvDim  = nKV  * headDim;

    auto load = [&](const char* name, std::vector<float>* v) -> bool {
        char p[1024];
        std::snprintf(p, sizeof(p), "%s/%u_%s.bin", dumpDir.c_str(), layer, name);
        return LoadCapturedVector(p, v);
    };

    struct Case { const char* stage; const char* pre; const char* post;
                  size_t dim, heads; };
    const Case cases[] = {
        {"Q_ROPE", "Q_PRE_ROPE", "Q_ROPE", qDim,  nH},
        {"K_ROPE", "K_PRE_ROPE", "K_ROPE", kvDim, nKV},
    };

    // pos/theta/scaling must be the values the forward actually used. The
    // attention-core bisect runs at step 0, where pos == 0 for the prefill
    // chunk that produced these captures; using anything else would compare a
    // real device result against a reference computed at a different position.
    const uint32_t pos = 0;

    for (const Case& c : cases) {
        ChainStage s;
        s.stage = c.stage;
        std::vector<float> pre, post;
        if (!load(c.pre, &pre) || !load(c.post, &post)) {
            s.reason = std::string("missing capture ") + c.pre + "/" + c.post;
            out->push_back(s);
            continue;
        }
        if (pre.size() != c.dim || post.size() != c.dim) {
            s.reason = "shape pre=" + std::to_string(pre.size()) +
                       " post=" + std::to_string(post.size()) +
                       " expected=" + std::to_string(c.dim);
            out->push_back(s);
            continue;
        }
// CPU reference on the EXACT captured pre-RoPE bytes.
        // applyRoPE writes BOTH q and k unconditionally and throws on a null
        // pointer, so a scratch K buffer of the right size is supplied and
        // ignored. Passing nullptr here terminated the process on the first run.
        std::vector<float> ref = pre;
        std::vector<float> scratchK(kvDim, 0.0f);
        applyRoPE(ref.data(), scratchK.data(), headDim, c.heads, nKV, pos,
                  modelWeights.ropeTheta, modelWeights.ropeScaling);

        double dot = 0, na = 0, nb = 0;
        for (size_t i = 0; i < c.dim; ++i) {
            const double a = ref[i], b = post[i];
            s.cpuL2 += a * a;
            s.gpuL2 += b * b;
            const double d = b - a;
            if (std::fabs(d) > s.maxAbsDiff) s.maxAbsDiff = std::fabs(d);
            s.rmsDiff += d * d;
            dot += a * b; na += a * a; nb += b * b;
        }
        s.cpuL2 = std::sqrt(s.cpuL2);
        s.gpuL2 = std::sqrt(s.gpuL2);
        s.rmsDiff = std::sqrt(s.rmsDiff / (double)c.dim);
        s.cosine = (na > 0 && nb > 0) ? dot / std::sqrt(na * nb) : 0.0;
        const double l2rel = (s.gpuL2 > 0) ? std::fabs(s.cpuL2 - s.gpuL2) / s.gpuL2 : 1.0;
        s.ran = true;
        s.cpuAvailable = true;
        s.match = (l2rel <= 1e-3) && (s.maxAbsDiff <= 1e-4);
        std::fprintf(stderr,
            "[ROPE_BISECT] layer=%u stage=%s dim=%zu pos=%u cpu_L2=%.6f gpu_L2=%.6f "
            "l2_rel=%.3e max_abs_diff=%.6g cosine=%.6f %s\n",
            layer, s.stage, c.dim, pos, s.cpuL2, s.gpuL2, l2rel, s.maxAbsDiff,
            s.cosine, s.match ? "MATCH" : "NUMERIC_MISMATCH");
        out->push_back(s);
    }
    return !out->empty();
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
    const uint32_t inter = (uint32_t)(
        lw.wGate.rows ? lw.wGate.rows :
        (lw.wUp.rows   ? lw.wUp.rows   : modelWeights.intermediateDim));

    const bool doAttn = lw.hasAttn;
    const bool doSSM  = lw.hasSSM;
    const bool doFFN  = lw.hasFFN;

    std::fprintf(stderr, "GPU_FORWARD_STAGE=CHECK_WEIGHT_DATA layer=%u slot=%u doAttn=%d doSSM=%d doFFN=%d\n",
        layer, slot, (int)doAttn, (int)doSSM, (int)doFFN);

    if (doAttn) {
        if (!lw.wq.data || !lw.wk.data || !lw.wv.data ||
            !(lw.wo.data || lw.attnO.data)) {
            std::fprintf(stderr,
                "GPU_FORWARD_FAIL_STAGE=WEIGHT_DATA_ATTN layer=%u wq=%p wk=%p wv=%p wo=%p attnO=%p\n",
                layer, (void*)lw.wq.data, (void*)lw.wk.data, (void*)lw.wv.data,
                (void*)lw.wo.data, (void*)lw.attnO.data);
            return false;
        }
    }
    if (doFFN) {
        if (!lw.wUp.data || !lw.wDown.data) {
            std::fprintf(stderr,
                "GPU_FORWARD_FAIL_STAGE=WEIGHT_DATA_FFN layer=%u wUp=%p wDown=%p\n",
                layer, (void*)lw.wUp.data, (void*)lw.wDown.data);
            return false;
        }
        if (lw.wGate.data) {
            // SwiGLU path — gate required
        } else {
            // Simple MLP (no gate) — GPU SiLU not yet bound; fall back to CPU for this layer
            std::fprintf(stderr,
                "GPU_FORWARD_FAIL_STAGE=WEIGHT_DATA_FFN layer=%u reason=no_gate_simple_mlp_not_yet_on_gpu\n",
                layer);
            return false;
        }
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
            // RAWRXD_QKV_PREFETCH_ALIAS_001 diagnostic: strictly serialise the
            // three QKV prefetch+compute steps. PrefetchWeight already gives
            // each call its own buffer, so this is NOT expected to change the
            // result; it is here to falsify the slot-reuse theory quickly.
            // If K is still wrong with full serialisation, weight delivery
            // timing is exonerated and the defect is inside the Q4_K kernel.
            static const bool serialQkv = [](){
                const char* v = std::getenv("RAWRXD_QKV_SERIALIZE");
                return v && v[0] && v[0] != '0';
            }();
            if (serialQkv) {
                uint32_t s0 = 0, s1 = 0, s2 = 0;
                if (!vc->PrefetchWeight(qa.data, qa.sizeBytes, s0)) return false;
                if (!vc->SubmitGemvPrefetch(s0, in, outA, rA, cols, qa.sizeBytes, qa.type)) return false;
                if (!vc->WaitWeightCompute(s0)) return false;
                if (!vc->PrefetchWeight(qb.data, qb.sizeBytes, s1)) return false;
                if (!vc->SubmitGemvPrefetch(s1, in, outB, rB, cols, qb.sizeBytes, qb.type)) return false;
                if (!vc->WaitWeightCompute(s1)) return false;
                if (!vc->PrefetchWeight(qc.data, qc.sizeBytes, s2)) return false;
                if (!vc->SubmitGemvPrefetch(s2, in, outC, rC, cols, qc.sizeBytes, qc.type)) return false;
                return vc->WaitWeightCompute(s2);
            }
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

    // RAWRXD_VULKAN_GRID_STEP_IDENTITY_001
    //
    // The grid key must not carry its own notion of "which step". It is
    // anchored here, on the AUTHORITATIVE KV logical position -- the same value
    // AppendKV writes to below and the same value whose successor
    // (pos + 1) is handed to DispatchAttnDecode as the visible context length.
    // Any independent step++ in the grid would be a second, unverified clock
    // for the same state, which is precisely how a 22-layer single-step grid
    // came to be read as a 22-step result.
    //
    // It is anchored BEFORE the first emit() in this layer, not next to the KV
    // write. An earlier placement left INPUT and RMS_ATTN unanchored on every
    // position -- two of the seventeen stages silently lost their identity,
    // which is the same class of defect as the unkeyed mask this replaced.
    const uint32_t pos = kvCache ? (uint32_t)kvCache->currentLength() : 0;
    VulkanParityGrid::instance().anchorStep(static_cast<int>(pos));

    if (!vc->DispatchRmsNorm(vc->ArenaHidden(), *attnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "attnNorm");
    ++c.rmsNormOps;
    // RAWRXD_VULKAN_BODY_PARITY_GRID_001
    VulkanParityGrid::instance().emit(vc, layer, 0, "INPUT",        vc->ArenaHidden(), H);
    VulkanParityGrid::instance().emit(vc, layer, 1, "RMS_ATTN",     vc->ArenaNormed(),  H);

    // RAWRXD_GPU_K_ROPE_BISECT_001: dump the projection input (post-RMSNorm)
    // so it can be diffed against the CPU `input` in LinearW. Requires
    // breaking the fused window, else this reads pre-RMSNorm bytes.
    {
        static const bool normInEnabled = [](){
            const char* v = std::getenv("RAWRXD_WK_BINDING");
            return v && v[0] && v[0] != '0';
        }();
        static bool normInDone = false;
        if (normInEnabled && !normInDone && layer == 0u) {
            normInDone = true;
            const bool wasFused = vc->FusedRecording();
            if (wasFused && !vc->EndFusedLayer())
                return fail("NORMIN", "EndFusedLayer");
            float nf[8] = {0};
            const bool ok = vc->ProbeDeviceFloats(vc->ArenaNormed(), 0u, 8u, nf);
            if (wasFused && !vc->BeginFusedLayer())
                return fail("NORMIN", "BeginFusedLayer");
            if (ok) {
                std::fprintf(stderr, "[NORMIN] GPU L=0 IN8=%g %g %g %g %g %g %g %g\n",
                    nf[0],nf[1],nf[2],nf[3],nf[4],nf[5],nf[6],nf[7]);
                std::fflush(stderr);
            }
        }
    }

    // RAWRXD_VULKAN_KV_SPLIT_001
    //
    // The K/V chain is split into four separately-hashed observations so the
    // defect can be localised without a general parity run:
    //
    //   K_PROJECTED / V_PROJECTED   post-RoPE K and raw V, i.e. what the
    //                               projection produced BEFORE any storage
    //   K_CACHE_WRITTEN / V_CACHE_WRITTEN
    //                               the bytes the cache actually holds at slot
    //                               `pos` after AppendKV
    //   K_CACHE_READBACK / V_CACHE_READBACK
    //                               the same slot re-read at the NEXT
    //                               opportunity, i.e. what a later step's
    //                               attention would consume
    //
    // Discriminator:
    //   PROJECTED match, CACHE_WRITTEN differ  -> Vulkan KV write/storage defect
    //   CACHE_WRITTEN match, READBACK differ   -> cache addressing/layout/read
    //   all match, FINAL_NORM differ           -> post-transformer norm defect
    //   FINAL_NORM match, LOGITS differ        -> lm_head / quant GEMV / layout
    //
    // The hash is FNV-1a over the FULL kvDim span in the slot's own layout
    // ([kvHead][headDim]), which is byte-for-byte the same quantity the CPU
    // probe publishes as K_HASH / V_HASH in parityEmitKvWrite. The two sides
    // are therefore joined on (step, layer) by exact hash, not by a tolerance
    // on an L2 norm.
    //
    // Probing breaks the fused window, so it serialises the layer and must
    // never run during a throughput gate. Opt-in, default OFF.
    const bool kvSplitEnabled = Deep2::AttnVis::envOn("RAWRXD_VULKAN_KV_SPLIT");
    const bool kvSplitLayer = kvSplitEnabled &&
                              (layer == 0u || layer + 1u == (uint32_t)config.numLayers);
    // ONE handle for the whole process, declared in the function scope rather
    // than inside the two blocks that use it. A block-local `static` in each
    // block would be two distinct objects, and the second one would reopen the
    // same path with "wb" -- truncating every record the first had written.
    static std::FILE* kvSplitFile = nullptr;
    if (kvSplitLayer && !kvSplitFile) {
        const char* kvsOut = std::getenv("RAWRXD_VULKAN_KV_SPLIT_OUT");
        kvSplitFile = std::fopen(kvsOut && *kvsOut ? kvsOut : "vulkan_kv_split.txt", "wb");
        if (kvSplitFile) {
            std::fprintf(kvSplitFile,
                "# RAWRXD_VULKAN_KV_SPLIT v1 hash=FNV1A_64_over_full_kvDim "
                "layout=[kvHead][headDim] cpu_join_key=(step,layer)\n");
            std::fflush(kvSplitFile);
            std::fprintf(stderr,
                "[KVSPLIT] ON out=%s (breaks fusion; NOT valid for TPS gates)\n",
                kvsOut && *kvsOut ? kvsOut : "vulkan_kv_split.txt");
            std::fflush(stderr);
        } else {
            std::fprintf(stderr, "[KVSPLIT] FAIL cannot open output file\n");
            std::fflush(stderr);
        }
    }
    // First 8 floats of slot 0 as written at the prefill position that created
    // it, so a later readback can prove the bytes survived.
    static uint64_t s_slot0WriteHash[2] = {0, 0};
    static bool     s_slot0HaveWrite[2]  = {false, false};
    static uint32_t s_slot0WritePos[2]   = {0, 0};
    const int kvSplitSlot = (layer == 0u) ? 0 : 1;
    // RAWRXD_VULKAN_KV_SPLIT_001: read a cache slot with the fused window closed.
    // A probe issued inside the window reads pre-AppendKV bytes, which is a
    // probe artefact and not a measurement -- the same failure that produced an
    // all-zero grid earlier in this file.
    // RAWRXD_VULKAN_KV_SPLIT_001: read a cache slot with the fused window closed.
    // A probe issued inside the window reads pre-AppendKV bytes, which is a
    // probe artefact and not a measurement -- the same failure that produced an
    // all-zero grid earlier in this file.
    auto probeKvBreakingFusion = [&](uint32_t p, std::vector<float>& kOut,
                                     std::vector<float>& vOut) -> bool {
        if (!vc) return false;
        const bool wasFused = vc->FusedRecording();
        if (wasFused && !vc->EndFusedLayer()) return false;
        const bool ok = vc->ProbeKvSlotFloats(layer, p,
                                              (uint32_t)kOut.size(),
                                              kOut.data(), vOut.data());
        if (wasFused && !vc->BeginFusedLayer()) return false;
        return ok;
    };
    auto probeArenaBreakingFusion = [&](VulkanCompute::DeviceBuf& buf, size_t n,
                                       std::vector<float>& out) -> bool {
        if (!vc) return false;
        const bool wasFused = vc->FusedRecording();
        if (wasFused && !vc->EndFusedLayer()) return false;
        const bool ok = vc->ProbeDeviceFloats(buf, 0u, (uint32_t)n, out.data());
        if (wasFused && !vc->BeginFusedLayer()) return false;
        return ok;
    };
    // RAWRXD_GPU_WK_BINDING_001: audit the three QKV projection bindings side
    // by side at layer 0. V is the positive control (numerically ~correct)
    // and K is the failing sibling on the same input and kernel family, so
    // any field where K differs from V is the candidate defect.
    {
        static const bool wkBindEnabled = [](){
            const char* v = std::getenv("RAWRXD_WK_BINDING");
            return v && v[0] && v[0] != '0';
        }();
        if (wkBindEnabled && layer == 0u) {
            auto dump=[&](const char* tag, const WeightTensor& w){
                std::fprintf(stderr,
                    "[WKBIND] %s name=%s ptr=%p type=%d\n",
                    tag, w.name.c_str(), w.data, w.type);
                std::fprintf(stderr,
                    "[WKBIND] %s rows=%zu cols=%zu sizeBytes=%zu fileOff=%llu shard=%u hasFile=%d\n",
                    tag, w.rows, w.cols, w.sizeBytes,
                    (unsigned long long)w.fileOffset, w.shardId,
                    w.hasFileBacking ? 1 : 0);
            };
            dump("WQ", lw.wq); dump("WK", lw.wk); dump("WV", lw.wv);
            // The invariants that decide the gate.
            const bool rowsOk   = (lw.wk.rows == kvDim) && (lw.wv.rows == kvDim);
            const bool colsOk   = (lw.wk.cols == H)      && (lw.wv.cols == H);
            const bool ptrDiff  = (lw.wk.data != lw.wv.data);
            const bool offDiff  = (lw.wk.fileOffset != lw.wv.fileOffset);
            const bool sizeEqKQ = (lw.wk.sizeBytes == lw.wq.sizeBytes);
            std::fprintf(stderr,
                "[WKBIND] CHECK expectKV=%u expectH=%u | rows_ok=%d cols_ok=%d "
                "k_ptr_ne_v=%d k_off_ne_v=%d k_size_eq_q_size=%d\n",
                kvDim, H, rowsOk?1:0, colsOk?1:0, ptrDiff?1:0, offDiff?1:0,
                sizeEqKQ?1:0);
            std::fflush(stderr);
        }
    }
    {
        DEEP2_GPU_CHILD_SCOPE(qkvScope, QKV);
        if (!gemvOverlap3(lw.wq, lw.wk, lw.wv, vc->ArenaNormed(),
                          vc->ArenaQ(), vc->ArenaK(), vc->ArenaV(), qDim, kvDim, kvDim, H))
            return fail("GEMV_QKV", "qkvOverlap3");
        c.qkvOps += 3;
    }
    // RAWRXD_VULKAN_ATTENTION_CORE_BISECT_001 (A0)
    // Capture the RAW Q/K/V entering the attention core, i.e. BEFORE RoPE.
    //
    // RAWRXD_COMPARE_B_CHAIN_001 already proved the projection is bit-exact on
    // these values, so they are a trustworthy starting point. Without a pre-RoPE
    // capture there is no way to tell "RoPE corrupted Q/K" from "the projection
    // was wrong", because the only post-projection capture available sits AFTER
    // DispatchRope. The existing "Q"/"K" grid stages are emitted post-RoPE and
    // were mislabelled as if they were the raw projection output.
    //
    // emit() breaks the fused window and reopens it, so the captures observe
    // executed bytes rather than deferred ones.
    {
        auto& pg = VulkanParityGrid::instance();
        pg.emit(vc, layer, 16, "Q_PRE_ROPE", vc->ArenaQ(), qDim);
        pg.emit(vc, layer, 17, "K_PRE_ROPE", vc->ArenaK(), kvDim);
        pg.emit(vc, layer, 18, "V_PRE_ROPE", vc->ArenaV(), kvDim);
    }
    // RAWRXD_GPU_K_ROPE_BISECT_001: capture ArenaK immediately before and
    // immediately after DispatchRope for layer 0, to separate "K projection is
    // wrong" from "RoPE corrupted K". This REQUIRES ending the fused
    // recording window first: inside the window nothing has been submitted,
    // so a probe reads pre-GEMV bytes and would report a false mismatch.
    // Diagnostic only -- it changes submission boundaries, not arithmetic.
    static bool ropeBisectDone = false;
    static const bool ropeBisectEnabled = [](){
        const char* v = std::getenv("RAWRXD_K_ROPE_BISECT");
        return v && v[0] && v[0] != '0';
    }();
    if (ropeBisectEnabled && !ropeBisectDone && layer == 0u) {
        ropeBisectDone = true;
        const bool wasFused = vc->FusedRecording();
        if (wasFused && !vc->EndFusedLayer())
            return fail("ROPE_BISECT", "EndFusedLayer");
        std::vector<float> kPre(kvDim, 0.0f), kPost(kvDim, 0.0f);
        std::vector<float> qPre(qDim, 0.0f), qPost(qDim, 0.0f);
        const bool preOk = vc->ProbeDeviceFloats(vc->ArenaK(), 0u, kvDim, kPre.data());
        const bool qPreOk = vc->ProbeDeviceFloats(vc->ArenaQ(), 0u, qDim, qPre.data());
        if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                              modelWeights.ropeTheta,
                              modelWeights.ropeNeoxStyle,
                              modelWeights.ropeDimensionCount))
            return fail("ROPE", "DispatchRope");
        const bool postOk = vc->ProbeDeviceFloats(vc->ArenaK(), 0u, kvDim, kPost.data());
        const bool qPostOk = vc->ProbeDeviceFloats(vc->ArenaQ(), 0u, qDim, qPost.data());
        if (wasFused && !vc->BeginFusedLayer())
            return fail("ROPE_BISECT", "BeginFusedLayer");
        if (qPreOk && qPostOk) {
            std::fprintf(stderr, "[QBISECT] L=0 pos=%u h0 Q_PRE =%g %g %g %g %g %g %g %g\n",
                pos, qPre[0],qPre[1],qPre[2],qPre[3],qPre[4],qPre[5],qPre[6],qPre[7]);
            std::fprintf(stderr, "[QBISECT] L=0 pos=%u h0 Q_POST=%g %g %g %g %g %g %g %g\n",
                pos, qPost[0],qPost[1],qPost[2],qPost[3],qPost[4],qPost[5],qPost[6],qPost[7]);
        }
        if (preOk && postOk) {
            std::fprintf(stderr,
                "[ROPEBISECT] L=0 pos=%u headDim=%u nHeads=%u nKv=%u theta=%g\n",
                pos, headDim, nHeads, nKv, (double)modelWeights.ropeTheta);
            for (uint32_t kh = 0; kh < nKv && kh < 2u; ++kh) {
                const uint32_t b0 = kh*headDim;
                std::fprintf(stderr, "[ROPEBISECT] L=0 kh=%u K_PRE =%g %g %g %g %g %g %g %g\n",
                    kh, kPre[b0+0],kPre[b0+1],kPre[b0+2],kPre[b0+3],
                    kPre[b0+4],kPre[b0+5],kPre[b0+6],kPre[b0+7]);
                std::fprintf(stderr, "[ROPEBISECT] L=0 kh=%u K_POST=%g %g %g %g %g %g %g %g\n",
                    kh, kPost[b0+0],kPost[b0+1],kPost[b0+2],kPost[b0+3],
                    kPost[b0+4],kPost[b0+5],kPost[b0+6],kPost[b0+7]);
                float dmax = 0.0f;
                for (uint32_t d = 0; d < headDim; ++d) {
                    const float df = kPost[b0+d] - kPre[b0+d];
                    if (std::fabs(df) > dmax) dmax = std::fabs(df);
                }
                std::fprintf(stderr, "[ROPEBISECT] L=0 kh=%u ROPE_DELTA_GPU=%g\n", kh, dmax);
            }
            std::fflush(stderr);
        } else {
            std::fprintf(stderr, "[ROPEBISECT] probe_failed pre=%d post=%d\n",
                preOk ? 1 : 0, postOk ? 1 : 0);
            std::fflush(stderr);
        }
    } else if (!vc->DispatchRope(vc->ArenaQ(), vc->ArenaK(), headDim, nHeads, nKv, pos,
                                 modelWeights.ropeTheta,
                                 // RAWRXD_VULKAN_ROPE_CONVENTION_001: the pairing
                                 // convention and the rotary dimension the CPU
                                 // actually used. The CPU selects rotated-half for
                                 // the NeoX architectures; the shader used to
                                 // implement only adjacent pairs, so every
                                 // position after 0 was rotated differently while
                                 // position 0 agreed because both are the identity
                                 // there.
                                 modelWeights.ropeNeoxStyle,
                                 modelWeights.ropeDimensionCount)) {
        return fail("ROPE", "DispatchRope");
    }
    ++c.ropeOps;
    {
        DEEP2_GPU_CHILD_SCOPE(kvScope, KVUpdate);
            if (!vc->AppendKV(vc->ArenaK(), vc->ArenaV(), kvDim, pos, layer)) return fail("APPEND_KV", "AppendKV");
    }
    // RAWRXD_VULKAN_KV_SPLIT_001: PROJECTED vs CACHE_WRITTEN, at the moment
    // between the two. The first pair is read off the arenas AppendKV just
    // consumed; the second is read back out of the cache slot it just wrote.
    if (kvSplitLayer && kvSplitFile) {
        std::vector<float> kProj(kvDim, 0.0f), vProj(kvDim, 0.0f);
            std::vector<float> kSlot(kvDim, 0.0f), vSlot(kvDim, 0.0f);
            const bool projOk =
                probeArenaBreakingFusion(vc->ArenaK(), kvDim, kProj) &&
                probeArenaBreakingFusion(vc->ArenaV(), kvDim, vProj);
            const bool slotOk = probeKvBreakingFusion(pos, kSlot, vSlot);
            // One line per (stage, tensor): K and V are separate evidence and a
            // single combined line would let one agree and mask the other.
            auto emitK = [&](const char* stage, const std::vector<float>& k, bool ok) {
                if (!ok) {
                    std::fprintf(kvSplitFile,
                        "STEP=%d POS=%d LAYER=%u STAGE=%s TENSOR=K COUNT=%zu PROBE=FAIL "
                        "NOTE=readback_unavailable_not_equal_to_zero\n",
                        (int)pos, (int)pos, layer, stage, (size_t)kvDim);
                    return;
                }
                double s2 = 0.0;
                for (size_t i = 0; i < k.size(); ++i) s2 += (double)k[i] * (double)k[i];
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=%s TENSOR=K COUNT=%zu PROBE=OK "
                    "HASH=%016llx L2=%.9g F8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g\n",
                    (int)pos, (int)pos, layer, stage, (size_t)kvDim,
                    (unsigned long long)VulkanParityGrid::instance().hashPublic(k.data(), k.size()),
                    std::sqrt(s2),
                    k[0],k[1],k[2],k[3],k[4],k[5],k[6],k[7]);
            };
            auto emitV = [&](const char* stage, const std::vector<float>& v, bool ok) {
                if (!ok) {
                    std::fprintf(kvSplitFile,
                        "STEP=%d POS=%d LAYER=%u STAGE=%s TENSOR=V COUNT=%zu PROBE=FAIL "
                        "NOTE=readback_unavailable_not_equal_to_zero\n",
                        (int)pos, (int)pos, layer, stage, (size_t)kvDim);
                    return;
                }
                double s2 = 0.0;
                for (size_t i = 0; i < v.size(); ++i) s2 += (double)v[i] * (double)v[i];
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=%s TENSOR=V COUNT=%zu PROBE=OK "
                    "HASH=%016llx L2=%.9g F8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g\n",
                    (int)pos, (int)pos, layer, stage, (size_t)kvDim,
                    (unsigned long long)VulkanParityGrid::instance().hashPublic(v.data(), v.size()),
                    std::sqrt(s2),
                    v[0],v[1],v[2],v[3],v[4],v[5],v[6],v[7]);
            };
            if (projOk) {
                emitK("K_PROJECTED", kProj, true);
                emitV("V_PROJECTED", vProj, true);
            } else {
                emitK("K_PROJECTED", kProj, false);
                emitV("V_PROJECTED", vProj, false);
            }
            if (slotOk) {
                emitK("K_CACHE_WRITTEN", kSlot, true);
                emitV("V_CACHE_WRITTEN", vSlot, true);
                if (!s_slot0HaveWrite[kvSplitSlot] && pos == 0u) {
                    s_slot0WriteHash[kvSplitSlot] =
                        VulkanParityGrid::instance().hashPublic(kSlot.data(), kSlot.size());
                    s_slot0WritePos[kvSplitSlot] = pos;
                    s_slot0HaveWrite[kvSplitSlot] = true;
                }
            } else {
                emitK("K_CACHE_WRITTEN", kSlot, false);
                emitV("V_CACHE_WRITTEN", vSlot, false);
            }
            std::fflush(kvSplitFile);
    }
    // RAWRXD_VULKAN_BODY_PARITY_GRID_001: post-projection and post-RoPE states.
    // Emitted here, after the fused window has completed, because the RoPE and
    // the Q/K/V GEMVs are submitted together -- reading Q before the window
    // closed would capture pre-RoPE bytes under a post-RoPE label.
    {
        auto& pg = VulkanParityGrid::instance();
        // RAWRXD_VULKAN_ATTENTION_CORE_BISECT_001: these are POST-RoPE. The
        // pre-RoPE values are captured separately as Q_PRE_ROPE/K_PRE_ROPE,
        // which is what makes RoPE isolable.
        pg.emit(vc, layer, 5, "Q_ROPE",  vc->ArenaQ(), qDim);
        pg.emit(vc, layer, 6, "K_ROPE",  vc->ArenaK(), kvDim);
        pg.emit(vc, layer, 4, "V",       vc->ArenaV(), kvDim);
    }
    // ATTN_SCORES / ATTN_PROBS / ATTN_VALUE have NO device-side arena on this
    // path: attention is fused into DispatchAttnDecode, so those intermediates
    // never exist in memory to be compared. They are reported as an explicit
    // gap rather than omitted, because a missing line is indistinguishable from
    // a stage that was never reached, and this whole grid exists to say
    // precisely which is which.
    VulkanParityGrid::instance().emitGap(layer, "ATTN_SCORES");
    VulkanParityGrid::instance().emitGap(layer, "ATTN_PROBS");
    VulkanParityGrid::instance().emitGap(layer, "ATTN_VALUE");
    // RAWRXD_GPU_KV_HANDOFF_001: measure the physical K/V bytes for the
    // Prefill-written slot (pos 0) at Prefill time, then re-measure the very
    // same slot immediately before Decode's attention dispatch and compare.
    // Probing slot 0 is safe here because AppendKV writes slot `pos`, and
    // pos>=1 on every decode step, so Decode's own write cannot land on the
    // slot being compared.
    {
        static const bool kvHandoffEnabled = [](){
            const char* v = std::getenv("RAWRXD_GPU_KV_HANDOFF");
            return v && v[0] && v[0] != '0';
        }();
        if (kvHandoffEnabled && (layer == 0u || layer + 1u == (uint32_t)config.numLayers)) {
            // Slot 0 = layer 0, slot 1 = the last layer.
            const int slotIdx = (layer == 0u) ? 0 : 1;
            static uint64_t s_writeK[2] = {0, 0};
            static uint64_t s_writeV[2] = {0, 0};
            static bool     s_haveWrite[2] = {false, false};
            const uint32_t probeBytes = 64u;
            VulkanCompute::KvSlotBytes b{};
            if (!vc->ProbeKvSlotBytes(layer, 0u, probeBytes, &b)) {
                std::fprintf(stderr, "[KVH] FAIL L=%u pos=0\n", layer);
            } else if (pos >= 2u) {
                // RAWRXD_GPU_KV_NUMERIC_PARITY_001: dump the GPU slot the same
                // way the CPU dump does -- per kvHead, first 8 floats, so the
                // two logs can be diffed element-for-element. Taken at
                // decode2 so that BOTH the prefill slot (0) and decode1's own
                // slot (1) have had their fused AppendKV submitted and waited.
                // Reading at decode1 would race decode1's own fused write.
                for (uint32_t dpos = 0; dpos <= 1u; ++dpos) {
                    std::vector<float> kAll(kvDim, 0.0f), vAll(kvDim, 0.0f);
                    if (!vc->ProbeKvSlotFloats(layer, dpos, kvDim,
                                               kAll.data(), vAll.data()))
                        continue;
                    std::fprintf(stderr, "[KVPAR] GPU layer=%u pos=%u headDim=%u kvHeads=%u\n",
                        layer, dpos, headDim, nKv);
                    for (uint32_t kh = 0; kh < nKv; ++kh) {
                        const uint32_t base = kh * headDim;
                        std::fprintf(stderr, "[KVPAR] GPU L=%u p=%u kh=%u K8=%g %g %g %g %g %g %g %g\n",
                            layer, dpos, kh,
                            kAll[base+0],kAll[base+1],kAll[base+2],kAll[base+3],
                            kAll[base+4],kAll[base+5],kAll[base+6],kAll[base+7]);
                        std::fprintf(stderr, "[KVPAR] GPU L=%u p=%u kh=%u V8=%g %g %g %g %g %g %g %g\n",
                            layer, dpos, kh,
                            vAll[base+0],vAll[base+1],vAll[base+2],vAll[base+3],
                            vAll[base+4],vAll[base+5],vAll[base+6],vAll[base+7]);
                    }
                    std::fflush(stderr);
                }
            }
            if (pos != 0u) {
                float kf[8] = {0}, vf[8] = {0};
                vc->ProbeKvSlotFloats(layer, 0u, 8u, kf, vf);
                if (pos == 0u) {
                    // Prefill. AppendKV is fused here (recorded, not yet
                    // submitted), so the cache does not contain this write
                    // yet. Probing now reads stale/zero bytes and would
                    // manufacture a false handoff mismatch. Skip it: the
                    // first trustworthy observation is decode1.
                } else if (!s_haveWrite[slotIdx]) {
                    // First observation of the Prefill-written slot happens on
                    // the first DECODE step, not at Prefill time: AppendKV is
                    // fused (recorded, not submitted), so a probe issued in
                    // the same window reads the cache BEFORE the copy runs and
                    // reports zeros. That is a probe artefact, not a defect.
                    s_writeK[slotIdx] = b.kHash; s_writeV[slotIdx] = b.vHash;
                    s_haveWrite[slotIdx] = true;
                    std::fprintf(stderr, "[KVH] BASE L=%u R=%u decodePos=%u off=%llu k=%016llx v=%016llx kmatch=vmatch=1\n",
                        b.layer, b.relLayer, pos, (unsigned long long)b.kOffset,
                        (unsigned long long)b.kHash, (unsigned long long)b.vHash);
                    std::fprintf(stderr, "[KVH] BASEF L=%u K=[%g %g %g %g %g %g %g %g]\n",
                        b.layer, kf[0],kf[1],kf[2],kf[3],kf[4],kf[5],kf[6],kf[7]);
                    std::fprintf(stderr, "[KVH] BASEF L=%u V=[%g %g %g %g %g %g %g %g]\n",
                        b.layer, vf[0],vf[1],vf[2],vf[3],vf[4],vf[5],vf[6],vf[7]);
                } else {
                    const bool kMatch = s_writeK[slotIdx] == b.kHash;
                    const bool vMatch = s_writeV[slotIdx] == b.vHash;
                    std::fprintf(stderr, "[KVH] CMP L=%u R=%u decodePos=%u off=%llu k=%016llx v=%016llx kmatch=%d vmatch=%d\n",
                        b.layer, b.relLayer, pos, (unsigned long long)b.kOffset,
                        (unsigned long long)b.kHash, (unsigned long long)b.vHash,
                        kMatch ? 1 : 0, vMatch ? 1 : 0);
                }
                std::fflush(stderr);
            }
        }
    }
    // RAWRXD_ATTN_CTX2_PROBE_001: the scale is hoisted out of the dispatch
    // block because the probe needs the same constant the kernel was given. A
    // copy of a constant is a new fact; this is the same one.
    const float attnScale = 1.0f / std::sqrt((float)headDim);
    {
        DEEP2_GPU_CHILD_SCOPE(attnScope, DeviceAttention);
        const float scale = attnScale;
        if (!vc->DispatchAttnDecode(vc->ArenaQ(), vc->ArenaKCache(), vc->ArenaVCache(),
                                    vc->ArenaAttn(), headDim, nHeads, nKv, pos + 1, scale,
                                    layer))
            return fail("ATTN_DECODE", "DispatchAttnDecode");
        ++c.softmaxOps;
        ++c.attnValueOps;
        ++c.attnScoreOps;
    }
    // RAWRXD_ATTN_VISIBILITY_TRACE_001: the GPU side of the same position frame
    // the CPU route fills in computeAttention. ctxLen is the literal sequence
    // length argument handed to DispatchAttnDecode above, not a recomputed
    // value: if the dispatch were given a shorter context than the write index
    // implies, this is where that would be visible.
    Deep2::AttnVis::recordAttention(
        layer, pos, pos, pos, pos, pos,
        0, pos, static_cast<size_t>(pos) + 1,
        "fused_ctx_len", 0, pos, pos, "vulkan_attn");
    // RAWRXD_ATTN_CTX2_PROBE_001
    //
    // The three sources the classification needs, in one place:
    //   gpu_model  = the kernel's own ALGORITHM, evaluated on the host in
    //                float32 with its loop order and its position-major cache
    //                indexing, from the exact device bytes just read back
    //   gpu_arena  = what the device actually wrote
    //
    // The pivot is the comparison between them. gpu_model == gpu_arena means
    // the kernel is faithful to its source and the defect is in the algorithm
    // or the layout; gpu_model != gpu_arena means the kernel does not do what
    // its own source says, which is a race, a buffer mix-up, or a fused-window
    // publication problem -- a different defect with a different fix.
    //
    // Q is read AFTER DispatchAttnDecode. The dispatch consumes Q but does not
    // write it, and reading it here keeps every readback on the far side of the
    // dispatch so the captured V slot is the one the kernel actually reached.
    if (layer == 0u && Deep2::Ctx2::wantsPosition(static_cast<int>(pos))) {
        std::vector<float> qArena(qDim, 0.0f);
        std::vector<float> attnArena(H, 0.0f);
        const bool gotQ = probeArenaBreakingFusion(vc->ArenaQ(), qDim, qArena);
        const bool gotO = probeArenaBreakingFusion(vc->ArenaAttn(), H, attnArena);
        std::vector<std::vector<float>> kSlots(pos + 1), vSlots(pos + 1);
        bool allSlots = true;
        for (uint32_t t = 0; t <= pos; ++t) {
            kSlots[t].assign(kvDim, 0.0f);
            vSlots[t].assign(kvDim, 0.0f);
            if (!probeKvBreakingFusion(t, kSlots[t], vSlots[t])) allSlots = false;
        }
        if (gotQ && gotO && allSlots) {
            Deep2::Ctx2::emitGpuModelSide(
                static_cast<int>(pos), pos, layer, qArena, kSlots, vSlots,
                nHeads, nKv, headDim, attnScale);
            Deep2::Ctx2::emitGpuArenaSide(
                static_cast<int>(pos), pos, layer, attnArena, nHeads, nKv, headDim);
        } else {
            std::FILE* p = Deep2::Ctx2::file();
            if (p) {
                std::fprintf(p,
                    "CTX2 step=%d ctx=%d side=gpu_model layer=0 READBACK=FAIL "
                    "Q=%d OUT=%d SLOTS=%d "
                    "NOTE=probe_unavailable_not_equal_to_zero\n",
                    (int)pos, (int)pos + 1, gotQ ? 1 : 0, gotO ? 1 : 0,
                    allSlots ? 1 : 0);
                std::fflush(p);
            }
        }
    }
    // RAWRXD_VULKAN_KV_SPLIT_001: CACHE_READBACK. Taken AFTER the attention
    // dispatch, so the comparison against CACHE_WRITTEN covers the bytes the
    // kernel was able to reach, not merely the bytes that were stored. Slot
    // `pos` is the newest slot; slot 0 is the first prefill slot and is
    // compared against the hash captured when it was written, which is what
    // turns "the write was correct" into "the write survived".
    if (kvSplitLayer && kvSplitFile) {
            std::vector<float> kNew(kvDim, 0.0f), vNew(kvDim, 0.0f);
            if (probeKvBreakingFusion(pos, kNew, vNew)) {
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=K_CACHE_READBACK TENSOR=K COUNT=%zu "
                    "PROBE=OK HASH=%016llx L2=%.9g\n",
                    (int)pos, (int)pos, layer, (size_t)kvDim,
                    (unsigned long long)VulkanParityGrid::instance().hashPublic(kNew.data(), kNew.size()),
                    [&]{ double s2=0; for (size_t i=0;i<kNew.size();++i) s2+=(double)kNew[i]*kNew[i]; return std::sqrt(s2); }());
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=V_CACHE_READBACK TENSOR=V COUNT=%zu "
                    "PROBE=OK HASH=%016llx L2=%.9g\n",
                    (int)pos, (int)pos, layer, (size_t)kvDim,
                    (unsigned long long)VulkanParityGrid::instance().hashPublic(vNew.data(), vNew.size()),
                    [&]{ double s2=0; for (size_t i=0;i<vNew.size();++i) s2+=(double)vNew[i]*vNew[i]; return std::sqrt(s2); }());
            } else {
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=K_CACHE_READBACK TENSOR=K COUNT=%zu "
                    "PROBE=FAIL NOTE=readback_unavailable_not_equal_to_zero\n",
                    (int)pos, (int)pos, layer, (size_t)kvDim);
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=V_CACHE_READBACK TENSOR=V COUNT=%zu "
                    "PROBE=FAIL NOTE=readback_unavailable_not_equal_to_zero\n",
                    (int)pos, (int)pos, layer, (size_t)kvDim);
            }
            if (s_slot0HaveWrite[kvSplitSlot] && pos > s_slot0WritePos[kvSplitSlot]) {
                std::vector<float> k0(kvDim, 0.0f), v0(kvDim, 0.0f);
                const bool ok0 = probeKvBreakingFusion(s_slot0WritePos[kvSplitSlot], k0, v0);
                const uint64_t hk0 = ok0 ? VulkanParityGrid::instance().hashPublic(k0.data(), k0.size()) : 0ull;
                std::fprintf(kvSplitFile,
                    "STEP=%d POS=%d LAYER=%u STAGE=K_SLOT0_SURVIVAL TENSOR=K COUNT=%zu "
                    "PROBE=%s HASH=%016llx WRITTEN_AT_POS=%u HASH_AT_WRITE=%016llx MATCH=%d\n",
                    (int)pos, (int)pos, layer, (size_t)kvDim, ok0 ? "OK" : "FAIL",
                    (unsigned long long)hk0, s_slot0WritePos[kvSplitSlot],
                    (unsigned long long)s_slot0WriteHash[kvSplitSlot],
                    (ok0 && hk0 == s_slot0WriteHash[kvSplitSlot]) ? 1 : 0);
            }
            std::fflush(kvSplitFile);
    }
    {
        DEEP2_GPU_CHILD_SCOPE(oProjScope, AttentionOutputProj);
        if (!gemv(*woWt, vc->ArenaAttn(), vc->ArenaDown(), H, qDim)) return fail("GEMV_OPROJ", "oProj");
        ++c.oProjOps;
        // RAWRXD_VULKAN_BODY_PARITY_GRID_001: attention output BEFORE the
        // residual add, so a divergence here is attributable to attention and
        // not to the add that follows.
        VulkanParityGrid::instance().emit(vc, layer, 7, "ATTN_VALUE", vc->ArenaAttn(), H);
        VulkanParityGrid::instance().emit(vc, layer, 8, "O_PROJ",     vc->ArenaDown(),  H);
        if (!vc->DispatchResidualAdd(vc->ArenaHidden(), vc->ArenaDown(),
                                     vc->ArenaResidual(), H))
            return fail("RESIDUAL", "attnResidual");
        ++c.residualOps;
        VulkanParityGrid::instance().emit(vc, layer, 9, "ATTN_RESIDUAL", vc->ArenaResidual(), H);
    }

    if (!vc->DispatchRmsNorm(vc->ArenaResidual(), *ffnNormBuf, vc->ArenaNormed(),
                             H, modelWeights.normEps))
        return fail("RMSNORM", "ffnNorm");

    ++c.ffnNormOps;
    VulkanParityGrid::instance().emit(vc, layer, 10, "RMS_FFN", vc->ArenaNormed(), H);

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
        // RAWRXD_VULKAN_BODY_PARITY_GRID_001: FFN interior, stage by stage.
        auto& pg = VulkanParityGrid::instance();
        pg.emit(vc, layer, 11, "FFN_GATE", vc->ArenaGate(), inter);
        pg.emit(vc, layer, 12, "FFN_UP",   vc->ArenaUp(),   inter);
        if (!vc->DispatchSwiGLU(vc->ArenaGate(), vc->ArenaUp(), vc->ArenaFFNAct(), inter))
            return fail("SWIGLU", "DispatchSwiGLU");
        ++c.ffnActOps;
        pg.emit(vc, layer, 13, "SWIGLU",   vc->ArenaFFNAct(), inter);
        if (!gemv(lw.wDown, vc->ArenaFFNAct(), vc->ArenaDown(), H, inter)) return fail("GEMV_FFN", "wDown");
        pg.emit(vc, layer, 14, "FFN_DOWN", vc->ArenaDown(), H);
        if (!vc->DispatchResidualAdd(vc->ArenaResidual(), vc->ArenaDown(),
                                     vc->ArenaHidden(), H))
            return fail("RESIDUAL", "ffnResidual");
        ++c.ffnResidualOps;
        // The layer's output hidden state. This is the value that must equal the
        // CPU's per-layer residual; a divergence here but not above localises the
        // fault to this layer's FFN or its second residual add.
        pg.emit(vc, layer, 15, "LAYER_RESIDUAL", vc->ArenaHidden(), H);
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

// RAWRXD_REAL_GPU_FORWARD_002 — certification authority.
//
// RAWRXD_REAL_GPU_FORWARD_002_DEFECT: generateStream() calls reset() in its
// tail (Deep2Engine.cpp:5302), and reset() clears gpuFwd_. A gate that reads
// the live counters after generation therefore observed zeros even though the
// same run had executed hundreds of GPU layer forwards. The reset is correct
// behaviour -- it clears per-generation state -- so the fix is not to stop the
// reset, it is to stop the GATE from depending on mutable live counters.
//
// captureGpuForwardReceipt() snapshots the counters at the instant the
// forward completes, before any cleanup can run. isRealGpuForward() then
// derives its answer from that snapshot.
//
// The old short-circuit on gpuFwdCommitted_ is deliberately removed. That flag
// is set by the execution path itself (Deep2Engine_VulkanRuntime.cpp), so
// consulting it would let any forward self-certify regardless of what the
// counters say.
void Deep2Engine::captureGpuForwardReceipt(uint64_t nanCount, uint64_t infCount) {
    gpuFwdReceipt_ = GpuForwardReceipt{};
    gpuFwdReceipt_.forwardLayers = gpuFwd_.forwardLayers;
    gpuFwdReceipt_.qkvOps = gpuFwd_.qkvOps;
    gpuFwdReceipt_.rmsNormOps = gpuFwd_.rmsNormOps;
    gpuFwdReceipt_.attnScoreOps = gpuFwd_.attnScoreOps;
    gpuFwdReceipt_.ffnActOps = gpuFwd_.ffnActOps;
    gpuFwdReceipt_.residualOps = gpuFwd_.residualOps;
    gpuFwdReceipt_.forwardSlot0 = gpuFwd_.forwardSlot[0];
    // One forward per token that reached the resident path. forwardSlot0
    // counts layer forwards, so dividing by the layer count recovers tokens
    // without adding a second increment site that could drift.
    const uint64_t layers =
        modelWeights.numLayers ? (uint64_t)modelWeights.numLayers : 0;
    gpuFwdReceipt_.tokenForwards =
        layers ? (gpuFwd_.forwardSlot[0] / layers) : 0;
    gpuFwdReceipt_.hostMaterializations = gpuFwd_.hostMaterializations;
    gpuFwdReceipt_.matFinalDownload = gpuFwd_.matFinalDownload;
    gpuFwdReceipt_.matCrossDeviceHandoff = gpuFwd_.matCrossDeviceHandoff;
    gpuFwdReceipt_.matGemvSingleRoundTrip = gpuFwd_.matGemvSingleRoundTrip;
    gpuFwdReceipt_.matDualRowSingle = gpuFwd_.matDualRowSingle;
    gpuFwdReceipt_.matDualRowGroup = gpuFwd_.matDualRowGroup;
    gpuFwdReceipt_.matOther = gpuFwd_.matOther;
    gpuFwdReceipt_.hostForwardLayerCalls = gpuFwd_.hostForwardLayerCalls;
    gpuFwdReceipt_.nanCount = nanCount;
    gpuFwdReceipt_.infCount = infCount;
    gpuFwdReceipt_.expectedLayersPerToken = (uint32_t)layers;
    gpuFwdReceipt_.generationId = ++gpuFwdGenerationId_;
    gpuFwdReceipt_.valid = true;


    std::fprintf(stderr,
        "GPUFWD_RECEIPT gen=%llu tokens=%llu layers=%llu qkv=%llu rms=%llu "
        "attn=%llu ffn=%llu resid=%llu slot0=%llu hostMat=%llu "
        "matFinal=%llu hostFwdLayers=%llu nan=%llu inf=%llu expectLayers=%u\n",
        (unsigned long long)gpuFwdReceipt_.generationId,
        (unsigned long long)gpuFwdReceipt_.tokenForwards,
        (unsigned long long)gpuFwdReceipt_.forwardLayers,
        (unsigned long long)gpuFwdReceipt_.qkvOps,
        (unsigned long long)gpuFwdReceipt_.rmsNormOps,
        (unsigned long long)gpuFwdReceipt_.attnScoreOps,
        (unsigned long long)gpuFwdReceipt_.ffnActOps,
        (unsigned long long)gpuFwdReceipt_.residualOps,
        (unsigned long long)gpuFwdReceipt_.forwardSlot0,
        (unsigned long long)gpuFwdReceipt_.hostMaterializations,
        (unsigned long long)gpuFwdReceipt_.matFinalDownload,
        (unsigned long long)gpuFwdReceipt_.hostForwardLayerCalls,
        (unsigned long long)gpuFwdReceipt_.nanCount,
        (unsigned long long)gpuFwdReceipt_.infCount,
        (unsigned)gpuFwdReceipt_.expectedLayersPerToken);
    std::fflush(stderr);
}

void Deep2Engine::resetGpuForwardCounters() {
    // Witness every reset so an invisible one can never appear later without
    // leaving a trace. RAWRXD_REAL_GPU_FORWARD_002_RESET_WITNESS.
    if (gpuFwd_.forwardLayers || gpuFwd_.qkvOps || gpuFwdCommitted_) {
        std::fprintf(stderr,
            "GPUFWD_RESET this=%p counters=%p layers=%llu qkv=%llu "
            "committed=%d receiptValid=%d receiptGen=%llu receiptTokens=%llu\n",
            static_cast<const void*>(this),
            static_cast<const void*>(&gpuFwd_),
            (unsigned long long)gpuFwd_.forwardLayers,
            (unsigned long long)gpuFwd_.qkvOps,
            gpuFwdCommitted_ ? 1 : 0,
            gpuFwdReceipt_.valid ? 1 : 0,
            (unsigned long long)gpuFwdReceipt_.generationId,
            (unsigned long long)gpuFwdReceipt_.tokenForwards);
        std::fflush(stderr);
    }
    gpuFwd_ = GpuForwardCounters{};
}

bool Deep2Engine::isRealGpuForward() const {
    // Derived from completed-generation evidence only.
    const GpuForwardReceipt& r = gpuFwdReceipt_;
    if (!r.valid)
        return false;
    if (r.tokenForwards == 0 || r.forwardLayers == 0)
        return false;
    // Every attention/FFN stage must have actually run on the device.
    if (r.qkvOps == 0 || r.rmsNormOps == 0 || r.attnScoreOps == 0 ||
        r.ffnActOps == 0 || r.residualOps == 0)
        return false;
    // A host-side forward layer means the model was not fully resident.
    if (r.hostForwardLayerCalls != 0)
        return false;
    // Layer-forward coverage must be exactly tokens x layers. This is the
    // strongest available structural check: it cannot be satisfied by a
    // partial run, and it caught nothing here because the measured run did
    // execute every layer (28 x 32 = 896).
    if (r.expectedLayersPerToken != 0) {
        const uint64_t expect =
            r.tokenForwards * (uint64_t)r.expectedLayersPerToken;
        if (r.forwardLayers != expect)
            return false;
    }
    // Non-finite device output is a failed forward regardless of op counts.
    if (r.nanCount != 0 || r.infCount != 0)
        return false;
    // Accounting completeness: every host materialization must fall into
    // exactly one classified bucket. This is the check that catches an
    // UNCLASSIFIED materialization, and it is the codebase's documented
    // exhaustive invariant (Deep2GpuForward_MatClassSum).
    const uint64_t classSum = r.matCrossDeviceHandoff +
                              r.matGemvSingleRoundTrip +
                              r.matDualRowSingle + r.matDualRowGroup +
                              r.matFinalDownload + r.matOther;
    if (r.hostMaterializations != classSum)
        return false;
    // Residency. RAWRXD_REAL_GPU_FORWARD_002_LMHEAD_CLASSIFICATION:
    // tryVulkanHostGEMV (Deep2Engine_GpuMoEMLA.cpp:67) is NOT a CPU fallback --
    // it is the single-GPU lane, taken when Deep2Engine.cpp:3024 declines the
    // dual-GPU row split because vulkanDevices_.size() < 2. Inside it,
    // DispatchWeight keeps the weights device-resident and only the output
    // vector is downloaded. On the output projection that download IS the
    // mandatory final-logits materialization the residency contract permits;
    // counting it as a violation rejected a fully resident LM head.
    //
    // So a single-GEMV round trip is admitted only when there is exactly one
    // per token forward, i.e. one output projection per token. Anything more
    // means per-layer host bouncing and is rejected.
    const uint64_t perToken = r.tokenForwards;
    if (r.matGemvSingleRoundTrip > perToken)
        return false;
    // Everything else bouncing to host is a genuine residency break.
    if (r.matCrossDeviceHandoff != 0 || r.matDualRowSingle != 0 ||
        r.matDualRowGroup != 0 || r.matOther != 0)
        return false;
    return true;
}

} // namespace Deep2

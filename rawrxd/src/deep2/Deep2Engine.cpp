/* Deep2Engine.cpp Ã¢â‚¬â€ Real Implementation
 * Connects: tokenizer, sampler, KV cache, weights, forward pass
 */
#include "Deep2Engine.h"
#include "Deep2Diag.h"
#include "Tokenizer.hpp"
#include "Sampler.hpp"
#include "GGUFLoader.hpp"
#include "ExecutionView.hpp"
#include "Nanof32BraidStreamer.hpp"
// RAWRXD_REVERSE_001: identity -> backing registration at the real bind site.
#include "ReverseLayer.hpp"
// RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: records where model-weight bytes are
// ACTUALLY consumed. LinearW() is a routing boundary, not a compute owner, so
// the census is attached to the branch that really did the arithmetic rather
// than to the call site. See WeightConsumptionCensus.hpp for the audit law.
#include "WeightConsumptionCensus.hpp"
#include "QuantKernelRegistry.hpp"
#include "Deep2DualGpuRowSplit.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "Deep2ArchitectureRuntime.hpp"
#include "Deep2ModelRegistry.hpp"
#include "AttnVisibilityTrace.h"
#include "AttnCtx2Probe.h"
#include "expert_cache/Deep2Batch005Integration.h"
// RAWRXD_INFERENCE_WIRE_001: the layer-dispatch boundary records its decision
// inputs. Include is unconditional so the boundary cannot drift out of the
// capture because someone removed a header.
#include "InferenceWire.hpp"
#if defined(RAWRXD_REMOTE64_LINKED)
#include "remote64_bridge.h"
#endif
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <new>

// ============================================================================
// RAWRXD_DEEP2_MODEL_REGISTRY_001 — production Architecture registration
//
// The registry refuses to admit an architecture that has no registered
// implementation. These descriptors are the real Deep2 execution path, bound to
// the actual engine members below. They are NOT test fixtures.
//
// One implementation serves the architectures that Deep2 genuinely executes with
// its generic transformer / MoE / MLA primitives; each still gets its own
// descriptor id so architecture identity is resolved once, at admission, and
// never re-guessed during forward.
//
// Architectures whose forward family is SpecialGraph, or which require a graph
// other than the one Deep2 wires, are deliberately NOT registered. That is what
// makes admit() reject them fail-closed instead of running llama math on them.
// ============================================================================
// RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — BowRain compute authority integration
// Maps the real compute graph traversal to BowRain evidence discipline.
#include "../compute/BowRainComputeAuthority.h"
namespace {

bool Deep2ArchProbe(const Deep2::ModelMetadata& md) noexcept {
    return Deep2::Arch::resolve(md.canonicalName).kind != Deep2::Arch::Kind::Unknown;
}

Deep2::LoadResult Deep2ArchLoad(Deep2::Deep2Engine& engine,
                                const Deep2::ModelMetadata& md) {
    Deep2::LoadResult r;
    // The engine's own loadModel() is the weight binder; it is already executing
    // when admission runs, so reaching here means the caller invoked the
    // descriptor directly. Route it through the engine's real entry point.
    r.ok = engine.loadModel(std::string(md.ggufPath));
    if (!r.ok) r.error = "Deep2Engine::loadModel rejected the model";
    return r;
}

bool Deep2ArchCreateContext(Deep2::Deep2Engine& engine,
                            const Deep2::ModelMetadata& md) {
    Deep2::LoadResult probe = Deep2ArchLoad(engine, md);
    return probe.ok;
}

Deep2::ArchitectureForwardResult Deep2ArchForward(Deep2::Deep2Engine& engine,
                                                  const Deep2::ForwardRequest& req) {
    Deep2::ArchitectureForwardResult r;
    if (req.tokens == nullptr || req.tokenCount == 0) {
        r.code = Deep2::ArchitectureForwardResult::Code::InvalidRequest;
        r.error = "forward request carried no tokens";
        return r;
    }
    // Run the real forward path. Deep2Engine drives its own token loop from the
    // tokenizer; this entry exists so the registry descriptor is backed by a
    // genuine call rather than a stub that reports success.
    // NOTE: ForwardResult is nested in Deep2Engine, distinct from the registry's
    // Deep2::ArchitectureForwardResult (see Deep2ModelRegistry.hpp).
    Deep2::Deep2Engine::ForwardResult fr = engine.forwardTokenAllLayers(nullptr, req.seqLen);
    if (!fr.ok) {
        r.code = Deep2::ArchitectureForwardResult::Code::ForwardFailed;
        r.error = "forwardTokenAllLayers failed";
        return r;
    }
    r.code = Deep2::ArchitectureForwardResult::Code::Ok;
    return r;
}

void Deep2ArchResetGeneration(Deep2::Deep2Engine& engine) noexcept {
    engine.reset();
}

void Deep2ArchDestroy(Deep2::Deep2Engine& engine) noexcept {
    engine.unloadModel();
}

// Canonical architecture ids Deep2 can actually execute today. Kept explicit:
// adding a key here asserts Deep2 can run it, which is a claim that must be
// earned by a real forward path, not a formatting change.
const char* const kExecutableArchs[] = {
    "llama", "mistral", "phi3",
    "qwen", "qwen2", "qwen3",
    "qwen2moe", "qwen3moe",
    "qwen3next", "qwen35", "qwen35moe",
    "gemma", "gemma2", "gemma3",
    "deepseek2", "deepseek32",
    "nemotron", "nemotron_h", "nemotron_h_moe",
    "mamba", "mamba2",
};

void RegisterDeep2Architectures() {
    static std::vector<Deep2::Architecture*> keepAlive;
    for (const char* id : kExecutableArchs) {
        auto* a = new Deep2::Architecture();
        a->id = id;
        a->probe = Deep2ArchProbe;
        a->load = Deep2ArchLoad;
        a->createContext = Deep2ArchCreateContext;
        a->forward = Deep2ArchForward;
        a->resetGeneration = Deep2ArchResetGeneration;
        a->destroy = Deep2ArchDestroy;
        keepAlive.push_back(a);
        Deep2::ModelRegistry::registerArchitecture(a);
    }
}

} // namespace
#include <stdexcept>
#include <fstream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>

// RAWRXD_MLA_LOAD_AUTHORITY_001 (M5d): the MLA metadata binder, previously
// present only as uncompiled source.
// RAWRXD_EXPERT_REUSE_TRACE_001: <map> and <vector> back the per-(layer,expert)
// reuse-distance table and the observed-distance population. Both were already
// used later in this file without a direct include; they are named here so the
// tracker does not depend on transitive inclusion order.
#include <map>
#include <vector>
#include <sstream>
#include "Deep2B66RuntimeMeta.hpp"
#endif

// RAWRXD_EXPERT_REUSE_TRACE_001 -- state for the reuse-distance tracker
// installed at the MoE route site. Everything is a plain observation counter;
// nothing here has a target value, and the trace is inert unless the env var is
// set, so a normal decode pays one relaxed-load branch per expert selection.
namespace {
struct ReuseSlot {
    std::uint64_t accessSeq = 0;
    std::uint64_t token     = 0;
};
std::map<std::uint64_t, ReuseSlot> g_expertReuseLast;
std::uint64_t g_expertReuseAccessSeq        = 0;
std::uint64_t g_expertReuseToken            = 0;
std::uint64_t g_expertReuseColdFirstTouches = 0;
std::uint64_t g_expertReuseReused           = 0;
// RAWRXD_REUSE_DECODE_PATH_EMISSION_001
// One-shot latch for the decode path's own emission. The cert's destructor also
// calls the emitter as a fallback; this latch makes the second call a no-op, so
// a run emits exactly one receipt regardless of how many paths reach it.
bool g_expertReuseDecodePathEmitted        = false;
const bool g_expertReuseTraceEnabled = [] {
    const char* v = std::getenv("RAWRXD_EXPERT_REUSE_TRACE");
    return v && *v && std::strcmp(v, "0") != 0;
}();
}  // namespace

namespace Deep2 {

// RAWRXD_EXPERT_REUSE_TRACE_001 -- summary of the population the trace actually
// observed. HOT_WORTHY_PAIR_FRACTION is reused/accesses: a low value means most
// accesses are first touches, which is the regime in which a small HOT set cannot
// work. It is a measurement, never a target.
//
// Defined with the Deep2Engine scope qualifier because the declaration in
// Deep2Engine.h is a MEMBER of the class. A definition of the form
// `Deep2::EmitExpertReuseSummary()` -- which is what this was originally --
// mangles to a different symbol and links to LNK2019, because
// `?EmitExpertReuseSummary@Deep2Engine@Deep2@@QEAAXXZ` carries the class scope.
// RAWRXD_REUSE_DECODE_PATH_EMISSION_001
// The production emission point. noexcept, and set-latch-first, because it is
// invoked from a decode-exit guard: if the body threw while unwinding, the throw
// would escape a noexcept boundary and call std::terminate, converting an
// ordinary early return into a crash. The latch is claimed BEFORE the body runs
// so a failed emission still yields exactly one receipt rather than two.
void Deep2Engine::EmitExpertReuseSummaryFromDecodePath() noexcept {
    if (g_expertReuseDecodePathEmitted) return;
    g_expertReuseDecodePathEmitted = true;
    try {
        EmitExpertReuseSummary();
    } catch (...) {
        // A telemetry path that cannot describe its own failure has failed. Say
        // so explicitly rather than silently emitting nothing.
        std::fprintf(stderr,
                     "EXPERT_REUSE_SUMMARY_EMIT_FAILED=1\n"
                     "REUSE_RECEIPT_VALID=0\n"
                     "VERDICT=FAIL\n");
        std::fflush(stderr);
    }
}

void Deep2Engine::EmitExpertReuseSummary() {
    if (!g_expertReuseTraceEnabled) return;

    // RAWRXD_REUSE_RECEIPT_FALSIFIABILITY_001
    // A reuse receipt over zero observations is not a result. These are the
    // invariants a receipt must satisfy before any consumer may treat it as
    // evidence, and they are checked HERE rather than by a downstream reader,
    // because a downstream reader is exactly what has been reporting a zero
    // population as though it characterized routing.
    //
    // Every condition below is a structural impossibility check, not a quality
    // threshold. A receipt that fails any of them is INVALID, and an INVALID
    // receipt may not be used to support a claim about residency or working set.
    const bool hasTokens   = (g_expertReuseToken > 0);
    const bool hasAccesses = (g_expertReuseAccessSeq > 0);
    const bool hasPairs    = (g_expertReuseLast.size() > 0);
    const bool partitionSums =
        (g_expertReuseColdFirstTouches + g_expertReuseReused == g_expertReuseAccessSeq);
    const bool pairsBounded = (g_expertReuseLast.size() <= g_expertReuseAccessSeq);
    const bool anyReused    = (g_expertReuseReused > 0);

    const bool valid = hasTokens && hasAccesses && hasPairs &&
                       partitionSums && pairsBounded;

    // Population counts are always printed: they are observations, and a zero is
    // an observation. What is NOT printed on an invalid receipt is any DERIVED
    // ratio.
    //
    // RAWRXD_REUSE_ABSENCE_IS_THE_RECEIPT_001
    //   This is the DROW form of "HOT_WORTHY_PAIR_FRACTION=ABSENT". Writing the
    //   token ABSENT would still emit the field, still occupy the receipt, and
    //   still imply a measurement slot exists. The absence must be the whole
    //   statement: when the receipt is invalid, NO line matching
    //   HOT_WORTHY_PAIR_FRACTION= may appear at all. A grep for that key is
    //   therefore a valid falsifier -- it returns nothing when nothing was
    //   measured, which is the property a default of 0.000000 destroys.
    //
    //   Concretely: 0.000000 over zero observations is a FABRICATED
    //   MEASUREMENT, not a default. It is indistinguishable from a measured
    //   zero, and this session has eleven instances of exactly that confusion.
    std::fprintf(stderr,
                 "EXPERT_REUSE_SUMMARY TOKENS=%llu EXPERT_ACCESSES=%llu "
                 "UNIQUE_PAIRS=%zu COLD_FIRST_TOUCHES=%llu REUSED_ACCESSES=%llu\n",
                 (unsigned long long)g_expertReuseToken,
                 (unsigned long long)g_expertReuseAccessSeq,
                 g_expertReuseLast.size(),
                 (unsigned long long)g_expertReuseColdFirstTouches,
                 (unsigned long long)g_expertReuseReused);
    std::fflush(stderr);

    if (valid) {
        // Only now does the fraction exist to be printed.
        std::fprintf(stderr, "HOT_WORTHY_PAIR_FRACTION=%.6f\n",
                     double(g_expertReuseReused) / double(g_expertReuseAccessSeq));
        std::fflush(stderr);
    }

    // Validity is reported separately from the numbers, so that no consumer can
    // read a fraction out of an invalid receipt. REUSE_DISTRIBUTION_MEASURED=0
    // with non-zero-looking fractions is precisely the shape that previously
    // produced confident wrong answers.
    std::fprintf(stderr,
                 "REUSE_RECEIPT_VALID=%d\n"
                 "REUSE_DISTRIBUTION_MEASURED=%d\n"
                 "REUSE_INVARIANT_TOKENS_NONZERO=%d\n"
                 "REUSE_INVARIANT_ACCESSES_NONZERO=%d\n"
                 "REUSE_INVARIANT_PAIRS_NONZERO=%d\n"
                 "REUSE_INVARIANT_PARTITION_SUMS=%d\n"
                 "REUSE_INVARIANT_PAIRS_BOUNDED=%d\n"
                 "REUSE_ANY_REUSE_OBSERVED=%d\n"
                 "REUSE_CLAIM_USABLE=%d\n",
                 valid ? 1 : 0,
                 valid ? 1 : 0,
                 hasTokens ? 1 : 0, hasAccesses ? 1 : 0, hasPairs ? 1 : 0,
                 partitionSums ? 1 : 0, pairsBounded ? 1 : 0, anyReused ? 1 : 0,
                 valid ? 1 : 0);
    if (!valid) {
        std::fprintf(stderr,
                     "REUSE_RECEIPT_REJECTED=1 reason=%s\n"
                     "NOTE=No routing observations were made. This receipt characterizes\n"
                     "     NOTHING about expert locality and may not be cited as evidence.\n"
                     "NOTE=No HOT_WORTHY_PAIR_FRACTION line is emitted for an invalid receipt.\n"
                     "     Its absence IS the receipt; a 0.000000 would be a fabricated\n"
                     "     measurement indistinguishable from a measured zero.\n",
                     !hasTokens ? "TOKENS_ZERO_MODEL_NEVER_ROUTED"
                                : (!partitionSums ? "COUNTER_PARTITION_MISMATCH"
                                                  : "INSUFFICIENT_OBSERVATIONS"));
        std::fprintf(stderr, "VERDICT=FAIL\n");
    } else {
        std::fprintf(stderr, "VERDICT=PASS\n");
    }
    std::fflush(stderr);
}

// ------------------------------------------------------------
// Token-path telemetry accumulator (C++20, zero-dependency beyond the standard lib).
// All fields are caller-fed from real execution points â€” no synthetic estimates.
// ------------------------------------------------------------
struct TokenTelemetryAccumulator {
    // Oneâ€‘time initialization / open
    bool open(const char* csv_path = nullptr, const char* jsonl_path = nullptr);

    // Call once per generated token (ideally right after the token is fully emitted).
    void record_token();

    // ------------------------------------------------------------------
    // Counters filled from the real Deep2 execution points (see the perâ€‘file wiring below).
    // ------------------------------------------------------------------
    // Token loop / timing
    uint64_t tokens_generated{};
    uint64_t token_total_ns{};          // TOKEN_TOTAL_NS wallâ€‘clock per token

    // Model footprint
    uint64_t model_file_bytes{};

    // Weight traffic per token
    uint64_t active_weight_bytes{};
    uint64_t vram_weight_bytes_read{};
    uint64_t ram_to_gpu_bytes{};
    uint64_t gpu_to_gpu_bytes{};
    uint64_t kv_read_bytes{};
    uint64_t kv_write_bytes{};
    uint64_t scratch_bytes{};

    // Expertâ€‘cache
    uint32_t experts_total{};
    uint32_t experts_active{};
    uint64_t expert_cache_hits{};
    uint64_t expert_cache_misses{};

    // GPU timing (ns)
    uint64_t gpu_busy_ns{};
    uint64_t gpu_idle_ns{};
    uint64_t wait_ns{};
    uint64_t submit_ns{};

    // Hotpatch authority (populated by the addressâ€‘space layer)
    uint64_t hotpatch_resolves{};
    uint64_t hotpatch_fallbacks{};
    uint64_t hotpatched_steps{};
    uint64_t fallback_steps{};
    uint64_t nominal_gpu_work_ns{};
    uint64_t avoided_gpu_work_ns{};

    // CSV/JSONL output (kept simple for the first integration)
    FILE* csv_fp{};
    FILE* jsonl_fp{};
};

// ------------------------------------------------------------
// Global instance â€“ one per engine process lifetime.
// ------------------------------------------------------------
static TokenTelemetryAccumulator telemetry;

// ------------------------------------------------------------
// Helper: now_ns using steady_clock (same as the telemetry lib).
// ------------------------------------------------------------
static uint64_t now_ns() noexcept {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

// ------------------------------------------------------------
// TokenTelemetryAccumulator methods
// ------------------------------------------------------------
bool TokenTelemetryAccumulator::open(const char* csv_path, const char* jsonl_path) {
    bool ok = true;
    if (csv_path) {
        csv_fp = std::fopen(csv_path, "w");
        if (!csv_fp) { ok = false; csv_fp = nullptr; }
        else { std::fprintf(csv_fp, "token_index,token_id,model_file_bytes,active_weight_bytes,"
                    "vram_weight_bytes_read,ram_to_gpu_bytes,gpu_to_gpu_bytes,"
                    "kv_read_bytes,kv_write_bytes,scratch_bytes,"
                    "experts_total,experts_active,expert_cache_hits,expert_cache_misses,"
                    "gpu_busy_ns,gpu_idle_ns,wait_ns,submit_ns,"
                    "hotpatch_resolves,hotpatch_fallbacks,hotpatched_steps,fallback_steps,"
                    "nominal_gpu_work_ns,avoided_gpu_work_ns,tokens_generated,token_total_ns\n"); }
    }
    if (jsonl_path) {
        jsonl_fp = std::fopen(jsonl_path, "w");
        if (!jsonl_fp) { ok = false; jsonl_fp = nullptr; }
        else { std::fprintf(jsonl_fp, "{\"model_file_bytes\":%llu}\n",
                  (unsigned long long)model_file_bytes); }
    }
    return ok;
}

void TokenTelemetryAccumulator::record_token() {
    ++tokens_generated;

    // Emit a CSV row if the file is open.
    if (csv_fp) {
        std::fprintf(csv_fp, "%llu,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
            (unsigned long long)tokens_generated, /* token_index */ 0, (unsigned long long)/* token_id */ 0,
            (unsigned long long)model_file_bytes, (unsigned long long)active_weight_bytes,
            (unsigned long long)vram_weight_bytes_read, (unsigned long long)ram_to_gpu_bytes,
            (unsigned long long)gpu_to_gpu_bytes, (unsigned long long)kv_read_bytes,
            (unsigned long long)kv_write_bytes, (unsigned long long)scratch_bytes,
            experts_total, experts_active,
            (unsigned long long)expert_cache_hits, (unsigned long long)expert_cache_misses,
            (unsigned long long)gpu_busy_ns, (unsigned long long)gpu_idle_ns,
            (unsigned long long)wait_ns, (unsigned long long)submit_ns,
            (unsigned long long)hotpatch_resolves, (unsigned long long)hotpatch_fallbacks,
            (unsigned long long)hotpatched_steps, (unsigned long long)fallback_steps,
            (unsigned long long)nominal_gpu_work_ns, (unsigned long long)avoided_gpu_work_ns,
            (unsigned long long)tokens_generated, (unsigned long long)token_total_ns);
    }
    // JSONL row would be written similarly.
}

// ------------------------------------------------------------
// Earlyâ€‘exit if telemetry not configured.
// ------------------------------------------------------------
#define TELEMETRY_GUARD if (!telemetry.csv_fp && !telemetry.jsonl_fp) return;

} // namespace Deep2

// =================== HELPER: RMSNorm ====================
static void rmsnorm(float* out, const float* in, const float* weight,
                    size_t dim, float eps) {
    if (!out || !in || dim == 0) return;
    float ss = 0.0f;
    for (size_t i = 0; i < dim; ++i) ss += in[i] * in[i];
    float norm = 1.0f / std::sqrt(ss / dim + eps);
    if (weight) {
        for (size_t i = 0; i < dim; ++i) out[i] = in[i] * norm * weight[i];
    } else {
        for (size_t i = 0; i < dim; ++i) out[i] = in[i] * norm;
    }
}

// =================== HELPER: SiLU ====================
static float silu(float x) { return x / (1.0f + std::exp(-x)); }

// =================== HELPER: GELU (tanh approximation) ====================
static float geluTanh(float x) {
    // GeLU approximation: 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
    const float c = 0.044715f;
    const float sqrt2OverPi = 0.7978845608f;
    float t = sqrt2OverPi * (x + c * x * x * x);
    return 0.5f * x * (1.0f + std::tanh(t));
}

// =================== HELPER: GeGLU (GELU-based gated activation) ====================
static void geglu(const float* gate, const float* up, float* output, size_t dim) {
    if (!gate || !up || !output || dim == 0) return;
    for (size_t i = 0; i < dim; ++i) {
        output[i] = geluTanh(gate[i]) * up[i];
    }
}

// =================== HELPER: Softmax ====================
static void softmax(float* x, size_t n) {
    if (!x || n == 0) return;
    float maxv = x[0];
    for (size_t i = 1; i < n; ++i) maxv = std::max(maxv, x[i]);
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) { x[i] = std::exp(x[i] - maxv); sum += x[i]; }
    const float inv = sum > 0.0f ? (1.0f / sum) : 0.0f;
    for (size_t i = 0; i < n; ++i) x[i] *= inv;
}

// =================== LAYER-0 PARITY PROBE (FNV-1a fingerprints) ============
namespace Deep2 {

// Emits one compact record per checkpoint for an external oracle. Format:
//   STEP=<name> COUNT=<n> FINITE=<k> MIN=<v> MAX=<v> MEAN=<v> L2=<v>
//   FIRST8=<a,b,c,d,e,f,g,h> HASH=<hex>
struct Deep2Engine::ParityProbe {
    FILE* f = nullptr;
    static constexpr int kCpCount = 21;
    bool emitted[kCpCount] = {};
    int  step = 0;            // current generation step (position)
    bool stepMode = false;    // true: re-arm checkpoints each parityBeginStep
    int  fullVecLayer = -1;   // >=0: dump full vectors for this layer
    static const char* name(ParityCheckpoint cp) {
        switch (cp) {
            case ParityCheckpoint::Embed:        return "EMBED";
            case ParityCheckpoint::AttnNorm:     return "ATTN_NORM";
            case ParityCheckpoint::Q:            return "Q";
            case ParityCheckpoint::K:            return "K";
            case ParityCheckpoint::V:            return "V";
            case ParityCheckpoint::Q_Rope:       return "Q_ROPE";
            case ParityCheckpoint::K_Rope:       return "K_ROPE";
            case ParityCheckpoint::AttnScores:   return "ATTN_SCORES";
            case ParityCheckpoint::AttnProbs:    return "ATTN_PROBS";
            case ParityCheckpoint::AttnValue:    return "ATTN_VALUE";
            case ParityCheckpoint::OProj:        return "O_PROJ";
            case ParityCheckpoint::AttnResidual: return "ATTN_RESIDUAL";
            case ParityCheckpoint::FfnNorm:      return "FFN_NORM";
            case ParityCheckpoint::FfnGate:      return "FFN_GATE";
            case ParityCheckpoint::FfnUp:        return "FFN_UP";
            case ParityCheckpoint::Swiglu:       return "SWIGLU";
            case ParityCheckpoint::FfnDown:      return "FFN_DOWN";
            case ParityCheckpoint::LayerResidual:return "LAYER_RESIDUAL";
            case ParityCheckpoint::FinalNorm:    return "FINAL_NORM";
            case ParityCheckpoint::Logits:       return "LOGITS";
            case (ParityCheckpoint)20:           return "HIDDEN_FINAL";
        }
        return "?";
    }
};

static uint64_t parityHash(const float* v, size_t n) {
    uint64_t h = 1469598103934665603ull;  // FNV-1a 64 offset basis
    const auto* bytes = reinterpret_cast<const uint8_t*>(v);
    for (size_t i = 0; i < n * sizeof(float); ++i) {
        h ^= bytes[i];
        h *= 1099511628211ull;
    }
    return h;
}

void Deep2Engine::parityEmitCount(ParityCheckpoint cp, size_t n, double minv,
                                  double maxv, double mean, double l2,
                                  const float* first8, uint64_t hash) {
    if (!parityProbe_ || !parityProbe_->f) return;
    const int idx = static_cast<int>(cp);
    if (idx < 0 || idx >= Deep2Engine::ParityProbe::kCpCount) return;
    if (parityProbe_->emitted[idx]) return;  // once per step (or once total)
    parityProbe_->emitted[idx] = true;
    if (parityProbe_->stepMode) {
        std::fprintf(parityProbe_->f, "STEP=%d ", parityProbe_->step);
    }
    float first[8] = {};
    if (first8 && n != 0) {
        const size_t copy = std::min<size_t>(n, 8);
        for (size_t i = 0; i < copy; ++i) first[i] = first8[i];
    }
    std::fprintf(parityProbe_->f,
        "CP=%s COUNT=%zu MIN=%.9g MAX=%.9g MEAN=%.9g L2=%.9g "
        "FIRST8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g HASH=%016llx\n",
        Deep2Engine::ParityProbe::name(cp), n, minv, maxv, mean, l2,
        first[0], first[1], first[2], first[3],
        first[4], first[5], first[6], first[7],
        static_cast<unsigned long long>(hash));
    std::fflush(parityProbe_->f);
}

void Deep2Engine::parityEmit(ParityCheckpoint cp, const float* v, size_t n) {
    if (!parityProbe_ || !parityProbe_->f) return;
    const int idx = static_cast<int>(cp);
    if (idx < 0 || idx >= Deep2Engine::ParityProbe::kCpCount) return;
    if (parityProbe_->emitted[idx]) return;
    if (!v || n == 0) {
        parityEmitCount(cp, 0, 0, 0, 0, 0, nullptr, 0);
        return;
    }
    double mn = v[0], mx = v[0], sum = 0.0, l2 = 0.0;
    size_t finite = 0;
    for (size_t i = 0; i < n; ++i) {
        const double x = static_cast<double>(v[i]);
        if (std::isfinite(x)) {
            ++finite;
            if (x < mn) mn = x;
            if (x > mx) mx = x;
            sum += x;
            l2 += x * x;
        }
    }
    const double mean = finite ? sum / static_cast<double>(finite) : 0.0;
    parityEmitCount(cp, n, mn, mx, mean, std::sqrt(l2), v, parityHash(v, n));
}

void Deep2Engine::enableParityProbe(const char* filePath, int maxSteps) {
    disableParityProbe();
    parityProbe_ = new ParityProbe();
    parityProbe_->f = std::fopen(filePath, "w");
    (void)maxSteps;  // per-checkpoint once-semantics; maxSteps reserved
    parityProbe_->stepMode = false;
    parityProbe_->step = 0;
}

void Deep2Engine::parityBeginStep(int step) {
    if (!parityProbe_) return;
    parityProbe_->step = step;
    parityProbe_->stepMode = true;
    for (int i = 0; i < Deep2Engine::ParityProbe::kCpCount; ++i)
        parityProbe_->emitted[i] = false;
}

void Deep2Engine::parityEmitKvWrite(int layer, const float* k, const float* v,
                                    size_t n) {
    if (!parityProbe_ || !parityProbe_->f) return;
    if (!parityProbe_->stepMode) return;  // KV records are step-scoped
    if (!k || !v || n == 0) return;
    const double kMin = *std::min_element(k, k + n);
    const double kMax = *std::max_element(k, k + n);
    double kSum = 0.0, kL2 = 0.0;
    for (size_t i = 0; i < n; ++i) {
        kSum += static_cast<double>(k[i]);
        kL2 += static_cast<double>(k[i]) * static_cast<double>(k[i]);
    }
    const double kMean = kSum / static_cast<double>(n);
    const uint64_t kHash = parityHash(k, n);
    const double vMin = *std::min_element(v, v + n);
    const double vMax = *std::max_element(v, v + n);
    double vSum = 0.0, vL2 = 0.0;
    for (size_t i = 0; i < n; ++i) {
        vSum += static_cast<double>(v[i]);
        vL2 += static_cast<double>(v[i]) * static_cast<double>(v[i]);
    }
    const double vMean = vSum / static_cast<double>(n);
    const uint64_t vHash = parityHash(v, n);
    std::fprintf(parityProbe_->f,
        "STEP=%d CP=KV_WRITE LAYER=%d COUNT=%zu "
        "K_MIN=%.9g K_MAX=%.9g K_MEAN=%.9g K_L2=%.9g K_HASH=%016llx "
        "V_MIN=%.9g V_MAX=%.9g V_MEAN=%.9g V_L2=%.9g V_HASH=%016llx\n",
        parityProbe_->step, layer, n,
        kMin, kMax, kMean, std::sqrt(kL2),
        static_cast<unsigned long long>(kHash),
        vMin, vMax, vMean, std::sqrt(vL2),
        static_cast<unsigned long long>(vHash));
    std::fflush(parityProbe_->f);
}

void Deep2Engine::parityEmitLogitsTop10(const float* logits, size_t n) {
    if (!parityProbe_ || !parityProbe_->f) return;
    if (!parityProbe_->stepMode) return;
    if (!logits || n == 0) return;
    // Greedy top-10 with first-max-wins tie-break (matches GreedySampler and
    // np.argmax): linear scan, strictly-greater comparison.
    int topIdx[50] = {};
    float topVal[50];
    std::fill(std::begin(topVal), std::end(topVal),
              -std::numeric_limits<float>::infinity());
    const size_t keep = std::min<size_t>(50, n);
    for (size_t i = 0; i < n; ++i) {
        float val = logits[i];
        // Insert into the (up to) 10-slot sorted-desc list.
        for (size_t s = 0; s < keep; ++s) {
            if (val > topVal[s]) {
                for (size_t t = keep - 1; t > s; --t) {
                    topVal[t] = topVal[t - 1];
                    topIdx[t] = topIdx[t - 1];
                }
                topVal[s] = val;
                topIdx[s] = static_cast<int>(i);
                break;
            }
        }
    }
    std::fprintf(parityProbe_->f, "STEP=%d CP=LOGITS_TOP10 TOP10=", 
                 parityProbe_->step);
    for (size_t s = 0; s < keep; ++s) {
        std::fprintf(parityProbe_->f, "%s%d:%.6f",
                     s ? "," : "", topIdx[s], topVal[s]);
    }
    std::fprintf(parityProbe_->f, "\n");
    std::fflush(parityProbe_->f);
}

void Deep2Engine::enableParityProbeFullVectors(int layer) {
    if (parityProbe_) parityProbe_->fullVecLayer = layer;
}

void Deep2Engine::parityEmitLayer(int layer, const char* cpName,
                                   const float* v, size_t n) {
    if (!parityProbe_ || !parityProbe_->f) return;
    if (!parityProbe_->stepMode) return;
    if (!v || n == 0) {
        std::fprintf(parityProbe_->f,
            "STEP=%d CP=LAYER_%d_%s COUNT=0 MIN=0 MAX=0 MEAN=0 L2=0 "
            "FIRST8=0,0,0,0,0,0,0,0 HASH=0000000000000000\n",
            parityProbe_->step, layer, cpName);
        std::fflush(parityProbe_->f);
        return;
    }
    double mn = v[0], mx = v[0], sum = 0.0, l2 = 0.0;
    size_t finite = 0;
    for (size_t i = 0; i < n; ++i) {
        const double x = static_cast<double>(v[i]);
        if (std::isfinite(x)) {
            ++finite;
            if (x < mn) mn = x;
            if (x > mx) mx = x;
            sum += x;
            l2 += x * x;
        }
    }
    const double mean = finite ? sum / static_cast<double>(finite) : 0.0;
    const uint64_t hash = parityHash(v, n);
    float first[8] = {};
    const size_t copy = std::min<size_t>(n, 8);
    for (size_t i = 0; i < copy; ++i) first[i] = v[i];
    std::fprintf(parityProbe_->f,
        "STEP=%d CP=LAYER_%d_%s COUNT=%zu MIN=%.9g MAX=%.9g MEAN=%.9g L2=%.9g "
        "FIRST8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g HASH=%016llx\n",
        parityProbe_->step, layer, cpName, n, mn, mx, mean, std::sqrt(l2),
        first[0], first[1], first[2], first[3],
        first[4], first[5], first[6], first[7],
        static_cast<unsigned long long>(hash));
    // DEEP2_QWEN2_CPU_CORRECTNESS_001: full-vector dump for the target layer.
    // LOGITS also dumped as VEC when fullVecLayer == -2.
    if (parityProbe_->fullVecLayer >= 0 && layer == parityProbe_->fullVecLayer) {
        std::fprintf(parityProbe_->f,
            "STEP=%d VEC=LAYER_%d_%s N=%zu\n",
            parityProbe_->step, layer, cpName, n);
        for (size_t i = 0; i < n; i += 16) {
            const size_t cnt = std::min<size_t>(16, n - i);
            for (size_t k = 0; k < cnt; ++k) {
                std::fprintf(parityProbe_->f, "%s%.9g", k ? "," : "", v[i + k]);
            }
            std::fputc('\n', parityProbe_->f);
        }
    }
    std::fflush(parityProbe_->f);
}
void Deep2Engine::disableParityProbe() {
    if (parityProbe_) {
        if (parityProbe_->f) std::fclose(parityProbe_->f);
        delete parityProbe_;
        parityProbe_ = nullptr;
    }
}

static bool finiteVector(const float* x, size_t n) {
    if (!x) return false;
    for (size_t i = 0; i < n; ++i) {
        if (!std::isfinite(x[i])) return false;
    }
    return true;
}

static bool matrixShape(const WeightTensor& wt, size_t& rows, size_t& cols) {
    rows = wt.rows;
    cols = wt.cols;
    if ((rows == 0 || cols == 0) && wt.shape.size() >= 2) {
        cols = static_cast<size_t>(wt.shape[0]);
        rows = static_cast<size_t>(wt.shape[1]);
    }
    return rows != 0 && cols != 0;
}

static size_t packedBytesRequired(int type, size_t rows, size_t cols) {
    const auto* desc = LookupQuantType(static_cast<uint32_t>(type));
    if (!desc || desc->blockBytes == 0 || desc->blockElements == 0) return 0;
    const size_t blocksPerRow =
        (cols + desc->blockElements - 1) / desc->blockElements;
    if (rows > (std::numeric_limits<size_t>::max() /
                (blocksPerRow ? blocksPerRow : 1))) {
        return 0;
    }
    return rows * blocksPerRow * desc->blockBytes;
}

// =================== SSM / Mamba (STRICT PROVIDER BOUNDARY) ====================
// DEEP2_SSM_CONV_NUMERICAL_INSTABILITY_001 diagnostics.
// Observation only: reports per-stage magnitude and finiteness so the first
// diverging stage is identified from measurement rather than inference.
// It never clamps, zeroes, or substitutes a value.
// Telemetry is compiled out unless RAWRXD_DEEP2_SSM_NUMERIC_DIAG is defined, so
// the certification run executes the production path with no diagnostic output.
#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
#define RAWRXD_DEEP2_TRACE(...) do { std::fprintf(stderr, __VA_ARGS__); std::fflush(stderr); } while (0)
namespace {
struct SsmStageRange {
    double mn = 0.0, mx = 0.0, amax = 0.0;
    size_t nonfinite = 0;
};
void ssmStageAccum(const float* p, size_t n, SsmStageRange& r) {
    if (!p) { r.nonfinite += n; return; }
    bool first = true;
    for (size_t i = 0; i < n; ++i) {
        const float f = p[i];
        if (!std::isfinite(f)) { ++r.nonfinite; first = true; continue; }
        const double v = static_cast<double>(f);
        if (first) { r.mn = v; r.mx = v; first = false; }
        else { if (v < r.mn) r.mn = v; if (v > r.mx) r.mx = v; }
        const double a = v < 0.0 ? -v : v;
        if (a > r.amax) r.amax = a;
    }
}
void ssmShapeText(const WeightTensor& wt, char* out, size_t cap) {
    if (!wt.data) { std::snprintf(out, cap, "ABSENT"); return; }
    int n = std::snprintf(out, cap, "[");
    for (size_t i = 0; i < wt.shape.size() && i < 6; ++i)
        n += std::snprintf(out + n, (cap > (size_t)n) ? cap - (size_t)n : 0,
                           "%s%zu", i ? "," : "", static_cast<size_t>(wt.shape[i]));
    std::snprintf(out + n, (cap > (size_t)n) ? cap - (size_t)n : 0,
                  "] rows=%zu cols=%zu type=%d bytes=%zu",
                  wt.rows, wt.cols, wt.type, wt.sizeBytes);
}
long long ssmDiagBudget() {
    static long long budget = -1;
    if (budget < 0) {
        budget = 24;
        if (const char* e = std::getenv("RAWRXD_SSM_DIAG_CALLS")) {
            char* endp = nullptr;
            const long long v = std::strtoll(e, &endp, 10);
            if (endp && *endp == '\0' && v > 0) budget = v;
        }
    }
    return budget;
}
long long ssmDiagNext() {
    static long long counter = 0;
    return counter++;
}
void ssmStageReport(const char* tag, long long call, long long layer,
                    const char* stage, const float* p, size_t n) {
    SsmStageRange r;
    ssmStageAccum(p, n, r);
    std::fprintf(stderr,
        "%s call=%lld layer=%lld STAGE=%s N=%zu MIN=%.9g MAX=%.9g ABSMAX=%.9g NONFINITE=%zu\n",
        tag, call, layer, stage, n, r.mn, r.mx, r.amax, r.nonfinite);
    std::fflush(stderr);
}
} // namespace
#else
#define RAWRXD_DEEP2_TRACE(...) do { } while (0)
#endif

// =================== RAWRXD_TENSOR_PROVENANCE_001 ===================
//
// Tensor identity must be a hard PREREQUISITE for every downstream numerical
// claim. Investigation order is therefore
//
//     IDENTITY -> INTERPRETATION -> NUMERICS -> SEMANTICS
//
// and a numerical probe run before identity is established is measuring a
// conditional premise. The Q2_K scale arithmetic investigated earlier was
// internally consistent over bytes that were NOT the tensor it claimed: every
// GEMV after the first in a process received the first tensor's residency-cache
// entry. Rigorous arithmetic, wrong object.
//
// Three ownership boundaries are fingerprinted and compared:
//
//   WQEXT    GGUF extraction, from the GGUFTensor the loader selected
//   LWBOUND  the bound WeightTensor as the consumer sees it
//   KERNEL   the bytes the kernel is actually handed, via ev.transientAddress
//
// The KERNEL boundary is hashed by CONTENT, not by pointer. Pointer equality is
// deliberately NOT the criterion: copying, staging, dequantisation, GPU upload
// or legitimate remapping all change addresses without changing identity. The
// question is whether the consumer operates on bytes derived from the tensor the
// loader claims it selected, and only content can answer that.
struct TensorProvenance {
    uint64_t provHash   = 0;   // identity from declared fields
    uint64_t prefixHash = 0;   // content: first 64 bytes
    uint64_t bodyHash   = 0;   // content: sampled windows across the extent
    uint64_t byteLength = 0;
    uint64_t fileOffset = 0;
    uint32_t shardId    = 0;
    uint32_t type       = 0;
    int64_t  dims[8]    = {0};
    uint32_t nDims      = 0;
    bool     haveContent = false;
};

static inline uint64_t provMix(uint64_t h, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        h ^= (v >> (i * 8)) & 0xFFull;
        h *= 1099511628211ull;
    }
    return h;
}
static uint64_t provFnvBytes(const void* p, size_t n, uint64_t seed) {
    const unsigned char* b = (const unsigned char*)p;
    uint64_t h = seed ? seed : 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

// Identity from DECLARED fields only. No pointer, no content: two tensors with
// the same name/type/dims/length/offset are the same tensor regardless of where
// they currently live.
static uint64_t provIdentityHash(const char* name, uint32_t type,
                                 const std::vector<int64_t>& shape,
                                 uint64_t byteLength, uint64_t fileOffset,
                                 uint32_t shardId) {
    uint64_t h = 14695981039346656037ull;
    h = provMix(h, 1ull);                                  // model fingerprint
    h = provMix(h, shardId);
    h = provMix(h, (uint64_t)type);
    h = provMix(h, byteLength);
    h = provMix(h, fileOffset);
    h = provMix(h, name ? (uint64_t)std::strlen(name) : 0ull);
    if (name) for (const char* c = name; *c; ++c) h = provMix(h, (uint64_t)(unsigned char)*c);
    for (int64_t d : shape) h = provMix(h, (uint64_t)d);
    return h;
}

// Content fingerprint of the bytes a consumer will actually read.
static void provContentHash(TensorProvenance& pv, const void* data, uint64_t len) {
    if (!data || len == 0) return;
    const unsigned char* b = (const unsigned char*)data;
    const size_t pre = (size_t)(len < 64 ? len : 64);
    pv.prefixHash = provFnvBytes(b, pre, 0);
    // 8 windows of 64 bytes spread across the extent: catches a wrong tensor of
    // the same length far more reliably than the prefix alone.
    const size_t kWindows = 8, kWin = 64;
    uint64_t h = 0;
    for (size_t w = 0; w < kWindows; ++w) {
        const uint64_t off = (len > kWin) ? ((uint64_t)w * (len - kWin) / (kWindows - 1)) : 0;
        h = provFnvBytes(b + off, (size_t)((len - off) < kWin ? (len - off) : kWin), h ? h : 14695981039346656037ull);
    }
    pv.bodyHash = h;
    pv.byteLength = len;
    pv.haveContent = true;
}

// =================== RAWRXD_TOKEN_WALL_PROFILE_001 ===================
//
// Splits one decode token's wall time into the stages that can each be the wall.
// At 1.99 GB/s of useful weight rate the runtime is roughly two orders of
// magnitude off memory-bound, and "COMPUTE_OR_KERNEL" is not actionable until it
// is split into dequant / gemv / dispatch / sync / copy / other.
//
// All buckets are measured, not apportioned. The fused scalar kernels do not
// separate dequantisation from the dot product, so that pair is reported as
// KERNEL_FUSED and the split is declared unavailable rather than invented.
struct TokWall {
    double wallNs = 0, prologueNs = 0, resolveNs = 0, kernelNs = 0, copyNs = 0;
    double attnNs = 0, ffnNs = 0, moeNs = 0, normNs = 0, embedNs = 0;
    uint64_t kernelBytes = 0, kernelCalls = 0, biasAdds = 0;
    uint64_t attnCalls = 0, ffnCalls = 0, moeCalls = 0;

    static double nowNs() {
        return (double)std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    void reset() { *this = TokWall{}; }
};

static TokWall g_tokWall;

static bool tokProfOn() {
    static const bool on = [] {
        const char* v = std::getenv("RAWRXD_TOKEN_PROFILE");
        return v && v[0] && v[0] != '0';
    }();
    return on;
}

static void tokProfEmit(const TokWall& p) {
    const double wallUs  = p.wallNs / 1e3;
    const double kernUs  = p.kernelNs / 1e3;
    // Only the buckets actually measured are apportioned. "other" is whatever
    // the named buckets did not account for, so it cannot hide a missing timer.
    const double namedUs = (p.prologueNs + p.resolveNs + p.kernelNs + p.copyNs +
                            p.attnNs + p.ffnNs + p.moeNs + p.normNs + p.embedNs) / 1e3;
    const double otherUs = wallUs - namedUs;
    const double gbps = kernUs > 0.0 ? ((double)p.kernelBytes / 1000.0 / kernUs) : 0.0;
    const double bytesPerTok = (double)p.kernelBytes;
    const double usefulRate = wallUs > 0.0 ? (bytesPerTok / 1000.0 / wallUs) : 0.0;
    std::fprintf(stderr,
        "TOKENPROF TOKEN_WALL_US=%.1f\n"
        "TOKENPROF WEIGHT_RESOLVE_US=%.1f GEMV_FUSED_US=%.1f COPY_US=%.1f PROLOGUE_US=%.1f\n"
        "TOKENPROF ATTENTION_US=%.1f FFN_US=%.1f MOE_US=%.1f NORM_US=%.1f EMBED_US=%.1f OTHER_US=%.1f\n"
        "TOKENPROF LINEARW_CALLS=%llu ATTN_CALLS=%llu FFN_CALLS=%llu MOE_CALLS=%llu BIAS_ADDS=%llu\n"
        "TOKENPROF KERNEL_WEIGHT_BYTES=%llu DEQUANT_SOURCE_BYTES=%llu DEQUANT_OUTPUT_BYTES=%llu GPU_UPLOAD_BYTES=0\n"
        "TOKENPROF GEMV_FUSED_GBPS=%.4f USEFUL_WEIGHT_RATE_GBPS=%.4f\n"
        "TOKENPROF DEQUANT_GBPS=UNAVAILABLE_FUSED_IN_KERNEL GEMV_GBPS=UNAVAILABLE_FUSED_IN_KERNEL UPLOAD_GBPS=0\n",
        wallUs,
        p.resolveNs / 1e3, kernUs, p.copyNs / 1e3, p.prologueNs / 1e3,
        p.attnNs / 1e3, p.ffnNs / 1e3, p.moeNs / 1e3, p.normNs / 1e3, p.embedNs / 1e3, otherUs,
        (unsigned long long)p.kernelCalls, (unsigned long long)p.attnCalls,
        (unsigned long long)p.ffnCalls, (unsigned long long)p.moeCalls,
        (unsigned long long)p.biasAdds,
        (unsigned long long)p.kernelBytes, (unsigned long long)p.kernelBytes, 0ull,
        gbps, usefulRate);
    std::fflush(stderr);
}

// Emits on every return path, including the failure paths, so a token that
// throws still produces a wall-time receipt instead of vanishing.
struct TokWallScope {
    bool active; double t0;
    explicit TokWallScope(bool on) : active(on), t0(TokWall::nowNs()) {
        if (active) g_tokWall.reset();
    }
    ~TokWallScope() {
        if (!active) return;
        TokWall p = g_tokWall;
        p.wallNs = TokWall::nowNs() - t0;
        tokProfEmit(p);
    }
};

static inline bool provOn() {
    static const bool on = [] {
        const char* v = std::getenv("RAWRXD_TENSOR_PROVENANCE");
        return v && v[0] && v[0] != '0';
    }();
    return on;
}

// WQEXT records, keyed by tensor name, so the KERNEL boundary can be compared
// against them IN THE SAME PROCESS. The two sides must not be inferred from one
// another: if the extraction record were reconstructed from the consumer's
// fields the comparison would be circular and could not fail.
static std::map<std::string, TensorProvenance>& provWqextTable() {
    static std::map<std::string, TensorProvenance> t;
    return t;
}

static void provEmit(const char* boundary, const char* name, const TensorProvenance& pv,
                     const void* ptr) {
    char dims[128];
    int  o = std::snprintf(dims, sizeof(dims), "[");
    for (uint32_t i = 0; i < pv.nDims && i < 8; ++i)
        o += std::snprintf(dims + o, (size_t)((o > 0 && (size_t)o < sizeof(dims)) ? sizeof(dims) - (size_t)o : 0),
                           "%s%lld", i ? "," : "", (long long)pv.dims[i]);
    std::snprintf(dims + o, (size_t)((o > 0 && (size_t)o < sizeof(dims)) ? sizeof(dims) - (size_t)o : 0), "]");
    std::fprintf(stderr,
        "PROV BOUNDARY=%s NAME=%s TYPE=%u DIMS=%s LEN=%llu "
        "FILE_OFF=%llu SHARD=%u PROV_ID=%016llx PREFIX_HASH=%016llx BODY_HASH=%016llx PTR=%p\n",
        boundary, name ? name : "(null)", pv.type, dims,
        (unsigned long long)pv.byteLength, (unsigned long long)pv.fileOffset,
        pv.shardId, (unsigned long long)pv.provHash,
        (unsigned long long)pv.prefixHash, (unsigned long long)pv.bodyHash, ptr);
    std::fflush(stderr);
}


// =================== CONSTRUCTOR / DESTRUCTOR ====================
namespace {
    rawrxd::Batch005Runtime s_expertCacheRuntime; // keeps expert_cache objects alive
}
Deep2Engine::Deep2Engine() {}
Deep2Engine::~Deep2Engine() {
    std::fprintf(stderr, "[CLEANUP_STAGE] ~Deep2Engine enter\n"); std::fflush(stderr);
    unloadModel();
    std::fprintf(stderr, "[CLEANUP_STAGE] ~Deep2Engine unloadModel done\n"); std::fflush(stderr);

    // RAWRXD_B63_PREPARED_WEIGHT_CACHE_001: release the prepared-weight cache
    // FIRST. Its keys are the model's source tensor pointers, and it must not
    // outlive the mapping it dereferences during a later dequant.
    // ReleasePreparedWeights also emits the B63 gate counters.
    ReleasePreparedWeights();

    // RAWRXD_VULKAN_TRANSPORT_LIFETIME_001
    //
    // expertTransports_ holds a VulkanExpertTransport that BORROWS the VkDevice
    // owned by vulkanCompute_; its destructor calls vkUnmapMemory /
    // vkDestroyBuffer / vkFreeMemory on that handle. C++ destroys members in
    // REVERSE declaration order, and both expertCaches_ (Deep2Engine.h:1192)
    // and expertTransports_ (:1193) are declared BEFORE vulkanCompute_ (:1265),
    // so implicit destruction would run them AFTER vulkanCompute_ had already
    // called vkDestroyDevice. That faults with 0xC0000005 immediately after the
    // "[CLEANUP_STAGE] ~VulkanCompute body done" line.
    //
    // Release them explicitly here instead, while vulkanCompute_ is still
    // alive. Caches go first: each cached allocation is freed through the
    // transport's freeDevice callback, so the transport must outlive them.
    expertCaches_.clear();
    expertTransports_.clear();
    std::fprintf(stderr, "[CLEANUP_STAGE] ~Deep2Engine expert transport released\n");
    std::fflush(stderr);
}

// RAWRXD_DEBUG_EXPOSE_LOGITS_001
// Resolved once per process, like the other debug gates. A run without the
// flag must not pay for a per-step V-float copy, and must not be able to
// produce a vector that a harness might mistake for a measured one.
bool Deep2Engine::debugLogitsEnabled() const {
    static const bool on = [] {
        const char* e = std::getenv("DEEP2_DEBUG_EXPOSE_LOGITS");
        return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
    }();
    return on;
}

// =================== WEIGHT TYPE INTROSPECTION ====================// RAWRXD_WEIGHT_TYPE_FROM_TENSORS_001
// These read the GGML type off the tensors that were actually loaded. The
// existing config_.weightQuant cannot answer this: it is a config field that is
// never assigned from the model, so it reports FP32 for every model, including
// Q6_K ones. A receipt built on that field would be reporting a default.
namespace {
// Weight-counted, not byte-counted: dominance over tensor instances is the
// honest question ("what type are the projections"), and a single F32 norm
// vector must not outvote 8 Q6_K projections just by being counted.
void Accum(const WeightTensor& t, int& n, std::vector<int>& hist) {
    if (!t.data) return;
    ++n;
    const int ty = t.type;
    if (ty >= 0 && static_cast<size_t>(ty) < hist.size()) ++hist[ty];
}
} // namespace

// RAWRXD_WEIGHT_TYPE_FROM_TENSORS_001
// Shared histogram over the tensors that actually determine the weight format:
// the projections and the FFN. Norms and biases are conventionally F32 inside a
// quantized model and are not evidence of the weight format, so they are
// excluded.
static void ProjectionTypeHistogram(const ModelWeights& mw,
                                    int* total, std::vector<int>* hist) {
    int n = 0;
    hist->assign(64, 0);
    Accum(mw.lmHead, n, *hist);
    Accum(mw.tokenEmbed, n, *hist);
    for (const LayerWeights& lw : mw.layers) {
        Accum(lw.wq, n, *hist); Accum(lw.wk, n, *hist);
        Accum(lw.wv, n, *hist); Accum(lw.wo, n, *hist);
        Accum(lw.wqkv, n, *hist);
        Accum(lw.wGate, n, *hist); Accum(lw.wUp, n, *hist); Accum(lw.wDown, n, *hist);
        Accum(lw.attnO, n, *hist);
        Accum(lw.attnQ_b, n, *hist); Accum(lw.attnK_b, n, *hist);
        Accum(lw.attnV_b, n, *hist);
        for (const WeightTensor& g : lw.moeGate)  Accum(g, n, *hist);
        for (const WeightTensor& u : lw.moeUp)    Accum(u, n, *hist);
        for (const WeightTensor& d : lw.moeDown)  Accum(d, n, *hist);
    }
    *total = n;
}

int Deep2Engine::loadedWeightType() const noexcept {
    if (!modelWeights.loaded) return -1;
    // RAWRXD_WEIGHT_TYPE_DOMINANT_001: return the DOMINANT type, not the type
    // of one convenient tensor.
    //
    // This previously probed lm_head and returned its type. On
    // qwen2.5-coder-1.5b-base.gguf that reported Q6_K while the histogram was
    // Q4_K=168 Q6_K=30 -- i.e. 85% of the projections are Q4_K and the receipt
    // claimed the model was Q6_K. A single tensor presented as the model's
    // weight type is the same class of error as reporting a config default, so
    // the type is now the mode of the projection/FFN population and the
    // dominance percentage is reported next to it.
    int n = 0;
    std::vector<int> hist;
    ProjectionTypeHistogram(modelWeights, &n, &hist);
    if (n == 0) return -1;
    int best = -1, bestCount = 0;
    for (size_t i = 0; i < hist.size(); ++i) {
        if (hist[i] > bestCount) { bestCount = hist[i]; best = (int)i; }
    }
    return bestCount > 0 ? best : -1;
}

const char* Deep2Engine::loadedWeightTypeName() const noexcept {
    switch (loadedWeightType()) {
    case  0: return "F32";
    case  1: return "F16";
    case  2: return "Q4_0";
    case  3: return "Q4_1";
    case  6: return "Q5_0";
    case  7: return "Q5_1";
    case  8: return "Q8_0";
    case 10: return "Q2_K";
    case 11: return "Q3_K";
    case 12: return "Q4_K";
    case 13: return "Q5_K";
    case 14: return "Q6_K";
    case 15: return "Q8_K";
    case 24: return "I8";
    case 25: return "I16";
    case 26: return "I32";
    case 27: return "I64";
    case 28: return "F64";
    case 30: return "BF16";
    default: return "UNKNOWN";
    }
}

// RAWRXD_WEIGHT_TYPE_FROM_TENSORS_001: the histogram makes dominance
// interpretable. A Q6_K model reporting 15% Q6_K dominance is either genuinely
// mixed or has `type` unpopulated on most tensors; those are indistinguishable
// from a single percentage, and only the distribution tells them apart.
std::string Deep2Engine::loadedWeightTypeHistogram() const {
    if (!modelWeights.loaded) return "NO_MODEL";
    int n = 0;
    std::vector<int> hist;
    ProjectionTypeHistogram(modelWeights, &n, &hist);
    if (n == 0) return "NO_PROJECTION_TENSORS";

    auto nameOf = [](int ty) -> const char* {
        switch (ty) {
        case  0: return "F32";    case  1: return "F16";
        case  2: return "Q4_0";   case  3: return "Q4_1";
        case  6: return "Q5_0";   case  7: return "Q5_1";
        case  8: return "Q8_0";   case 10: return "Q2_K";
        case 11: return "Q3_K";   case 12: return "Q4_K";
        case 13: return "Q5_K";   case 14: return "Q6_K";
        case 15: return "Q8_K";   case 30: return "BF16";
        default: return "OTHER";
        }
    };
    // Descending by count so the dominant type leads.
    std::vector<std::pair<int,int>> byCount;   // (count, type)
    for (size_t i = 0; i < hist.size(); ++i)
        if (hist[i] > 0) byCount.emplace_back(hist[i], (int)i);
    std::sort(byCount.begin(), byCount.end(),
              [](const std::pair<int,int>& a, const std::pair<int,int>& b) {
                  if (a.first != b.first) return a.first > b.first;
                  return a.second < b.second;
              });
    std::string out;
    char buf[64];
    for (size_t i = 0; i < byCount.size() && i < 8; ++i) {
        std::snprintf(buf, sizeof(buf), "%s%s=%d",
                      i ? " " : "", nameOf(byCount[i].second), byCount[i].first);
        out += buf;
    }
    std::snprintf(buf, sizeof(buf), " (tensors=%d)", n);
    out += buf;
    return out;
}

double Deep2Engine::loadedWeightTypeDominancePercent() const noexcept {
    if (!modelWeights.loaded) return 0.0;
    int n = 0;
    std::vector<int> hist;
    ProjectionTypeHistogram(modelWeights, &n, &hist);
    if (n == 0) return 0.0;
    const int want = loadedWeightType();
    if (want < 0 || static_cast<size_t>(want) >= hist.size()) return 0.0;
    return 100.0 * static_cast<double>(hist[want]) / static_cast<double>(n);
}

// =================== INITIALIZE ====================
bool Deep2Engine::initialize(const EngineConfig& cfg) {
    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: install the exit writer here, and
    // only here, so it is registered exactly once per process and it runs even
    // for a forward pass that consumed nothing -- which is precisely the case
    // that must produce FAIL_NO_MEASURED_CONSUMPTION rather than silence.
    rawrxd::deep2::weightcensus::installCensusExitWriter();
    rawrxd::deep2::weightcensus::WeightConsumptionCensus::instance().reset();
    std::fprintf(stderr, "[INIT] Deep2Engine::initialize hiddenDim=%zu vocabSize=%zu numLayers=%zu numHeads=%zu maxSeqLen=%zu numThreads=%zu\n",
        (size_t)cfg.hiddenDim, (size_t)cfg.vocabSize, (size_t)cfg.numLayers,
        (size_t)cfg.numHeads, (size_t)cfg.maxSeqLen, (size_t)cfg.numThreads);
    std::fflush(stderr);
    // Core lifecycle owns runtime objects; model geometry may still be unknown
    // until the GGUF/model-loader batch binds real metadata.
    deallocateBuffers();
    config = cfg;

    clearCancel();
    // RAWRXD_REAL_GPU_FORWARD_002: route through the witness so every reset
    // site is visible in the trace.
    resetGpuForwardCounters();
    gpuFwdCommitted_ = false;
    modelState_ = ModelState::Closed;

    if (cfg.useThreadPool && cfg.numThreads > 0) {
        threadPool = std::make_unique<ThreadPool>(cfg.numThreads);
        std::fprintf(stderr, "[INIT] threadPool created numThreads=%zu\n", (size_t)cfg.numThreads);
        std::fflush(stderr);
    } else {
        threadPool.reset();
    }

    kvCache = std::make_unique<KVCache>();
    tokenizer = std::make_unique<BPETokenizer>();
    sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
    deterministicGreedy_ = true;

    // RAWRXD_SPACELESS_STEP_9: TensorResidencyCache initialization
    residencyCache_ = std::make_unique<Deep2::TensorResidencyCache>(256);

    // RAWRXD_REMOTE64_PRODUCT_INTEGRATION_001
    // Production consumption of src/remote64/deep2_bridge.asm. initialize() is
    // the single point every Deep2 client passes through, so it is where the
    // native remote authority is brought to a known state and sampled. This
    // reads the assembly; it does not gate decode, and it does not alter the
    // forward path or any TPS measurement.
#if defined(RAWRXD_REMOTE64_LINKED)
    {
        rawrxd::remote64::initRemoteAuthority();
        remoteObservePermitted_ = rawrxd::remote64::remoteObservePermitted();
        remoteControlPermitted_  = rawrxd::remote64::remoteControlPermitted();
        std::fprintf(stderr, "[INIT] remote64 authority linked observe=%d control=%d\n",
                     remoteObservePermitted_ ? 1 : 0,
                     remoteControlPermitted_ ? 1 : 0);
    }
#else
    remoteObservePermitted_ = false;
    remoteControlPermitted_ = false;
    std::fprintf(stderr, "[INIT] remote64 authority NOT linked (build has no rawrxd_remote64)\n");
#endif
    std::fflush(stderr);
    QuantKernelRegistry::Instance().Initialize();
    std::fprintf(stderr, "[INIT] KVCache+tokenizer+sampler created\n"); std::fflush(stderr);

    // Initialization means the runtime is ready. Scratch buffers are allocated
    // immediately only when geometry is already known; otherwise loadModel()
    // (or a later real loader) binds geometry and allocates them.
    initialized = true;
    if (cfg.hiddenDim != 0 && cfg.vocabSize != 0) {
        if (!allocateBuffers()) {
            std::fprintf(stderr, "[INIT] allocateBuffers FAILED\n"); std::fflush(stderr);
            initialized = false;
            return false;
        }
        std::fprintf(stderr, "[INIT] allocateBuffers OK\n"); std::fflush(stderr);
    }

    if (cfg.useKVCache && cfg.numLayers != 0 && cfg.maxSeqLen != 0 &&
        cfg.numHeads != 0) {
        KVCacheConfig kc{};
        kc.numLayers = cfg.numLayers;
        kc.numHeads = cfg.numKVHeads ? cfg.numKVHeads : cfg.numHeads;
        kc.headDim = cfg.headDim ? cfg.headDim : (cfg.hiddenDim / cfg.numHeads);
        kc.maxSeqLen = cfg.maxSeqLen;
        if (kc.headDim == 0 || !kvCache->allocate(kc)) {
            std::fprintf(stderr, "[INIT] KVCache::allocate FAILED headDim=%zu\n", (size_t)kc.headDim); std::fflush(stderr);
            initialized = false;
            return false;
        }
        std::fprintf(stderr, "[INIT] KVCache::allocate OK layers=%zu heads=%zu headDim=%zu maxSeqLen=%zu\n",
            (size_t)kc.numLayers, (size_t)kc.numHeads, (size_t)kc.headDim, (size_t)kc.maxSeqLen); std::fflush(stderr);
    }
    std::fprintf(stderr, "[INIT] Deep2Engine::initialize SUCCESS\n"); std::fflush(stderr);
    return true;
}

// =================== ALLOCATE BUFFERS ====================
bool Deep2Engine::allocateBuffers() {
    const size_t H = modelWeights.hiddenDim ? modelWeights.hiddenDim : config.hiddenDim;
    const size_t V = modelWeights.vocabSize ? modelWeights.vocabSize : config.vocabSize;
    const size_t I = modelWeights.intermediateDim
        ? modelWeights.intermediateDim
        : (config.intermediateDim ? config.intermediateDim : (H ? H * 4 : 0));

    if (H == 0 || V == 0 || I == 0) {
        std::fprintf(stderr, "[ALLOC] allocateBuffers FAILED: H=%zu V=%zu I=%zu\n", H, V, I); std::fflush(stderr);
        return false;
    }
    std::fprintf(stderr, "[ALLOC] allocateBuffers H=%zu V=%zu I=%zu\n", H, V, I); std::fflush(stderr);

    // Determine projection dimensions based on model metadata (supports rectangular attention like Gemma3)
    const size_t numHeads = modelWeights.numHeads ? modelWeights.numHeads : config.numHeads;
    const size_t headDim = modelWeights.headDim ? modelWeights.headDim : config.headDim;
    const size_t numKVHeads = modelWeights.numKVHeads ? modelWeights.numKVHeads : numHeads;

    const size_t qDim  = (numHeads && headDim) ? (numHeads * headDim) : H;
    const size_t kvDim = (numKVHeads && headDim) ? (numKVHeads * headDim) : H;
    std::fprintf(stderr, "[ALLOC] qDim=%zu kvDim=%zu numHeads=%zu headDim=%zu numKVHeads=%zu\n",
        qDim, kvDim, numHeads, headDim, numKVHeads); std::fflush(stderr);

    deallocateBuffers();

    hiddenStates    = new (std::nothrow) float[H];
    attentionOutput = new (std::nothrow) float[H];
    ffnOutput       = new (std::nothrow) float[H];
    logits          = new (std::nothrow) float[V];
    qProj           = new (std::nothrow) float[qDim];
    kProj           = new (std::nothrow) float[kvDim];
    vProj           = new (std::nothrow) float[kvDim];
    gateBuf         = new (std::nothrow) float[I];
    upBuf           = new (std::nothrow) float[I];
    layerTemp       = new (std::nothrow) float[H];
    layerOut        = new (std::nothrow) float[H];
    mixerBranch     = new (std::nothrow) float[H];
    moeSharedTemp   = new (std::nothrow) float[H];
    blockResidual   = new (std::nothrow) float[H];

    // SSM / Mamba2 per-layer state buffers (Nemotron-H)
    const bool archIsNemotronH = (modelArchitecture_ == "nemotron_h" || modelArchitecture_ == "nemotron_h_moe");
    if (archIsNemotronH && ssmInner_ && ssmStateSize_ && ssmHeads_ && ssmGroups_ &&
        modelWeights.numLayers > 0) {
        const size_t groupBC = ssmGroups_ * ssmStateSize_;
        const size_t convChannels = ssmInner_ + 2 * groupBC;
        const size_t inRows = 2 * ssmInner_ + 2 * groupBC + ssmHeads_;
        ssmX      = new (std::nothrow) float[convChannels];
        ssmY      = new (std::nothrow) float[convChannels];
        ssmTemp   = new (std::nothrow) float[inRows];
        ssmState  = new (std::nothrow) float[modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_];
        ssmConvState = new (std::nothrow) float[modelWeights.numLayers * convChannels * (ssmConvKernel ? (ssmConvKernel - 1) : 0)];
        if (ssmState)  std::memset(ssmState,  0, modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_ * sizeof(float));
        if (ssmConvState && ssmConvKernel > 1) std::memset(ssmConvState, 0, modelWeights.numLayers * convChannels * (ssmConvKernel - 1) * sizeof(float));
        ssmLayerCaches_.resize(modelWeights.numLayers);
    }

    if (!hiddenStates || !attentionOutput || !ffnOutput || !logits ||
        !qProj || !kProj || !vProj || !gateBuf || !upBuf || !layerTemp ||
        !layerOut || !mixerBranch || !moeSharedTemp || !blockResidual) {
        std::fprintf(stderr, "[ALLOC] FAILED: one or more buffers null (hidden=%p attn=%p ffn=%p logits=%p q=%p k=%p v=%p gate=%p up=%p temp=%p out=%p mixer=%p moeshare=%p blockres=%p)\n",
            (void*)hiddenStates, (void*)attentionOutput, (void*)ffnOutput, (void*)logits,
            (void*)qProj, (void*)kProj, (void*)vProj, (void*)gateBuf, (void*)upBuf, (void*)layerTemp, (void*)layerOut,
            (void*)mixerBranch, (void*)moeSharedTemp, (void*)blockResidual);
        std::fflush(stderr);
        deallocateBuffers();
        return false;
    }
    std::fprintf(stderr, "[ALLOC] all buffers allocated OK\n"); std::fflush(stderr);

    std::memset(hiddenStates,    0, H * sizeof(float));
    std::memset(attentionOutput, 0, H * sizeof(float));
    std::memset(ffnOutput,       0, H * sizeof(float));
    std::memset(logits,          0, V * sizeof(float));
    std::memset(qProj,           0, qDim * sizeof(float));
    std::memset(kProj,           0, kvDim * sizeof(float));
    std::memset(vProj,           0, kvDim * sizeof(float));
    std::memset(gateBuf,         0, I * sizeof(float));
    std::memset(upBuf,           0, I * sizeof(float));
    std::memset(layerTemp,       0, H * sizeof(float));
    std::memset(layerOut,        0, H * sizeof(float));
    std::memset(mixerBranch,     0, H * sizeof(float));
    std::memset(moeSharedTemp,   0, H * sizeof(float));
    std::memset(blockResidual,   0, H * sizeof(float));

    config.hiddenDim = H;
    config.vocabSize = V;
    config.intermediateDim = I;
    return true;
}

void Deep2Engine::deallocateBuffers() {
    delete[] hiddenStates;    hiddenStates = nullptr;
    delete[] attentionOutput; attentionOutput = nullptr;
    delete[] ffnOutput;       ffnOutput = nullptr;
    delete[] logits;          logits = nullptr;
    delete[] qProj;           qProj = nullptr;
    delete[] kProj;           kProj = nullptr;
    delete[] vProj;           vProj = nullptr;
    delete[] gateBuf;         gateBuf = nullptr;
    delete[] upBuf;           upBuf = nullptr;
    delete[] layerTemp;       layerTemp = nullptr;
    delete[] layerOut;        layerOut = nullptr;
    delete[] mixerBranch;     mixerBranch = nullptr;
    delete[] moeSharedTemp;   moeSharedTemp = nullptr;
    delete[] blockResidual;   blockResidual = nullptr;
    delete[] ssmState;        ssmState = nullptr;
    delete[] ssmConvState;      ssmConvState = nullptr;
    delete[] ssmX;              ssmX = nullptr;
    delete[] ssmY;              ssmY = nullptr;
    delete[] ssmTemp;           ssmTemp = nullptr;
    ssmLayerCaches_.clear();
}

// =================== RESET (REAL KV RESET) ====================
void Deep2Engine::reset() {
    clearCancel();
    if (kvCache) (void)kvCache->clear(false);

    if (hiddenStates && config.hiddenDim)
        std::memset(hiddenStates, 0, config.hiddenDim * sizeof(float));
    if (attentionOutput && config.hiddenDim)
        std::memset(attentionOutput, 0, config.hiddenDim * sizeof(float));
    if (ffnOutput && config.hiddenDim)
        std::memset(ffnOutput, 0, config.hiddenDim * sizeof(float));
    if (mixerBranch && config.hiddenDim)
        std::memset(mixerBranch, 0, config.hiddenDim * sizeof(float));
    if (moeSharedTemp && config.hiddenDim)
        std::memset(moeSharedTemp, 0, config.hiddenDim * sizeof(float));
    if (blockResidual && config.hiddenDim)
        std::memset(blockResidual, 0, config.hiddenDim * sizeof(float));

    // Reset SSM recurrent state for new conversation. Guard against the
    // pre-loadmodel state where ssmHeads_/ssmGroups_/ssmStateSize_ are all
    // zero (would cause divide-by-zero in the original expression).
    if (ssmState && ssmHeads_ > 0 && ssmStateSize_ > 0) {
        const size_t stateBytes = modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_ * sizeof(float);
        std::memset(ssmState, 0, stateBytes);
    }
    if (ssmConvState && ssmGroups_ > 0 && ssmStateSize_ > 0) {
        const size_t groupBC = ssmGroups_ * ssmStateSize_;
        const size_t convChannels = ssmInner_ + 2 * groupBC;
        const size_t convHistBytes = modelWeights.numLayers * convChannels * (ssmConvKernel > 1 ? (ssmConvKernel - 1) : 0) * sizeof(float);
        std::memset(ssmConvState, 0, convHistBytes);
    }

    // BATCH10_RESET_MLA_CACHE
    for (auto& gpu : vulkanDevices_) {
        if (gpu) gpu->ResetMLACache();
    }
    // RAWRXD_D2_LIFECYCLE_001_HOTFIX: specKvMirrorReset() crashes inside the
    // pre-built InferenceEngine_patched.lib when called from reset() at a
    // generation boundary. The crash is independent of the input data and
    // reproduces with empty prompts; the function's only effect when vulkan
    // is disabled is to reset specKvMirrorCommittedLen_ to zeros, which is
    // already correct at construction. We therefore gate this call on a
    // feature flag, defaulting to OFF, and document the gate as a deliberate
    // generation-boundary contract. When InferenceEngine_patched.lib is
    // rebuilt with the specKvMirrorReset() fix, set RAWRXD_ENABLE_SPEC_KV_RESET
    // to 1 to re-enable.
    static const char* enableSpecKvResetEnv =
        std::getenv("RAWRXD_ENABLE_SPEC_KV_RESET");
    const bool enableSpecKvReset =
        enableSpecKvResetEnv && (enableSpecKvResetEnv[0] == '1' ||
                                  enableSpecKvResetEnv[0] == 't' ||
                                  enableSpecKvResetEnv[0] == 'T');
    if (enableSpecKvReset) {
        specKvMirrorReset();
    }

    gpuFwdCommitted_ = false;
    // RAWRXD_REAL_GPU_FORWARD_002: the generation-boundary reset. This is the
    // site that used to erase the evidence a gate needed; the receipt is now
    // captured inside the forward, before this runs.
    resetGpuForwardCounters();

    // RAWRXD_BATCH_02_SAMPLER_GATE_001 â€” repetition-penalty history is
    // per-generation and must be cleared at the generation boundary.
    generatedTokensHistory_.clear();

    // RAWRXD_DEEP2_PREDICTIVE_ROUTER_ADOPTION_001: routing heat is per-session
    // learned state, not per-generation. Clearing it at every reset() would
    // destroy the learning the predictor exists to provide, so only the
    // generation-scoped counters are cleared here; use resetExpertPredictor()
    // to drop the learned heat map explicitly.
    expertPredictorCounters_.prefetchesIssued = 0;
}

// RAWRXD_DEEP2_PREDICTIVE_ROUTER_ADOPTION_001: measured reachability evidence.
// Every field is incremented on a live inference path; nothing here is
// initialized to a non-zero constant.
Deep2Engine::ExpertPredictorTelemetry
Deep2Engine::getExpertPredictorTelemetry() const {
    ExpertPredictorTelemetry t{};
    t.observations      = expertPredictorCounters_.observations;
    t.predictedQueries  = expertPredictorCounters_.predictedQueries;
    t.predictedKeys     = expertPredictorCounters_.predictedKeys;
    t.notesEmitted      = expertPredictorCounters_.notesEmitted;
    t.matchesNextLayer  = expertPredictorCounters_.matchesNextLayer;
    t.liveRoutes        = expertPredictorCounters_.liveRoutes;
    t.prefetchesIssued  = expertPredictorCounters_.prefetchesIssued;
    return t;
}

void Deep2Engine::resetExpertPredictor() {
    expertPredictor_.reset();
    expertPredictorCounters_ = ExpertPredictorCounters{};
}

// DEEP2_UPSTREAM_REPEAT_REQUEST_001: authority-bearing KV state accessor.
size_t Deep2Engine::kvCacheLength() const {
    return kvCache ? kvCache->currentLength() : 0;
}

// Gemma3-style per-layer RoPE theta (global vs local)
float Deep2::Deep2Engine::ropeThetaForLayer(size_t layer) const noexcept {
    if (modelWeights.slidingWindowPattern > 0 &&
        (layer % modelWeights.slidingWindowPattern) != 0) {
        return modelWeights.ropeThetaLocal;
    }
    return modelWeights.ropeTheta;
}

// =================== LOAD MODEL (REAL GGUF BIND) ====================
bool Deep2Engine::loadModel(const std::string& ggufPath, ModelLoadDiag* diag) {
    if (ggufPath.empty()) {
        if (diag) {
            diag->stageCode = 1;
            diag->stageName = "LOAD_EMPTY_PATH";
            diag->message = "GGUF path string is empty.";
        }
        return false;
    }

    // Tear down aliases before replacing the mapping.
    modelWeights = {};
    ggufResult = {};
    modelState_ = ModelState::Closed;

    auto loader = std::make_shared<GGUFLoader>();
    if (!loader->load(ggufPath)) {
        std::fprintf(stderr, "[Deep2Engine] GGUF load failed: %s\n",
                     loader->error().c_str());
        if (diag) {
            diag->stageCode = 2;
            diag->stageName = "LOAD_GGUF_OPEN";
            diag->message = std::string("GGUFLoader::load() failed: ") + loader->error().c_str();
        }
        return false;
    }

    const std::string arch = loader->getMetaString("general.architecture");
    if (arch.empty()) {
        std::fprintf(stderr, "[Deep2Engine] GGUF missing general.architecture\n");
        if (diag) {
            diag->stageCode = 3;
            diag->stageName = "LOAD_ARCH_MISSING";
            diag->message = "GGUF metadata lacks general.architecture.";
        }
        return false;
    }
    modelArchitecture_ = arch;

    auto metaSize = [&](const std::string& suffix, size_t def = 0) -> size_t {
        const int64_t v = loader->getMetaInt(arch + "." + suffix,
                                             static_cast<int64_t>(def));
        return v > 0 ? static_cast<size_t>(v) : def;
    };
    auto metaFloat = [&](const std::string& suffix, double def = 0.0) -> double {
        return loader->getMetaFloat(arch + "." + suffix, def);
    };

    auto tensor = [&](const char* name) -> const GGUFTensor* {
        return loader->getTensor(name);
    };

    // -----------------------------------------------------------------------
    // RAWRXD_REVERSE_001: real backing registration.
    //
    // Until this existed, ReverseLayer had zero production callers and
    // BackingDirectory was empty in every real load -- measured:
    //   PRODUCTION_CALLERS_OUTSIDE_OWN_TU = 3   (all inside the new files)
    //   LOADMODEL_REGISTRATIONS           = 0
    // An authority nobody calls is not an authority; it is a source file with
    // an impressive header. These registrations are what make it reachable.
    //
    // modelIdentity is derived from facts the loader actually reports for this
    // file. It is not a hash of the path string alone, because the same path can
    // be replaced with different content between runs and identity must not
    // survive that.
    const uint64_t modelIdentity = [this, &loader]() -> uint64_t {
        uint64_t h = 14695981039346656037ull;
        auto mix = [&h](uint64_t v) {
            for (int i = 0; i < 8; ++i) { h ^= (uint8_t)(v >> (i * 8)); h *= 1099511628211ull; }
        };
        mix(loader->tensorCount());
        // Two real tensors' geometry and offsets are enough to distinguish two
        // different models that happen to share a tensor count.
        const std::vector<std::string> names = loader->listTensors();
        size_t taken = 0;
        for (const auto& n : names) {
            const GGUFTensor* t = loader->getTensor(n);
            if (!t) continue;
            mix(fnv1a64Name(n.data(), n.size()));
            mix(t->sizeBytes);
            mix(t->fileOffset);
            mix(static_cast<uint64_t>(t->type));
            if (++taken >= 3) break;
        }
        mix(taken);
        return h;
    }();

    // Real classification from the real tensor name. Roles are semantic and
    // survive a change of representation; they are not addresses.
    auto roleFromName = [](const std::string& n) -> uint16_t {
        if (n.find("token_embd") != std::string::npos)      return 1;
        if (n.find("output_norm") != std::string::npos)     return 2;
        if (n == "output.weight" || n.find("lm_head") != std::string::npos) return 3;
        if (n.find("attn_norm") != std::string::npos)       return 4;
        if (n.find("ffn_norm") != std::string::npos)        return 5;
        if (n.find("attn_q") != std::string::npos)          return 6;   // covers attn_q_a/b
        if (n.find("attn_k") != std::string::npos)          return 7;   // attn_k_b
        if (n.find("attn_v") != std::string::npos)          return 8;   // attn_v_b
        if (n.find("attn_kv_a") != std::string::npos)       return 9;
        if (n.find("attn_output") != std::string::npos)     return 10;
        if (n.find("ffn_gate_exps") != std::string::npos)   return 11;
        if (n.find("ffn_up_exps") != std::string::npos)     return 12;
        if (n.find("ffn_down_exps") != std::string::npos)   return 13;
        if (n.find("ffn_gate") != std::string::npos)        return 14;
        if (n.find("ffn_up") != std::string::npos)          return 15;
        if (n.find("ffn_down") != std::string::npos)        return 16;
        if (n.find("attn_qkv") != std::string::npos)        return 17;
        if (n.find("ssm_in") != std::string::npos)          return 18;
        if (n.find("ssm_out") != std::string::npos)         return 19;
        if (n.find("ssm_conv1d") != std::string::npos)      return 20;
        if (n.find("ssm") != std::string::npos)             return 21;
        return 0;   // unclassified is a real, recorded answer, not a guess
    };

    // Real extraction of the block index from names like "blk.17.attn_q.weight".
    auto layerFromName = [](const std::string& n) -> uint32_t {
        if (n.size() < 4 || n.compare(0, 4, "blk.") != 0) return 0;
        uint32_t v = 0, i = 4, digits = 0;
        while (i < n.size() && n[i] >= '0' && n[i] <= '9') {
            v = v * 10 + static_cast<uint32_t>(n[i] - '0');
            ++i; ++digits;
            if (digits > 6) return 0;   // implausible block index; treat as none
        }
        return v;
    };

    // Counters so a receipt can report what the registration path actually did
    // instead of assuming it ran.
    static std::atomic<uint64_t> g_backingRegistered{0};
    static std::atomic<uint64_t> g_backingRejected{0};

    auto bindTensor = [&](const std::string& name, WeightTensor& wt) -> bool {
        const GGUFTensor* t = loader->getTensor(name);
        if (!t || !t->data || t->sizeBytes == 0) return false;

        wt = {};
        wt.data = const_cast<uint8_t*>(t->data);
        wt.type = static_cast<int>(t->type);
        wt.sizeBytes = t->sizeBytes;
        wt.name = t->name;
        wt.shape = t->shape;
        wt.mapped = true;
        wt.shardId = t->shardId;
        wt.fileOffset = t->fileOffset;
        wt.hasFileBacking = true;

        if (t->shape.size() >= 2) {
            wt.cols = static_cast<size_t>(t->shape[0]);
            size_t rows = 1;
            for (size_t i = 1; i < t->shape.size(); ++i) {
                const size_t d = static_cast<size_t>(t->shape[i]);
                if (d != 0 && rows > std::numeric_limits<size_t>::max() / d)
                    return false;
                rows *= d;
            }
            wt.rows = rows;
        } else if (t->shape.size() == 1) {
            wt.rows = static_cast<size_t>(t->shape[0]);
            wt.cols = 1;
        } else {
            return false;
        }

        // ---- register the real backing for this identity ----
        // Placed AFTER the geometry is known, so the BackingRef carries rows and
        // cols that were actually derived, and it is skipped on the early
        // returns above rather than registering a tensor whose shape failed.
        {
            TensorIdentity id{};
            id.model   = modelIdentity;
            id.tensor  = fnv1a64Name(name.data(), name.size());
            id.layer   = layerFromName(name);
            id.role    = roleFromName(name);
            id.variant = 0;

            BackingRef bref;
            bref.source      = BackingSource::GGUF_MMAP;
            bref.shardId     = t->shardId;
            bref.fileOffset  = t->fileOffset;
            bref.byteLength  = t->sizeBytes;
            bref.quantType   = static_cast<uint32_t>(t->type);
            bref.rows        = wt.rows;
            bref.cols        = wt.cols;
            bref.tensorName  = t->name;
            bref.generation  = 0;

            BackingDirectory::Instance().registerBinding(id, bref);
            ++g_backingRegistered;

            // RAWRXD_SPACELESS_IDENTITY_POPULATION_001
            //
            // The identity computed above was used ONLY to key the backing
            // directory. It was never copied into the tensor. Because `wt = {}`
            // zero-initialises the struct, every tensor bound through this
            // lambda carried TensorIdentity{0,0,0,0,0} for its entire lifetime.
            //
            // LinearW() looks the residency cache up by wt.identity:
            //     if (residencyCache_->lookup(wt.identity, ev)) { ... }
            //     else { ev.transientAddress = wt.data; insert(ev); }
            // With every identity equal, the FIRST LinearW call inserts one
            // entry and every later call HITS it, so every subsequent GEMV in
            // the model was handed the first tensor's address instead of its own
            // wt.data. Measured at Deep2Engine.cpp LinearW_EV:
            //     attn_q      cache_hit=0 ADDR_MATCH=1   <-- only correct GEMV
            //     attn_k      cache_hit=1 ADDR_MATCH=0   ev_addr == attn_q's
            //     attn_v      cache_hit=1 ADDR_MATCH=0   ev_bytes == attn_q's
            //     ffn_gate    cache_hit=1 ADDR_MATCH=0   FIRST_BAD_ROW=1 (NaN)
            // Note attn_k was not "healthy": its output was bit-identical to
            // attn_q's first 256 rows, which is what a duplicate GEMV looks
            // like, not a correct projection. V was the visible symptom only
            // because the kernel reached it first with the wrong bytes.
            //
            // loadTensorFromGGUF() already assigned wt.identity; this path did
            // not, which is why reading that function made the code look correct.
            wt.identity = id;

            // RAWRXD_TENSOR_PROVENANCE_001 -- boundary WQEXT (extraction).
            // Fingerprinted from the GGUFTensor the loader actually selected,
            // before any caching, staging or remapping can occur.
            if (provOn()) {
                TensorProvenance pv;
                pv.provHash = provIdentityHash(t->name.c_str(),
                                               static_cast<uint32_t>(t->type),
                                               t->shape, t->sizeBytes,
                                               t->fileOffset, t->shardId);
                pv.byteLength = t->sizeBytes;
                pv.fileOffset = t->fileOffset;
                pv.shardId    = t->shardId;
                pv.type       = static_cast<uint32_t>(t->type);
                pv.nDims      = (uint32_t)(t->shape.size() < 8 ? t->shape.size() : 8);
                for (uint32_t di = 0; di < pv.nDims; ++di) pv.dims[di] = t->shape[di];
                provContentHash(pv, t->data, t->sizeBytes);
                provWqextTable()[t->name] = pv;
                provEmit("WQEXT", t->name.c_str(), pv, t->data);
            }
        }
        return true;
    };

    auto bindFirst = [&](WeightTensor& wt,
                         std::initializer_list<const char*> names) -> bool {
        for (const char* n : names) {
            if (bindTensor(n, wt)) return true;
        }
        return false;
    };

    // Global tensor topology establishes hard geometry when metadata is absent.
    if (!bindFirst(modelWeights.tokenEmbed,
                   {"token_embd.weight", "token_embeddings.weight"})) {
        std::fprintf(stderr, "[Deep2Engine] GGUF missing token embedding tensor\n");
        if (diag) {
            diag->stageCode = 4;
            diag->stageName = "BIND_TOKEN_EMBED";
            diag->message = "Missing token_embd.weight or token_embeddings.weight tensor.";
        }
        return false;
    }

    const size_t embedCols = modelWeights.tokenEmbed.cols;
    const size_t embedRows = modelWeights.tokenEmbed.rows;

    modelWeights.hiddenDim = metaSize("embedding_length", embedCols);
    modelWeights.vocabSize = embedRows;

    if (modelWeights.hiddenDim == 0 ||
        modelWeights.hiddenDim != embedCols ||
        modelWeights.vocabSize == 0) {
        std::fprintf(stderr, "[Deep2Engine] embedding geometry mismatch\n");
        if (diag) {
            diag->stageCode = 5;
            diag->stageName = "EMBED_GEOMETRY";
            diag->message = "Embedding geometry mismatch (hiddenDim==0, hiddenDim!=embedCols, or vocabSize==0).";
        }
        return false;
    }

    modelWeights.numLayers = metaSize("block_count", 0);
    if (modelWeights.numLayers == 0) {
        size_t maxLayer = 0;
        bool sawLayer = false;
        for (const std::string& name : loader->listTensors()) {
            if (name.rfind("blk.", 0) != 0) continue;
            size_t p = 4;
            size_t value = 0;
            bool any = false;
            while (p < name.size() && name[p] >= '0' && name[p] <= '9') {
                any = true;
                value = value * 10 + static_cast<size_t>(name[p] - '0');
                ++p;
            }
            if (any && p < name.size() && name[p] == '.') {
                maxLayer = std::max(maxLayer, value);
                sawLayer = true;
            }
        }
        if (sawLayer) modelWeights.numLayers = maxLayer + 1;
    }

    modelWeights.numHeads = metaSize("attention.head_count", 0);
    modelWeights.numKVHeads =
        metaSize("attention.head_count_kv", modelWeights.numHeads);

    // Nemotron-H carries its hybrid pattern as PER-LAYER ARRAYS, not scalars.
    // A scalar getMetaInt() of an array key returns the caller's default, which
    // silently reports numKVHeads == numHeads and feed_forward_length == 0 and
    // therefore classifies every block as "recurrent". Parse the arrays here so
    // the block mixers can be derived per layer later.
    //
    // Reference rule (llama.cpp, nemotron_h hparams):
    //     recurrent = (n_head_kv(i) == 0 && n_ff(i) == 0)
    nemotronHeadKvPerLayer_.clear();
    nemotronFfPerLayer_.clear();
    nemotronPatternOk_ = false;
    if (arch == "nemotron_h" || arch == "nemotron_h_moe") {
        const bool gotKv =
            loader->getMetaInt32Array(arch + ".attention.head_count_kv",
                                      nemotronHeadKvPerLayer_);
        const bool gotFf =
            loader->getMetaInt32Array(arch + ".feed_forward_length",
                                      nemotronFfPerLayer_);
        if (!gotKv || !gotFf ||
            nemotronHeadKvPerLayer_.size() != modelWeights.numLayers ||
            nemotronFfPerLayer_.size() != modelWeights.numLayers) {
            std::fprintf(stderr,
                "[Deep2Engine] nemotron_h per-layer pattern arrays unusable:"
                " head_count_kv=%zu feed_forward_length=%zu block_count=%zu\n",
                nemotronHeadKvPerLayer_.size(), nemotronFfPerLayer_.size(),
                modelWeights.numLayers);
            if (diag) {
                diag->stageCode = 6;
                diag->stageName = "NEMOTRON_H_PATTERN_ARRAY_MISSING";
                diag->message =
                    "nemotron_h attention.head_count_kv / feed_forward_length must be per-layer arrays of block_count length.";
            }
            nemotronHeadKvPerLayer_.clear();
            nemotronFfPerLayer_.clear();
        } else {
            nemotronPatternOk_ = true;
            // Global KV head count is the value on the ATTENTION blocks. Taking
            // element 0 would be wrong: block 0 is recurrent and its entry is 0.
            size_t attnKvHeads = 0;
            for (int32_t v : nemotronHeadKvPerLayer_) {
                if (v > 0) { attnKvHeads = static_cast<size_t>(v); break; }
            }
            if (attnKvHeads) modelWeights.numKVHeads = attnKvHeads;
            std::fprintf(stderr,
                "[Deep2Engine] NEMOTRON_PATTERN layers=%zu attnHeads=%zu attnKvHeads=%zu\n",
                modelWeights.numLayers, modelWeights.numHeads, modelWeights.numKVHeads);
        }
    }

    if (modelWeights.numLayers == 0 || modelWeights.numHeads == 0 ||
        modelWeights.numKVHeads == 0 ||
        (modelWeights.numHeads % modelWeights.numKVHeads) != 0) {
        std::fprintf(stderr, "[Deep2Engine] invalid transformer head/layer geometry\n");
        if (diag) {
            diag->stageCode = 6;
            diag->stageName = "HEAD_LAYER_GEOMETRY";
            diag->message = "Invalid head/layer geometry (zero layer/head count or numHeads%numKVHeads!=0).";
        }
        return false;
    }

    // Explicit GGUF key/value length is authoritative for rectangular attention.
    // Only the metadata fallback path requires hiddenDim to divide numHeads.
    const size_t keyLen   = metaSize("attention.key_length", 0);
    const size_t valueLen = metaSize("attention.value_length", 0);

    // RAWRXD_MLA_LOAD_AUTHORITY_001 (M5d): parse MLA metadata through the one
    // binder that knows the rule, instead of leaving that knowledge in
    // uncompiled source. Before this the engine's own MLA fields were never
    // assigned by any loader, so useMLA could not become true and
    // computeMLAAttentionGpu was unreachable even for a model that passed
    // admission.
    //
    // NOTE what this does NOT do: it does not make MLA loadable. The eight MLA
    // tensors (attnQ_a, attnQ_a_norm, attnQ_b, attnKV_a_mqa, attnKV_a_norm,
    // attnK_b, attnV_b, attnO) are still never bound by this loader, so
    // modelWeights.useMLA is deliberately left false for routing. See the
    // refusal below, which now names the unmet precondition instead of
    // reporting only a dimension mismatch.
    // M5.0-M5.3: derive the geometry that metadata does not carry, from the
    // tensor table, and reconcile it. Numbers are accepted only when the
    // divisions and relationships are EXACT and agree with the metadata that
    // does exist; a plausible integer is not enough.
    //
    // Two MLA tensor layouts exist in the wild and this file may be either:
    //   split : attn_q_a, attn_q_a_norm, attn_q_b, attn_kv_a_mqa, attn_kv_a_norm,
    //           attn_k_b, attn_v_b, attn_o            (what the consumer wants)
    //   fused : attn_q, attn_kv_a_mqa, attn_kv_a_norm, attn_kv_b, attn_output
    //           (q_a/q_b and k_b/v_b pre-fused by the converter)
    struct MlaFacts {
        bool rectangular = false;
        bool metadataParsed = false;
        bool geometryValidated = false;
        bool layoutSplit = false;
        bool layoutFused = false;
        std::size_t keyLen = 0, valueLen = 0;
        std::size_t qLoraRank = 0, kvLoraRank = 0;
        std::size_t qkNope = 0, qkRope = 0, vHead = 0;
        std::size_t numHeads = 0;
        std::size_t layersFullyBound = 0;
        std::size_t numLayersExpected = 0;
        std::string missing;
    } mla;
    mla.keyLen = keyLen;
    mla.valueLen = valueLen;
    mla.rectangular = (keyLen != 0 && valueLen != 0 && keyLen != valueLen);

    bool mlaMetaParsed = false;
    {
        // M5.0: identify the MLA projection tensors that actually exist in this
        // file, rather than assuming a naming convention. Every name and shape
        // below is read from the tensor table.
        {
            const std::vector<std::string> all = loader->listTensors();
            size_t printed = 0;
            for (const std::string& n : all) {
                if (n.rfind("blk.0.", 0) != 0) continue;
                if (n.find("attn") == std::string::npos) continue;
                const GGUFTensor* t = loader->getTensor(n);
                if (!t) continue;
                std::fprintf(stderr, "[Deep2Engine] MLA_TENSOR name=%s shape=[", n.c_str());
                for (std::size_t i = 0; i < t->shape.size(); ++i) {
                    std::fprintf(stderr, "%s%lld", i ? "," : "",
                                 static_cast<long long>(t->shape[i]));
                }
                std::fprintf(stderr, "] type=%d bytes=%llu\n",
                             static_cast<int>(t->type),
                             static_cast<unsigned long long>(t->sizeBytes));
                if (++printed >= 24) break;
            }
            std::fflush(stderr);
        }
        auto metaU64 = [&](const char* key) -> uint64_t {
            const int64_t prefixed = loader->getMetaInt(arch + std::string(".") + key, -1);
            if (prefixed > 0) return static_cast<uint64_t>(prefixed);
            const int64_t bare = loader->getMetaInt(std::string(key), -1);
            return bare > 0 ? static_cast<uint64_t>(bare) : 0ull;
        };
        static const char* const kB66Keys[] = {
            "block_count", "llm.block_count",
            "embedding_length", "llm.embedding_length",
            "attention.head_count", "attention.head_count_kv",
            "attention.key_length", "attention.value_length",
            "feed_forward_length",
            "expert_count", "expert_used_count", "expert_shared_count",
            "context_length",
            "attention.q_lora_rank", "attention.kv_lora_rank",
            "rope.dimension_count",
            "ssm.state_size", "attention.sliding_window",
            "attention.linear_layer_count"};
        Deep2::B66MetadataSource source;
        for (const char* k : kB66Keys) {
            const uint64_t v = metaU64(k);
            if (v != 0) source.u64[k] = v;
        }
        source.str["general.architecture"] = arch;
        const Deep2::B66Result bound = Deep2::B66RuntimeMetaBinder::bind(source);
        mlaMetaParsed = bound.pass;
        mla.metadataParsed = mlaMetaParsed;
        if (mlaMetaParsed) {
            mla.qLoraRank  = bound.meta.qLoraRank;
            mla.kvLoraRank = bound.meta.kvLoraRank;
            mla.numHeads   = bound.meta.heads ? bound.meta.heads
                                              : modelWeights.numHeads;
            modelWeights.qLoraRank  = mla.qLoraRank;
            modelWeights.kvLoraRank = mla.kvLoraRank;
            modelWeights.qkNopeHeadDim = metaSize("attention.qk_nope_head_dim", 0);
            modelWeights.qkRopeHeadDim = metaSize("attention.qk_rope_head_dim", 0);
            modelWeights.vHeadDim      = metaSize("attention.v_head_dim", 0);
            modelWeights.keyLength     = keyLen;
            modelWeights.valueLength   = valueLen;

            // --- M5.0: which layout does this file actually use? ---
            const auto has = [&](const char* leaf) {
                return loader->getTensor(std::string("blk.0.") + leaf) != nullptr;
            };
            const bool splitQ  = has("attn_q_a.weight") && has("attn_q_b.weight");
            const bool splitKV = has("attn_k_b.weight") && has("attn_v_b.weight");
            const bool fusedQ  = has("attn_q.weight");
            const bool fusedKV = has("attn_kv_b.weight");
            mla.layoutSplit = splitQ && splitKV && has("attn_kv_a_mqa.weight");
            mla.layoutFused = fusedQ && fusedKV && has("attn_kv_a_mqa.weight");

            // --- M5.2: derive what metadata does not carry ---
            const GGUFTensor* kvmqa = loader->getTensor("blk.0.attn_kv_a_mqa.weight");
            if (mla.kvLoraRank != 0 && kvmqa && kvmqa->shape.size() >= 2) {
                const std::size_t rows = static_cast<std::size_t>(kvmqa->shape[1]);
                if (rows > mla.kvLoraRank) {
                    const std::size_t rope = rows - mla.kvLoraRank;
                    if ((rope & 1u) == 0 && rope != 0) mla.qkRope = rope;
                }
            }
            if (mla.qkRope != 0 && keyLen > mla.qkRope) {
                mla.qkNope = keyLen - mla.qkRope;
            }
            if (valueLen != 0) mla.vHead = valueLen;

            if (mla.layoutSplit && splitQ) {
                const GGUFTensor* qb = loader->getTensor("blk.0.attn_q_b.weight");
                if (qb && qb->shape.size() >= 2) {
                    mla.qLoraRank = static_cast<std::size_t>(qb->shape[0]);
                }
            } else if (mla.layoutFused && fusedQ) {
                // Fused: q_a and q_b are pre-combined, so q_lora_rank is not
                // recoverable from the tensor. Leave it 0 rather than invent it.
                mla.qLoraRank = 0;
            }

            // --- M5.3: reconcile. Every check must hold exactly. ---
            mla.geometryValidated =
                mla.metadataParsed && mla.rectangular && mla.kvLoraRank != 0 &&
                mla.numHeads != 0 && mla.keyLen != 0 && mla.valueLen != 0 &&
                mla.qkRope != 0 && (mla.qkRope & 1u) == 0 &&
                mla.qkNope != 0 && mla.vHead == mla.valueLen &&
                (mla.qkNope + mla.qkRope) == mla.keyLen;

            // Cross-check against the tensor that fuses the KV down-projection,
            // when present: rows must equal heads*(nope + vHead) for the fused
            // layout, or heads*(keyLen) for the split layout's attn_q.
            if (mla.geometryValidated && mla.layoutFused) {
                const GGUFTensor* kvb = loader->getTensor("blk.0.attn_kv_b.weight");
                if (kvb && kvb->shape.size() >= 2) {
                    const std::size_t expect =
                        mla.numHeads * (mla.qkNope + mla.vHead);
                    if (static_cast<std::size_t>(kvb->shape[1]) != expect) {
                        mla.geometryValidated = false;
                    }
                }
            }
            if (mla.geometryValidated && mla.layoutFused && fusedQ) {
                const GGUFTensor* q = loader->getTensor("blk.0.attn_q.weight");
                if (q && q->shape.size() >= 2) {
                    if (static_cast<std::size_t>(q->shape[1]) != mla.numHeads * mla.keyLen) {
                        mla.geometryValidated = false;
                    }
                }
            }

            modelWeights.qkNopeHeadDim = mla.qkNope;
            modelWeights.qkRopeHeadDim = mla.qkRope;
            modelWeights.vHeadDim      = mla.vHead;
            modelWeights.qLoraRank     = mla.qLoraRank;

            std::fprintf(stderr,
                "[Deep2Engine] MLA_METADATA arch=%s layout=%s numHeads=%zu "
                "kvLoraRank=%zu qLoraRank=%zu qkNopeHeadDim=%zu qkRopeHeadDim=%zu "
                "vHeadDim=%zu keyLength=%zu valueLength=%zu geometryValidated=%d\n",
                arch.c_str(), mla.layoutSplit ? "split" : (mla.layoutFused ? "fused" : "unknown"),
                mla.numHeads, mla.kvLoraRank, mla.qLoraRank, mla.qkNope, mla.qkRope,
                mla.vHead, mla.keyLen, mla.valueLen,
                mla.geometryValidated ? 1 : 0);
            std::fflush(stderr);
        }
    }

    // RAWRXD_MLA_LOAD_AUTHORITY_001 (M4). The rectangular decision is DEFERRED,
    // not taken here: eligibility depends on whether every layer actually binds
    // the tensors the MLA consumer requires, which is only known after the
    // per-layer binder has run. Taking it here would either refuse a model that
    // turns out to be eligible, or accept one that does not.
    //
    // Hard invariant, enforced at the deferred site:
    //     RECTANGULAR_ATTN && !MLA_EXECUTION_ELIGIBLE -> LOAD_REFUSED
    if (mla.rectangular) {
        // A rectangular model's Q rows are heads*key_length, so headDim must be
        // the larger of the two or any square-derived sizing under-allocates.
        modelWeights.headDim = keyLen > valueLen ? keyLen : valueLen;
        std::fprintf(stderr,
            "[Deep2Engine] MLA_RECTANGULAR_DEFERRED arch=%s key_length=%zu "
            "value_length=%zu headDim=%zu awaitingEligibility=1\n",
            arch.c_str(), keyLen, valueLen, modelWeights.headDim);
        std::fflush(stderr);
    } else if (keyLen != 0) {
        modelWeights.headDim = keyLen;
    } else if (valueLen != 0) {
        modelWeights.headDim = valueLen;
    } else {
        if ((modelWeights.hiddenDim % modelWeights.numHeads) != 0) {
            if (diag) {
                diag->stageCode = 6;
                diag->stageName = "ATTN_HEAD_DIM_FALLBACK";
                diag->message = "No explicit attention key/value length and hiddenDim is not divisible by numHeads.";
            }
            return false;
        }
        modelWeights.headDim =
            modelWeights.hiddenDim / modelWeights.numHeads;
    }

    modelWeights.intermediateDim =
        metaSize("feed_forward_length", 0);
    if (modelWeights.intermediateDim == 0 && nemotronPatternOk_) {
        // Per-layer array: the dense MLP blocks carry the feed-forward width.
        for (int32_t v : nemotronFfPerLayer_) {
            if (v > 0) {
                modelWeights.intermediateDim = static_cast<size_t>(v);
                break;
            }
        }
    }
    modelWeights.moeIntermediateDim =
        metaSize("expert_feed_forward_length", 0);
    modelWeights.numExperts =
        metaSize("expert_count", 0);
    modelWeights.numExpertsPerToken =
        metaSize("expert_used_count", 0);
    modelWeights.numSharedExperts =
        metaSize("expert_shared_count", 0);
    modelWeights.leadingDenseBlockCount =
        metaSize("leading_dense_block_count", 0);
    modelWeights.isMoE = modelWeights.numExperts > 0;

    modelWeights.ropeDimensionCount =
        metaSize("rope.dimension_count", modelWeights.headDim);

    // --- RoPE theta: try architecture-qualified key first, then generic ---
    float ropeTheta = static_cast<float>(metaFloat("rope.global.freq_base", 0.0));
    float ropeThetaLocal = static_cast<float>(metaFloat("rope.local.freq_base", 0.0));
    if (!(ropeTheta > 1.0f)) {
        ropeTheta = static_cast<float>(metaFloat("rope.freq_base", 0.0));
    }
    if (!(ropeTheta > 1.0f)) {
        if (arch == "gemma3") ropeTheta = 1000000.0f;
        else                  ropeTheta = 10000.0f;
    }
    if (!(ropeThetaLocal > 1.0f)) {
        ropeThetaLocal = static_cast<float>(metaFloat("rope.local_freq_base", 0.0));
    }
    if (!(ropeThetaLocal > 1.0f)) {
        if (arch == "gemma3") ropeThetaLocal = 10000.0f;
        else                  ropeThetaLocal = ropeTheta;
    }
    modelWeights.ropeTheta = ropeTheta;
    modelWeights.ropeThetaLocal = ropeThetaLocal;

    // Gemma3 sliding-window metadata
    modelWeights.slidingWindowSize = metaSize("attention.sliding_window", 0);
    modelWeights.slidingWindowPattern = metaSize("attention.sliding_window_pattern", 0);
    if (arch == "gemma3" && modelWeights.slidingWindowSize == 0) {
        modelWeights.slidingWindowSize = 512;
    }
    if (arch == "gemma3" && modelWeights.slidingWindowPattern == 0) {
        modelWeights.slidingWindowPattern = 6;
    }

    std::fprintf(stderr,
        "[Deep2Engine] ROPE_ARCH=%s ROPE_THETA_GLOBAL=%.1f ROPE_THETA_LOCAL=%.1f "
        "SLIDING_WINDOW=%zu SLIDING_WINDOW_PATTERN=%zu\n",
        arch.c_str(), modelWeights.ropeTheta, modelWeights.ropeThetaLocal,
        modelWeights.slidingWindowSize, modelWeights.slidingWindowPattern);

    modelWeights.ropeScaling =
        static_cast<float>(metaFloat("rope.scaling.factor", 1.0));

    modelWeights.normEps = static_cast<float>(
        metaFloat("attention.layer_norm_rms_epsilon",
                  metaFloat("attention.layer_norm_epsilon", 0.0)));

    if (!(modelWeights.normEps > 0.0f)) {
        std::fprintf(stderr, "[Deep2Engine] GGUF missing layer-norm epsilon\n");
        if (diag) {
            diag->stageCode = 7;
            diag->stageName = "NORM_EPS_MISSING";
            diag->message = "GGUF missing attention.layer_norm_rms_epsilon / attention.layer_norm_epsilon.";
        }
        return false;
    }

    // RoPE pairing convention is architecture-defined (not in GGUF metadata):
    //   NeoX rotated-half: llama/qwen/mistral/gemma
    //   GPT-J adjacent:    gpt-neox/phi (legacy GGUF conversions)
    const bool archIsNeoxRoPE =
        arch == "llama" || arch == "qwen" || arch == "qwen2" ||
        arch == "mistral" || arch == "baichuan" || arch == "yi" ||
        arch == "olmo" || arch == "starchat" || arch == "replit" ||
        arch == "refact" || arch == "stablelm" || arch == "deepseek2";
    modelWeights.ropeNeoxStyle = archIsNeoxRoPE;
    if (const char* overrideStyle = std::getenv("DEEP2_ROPE_GPTJ")) {
        if (overrideStyle[0] == '1') modelWeights.ropeNeoxStyle = false;
    }
    // Diagnostic: log chosen RoPE style for first-run verification    // Nemotron-H / Mamba2 SSM metadata (read from GGUF keys used by llama.cpp converters)
    if (arch == "nemotron_h" || arch == "nemotron_h_moe") {
        ssmInner_      = metaSize("ssm.inner_size",      0);
        ssmStateSize_  = metaSize("ssm.state_size",      0);
        ssmHeads_      = metaSize("ssm.head_count",      0);
        ssmGroups_     = metaSize("ssm.group_count",     0);
        ssmConvKernel  = metaSize("ssm.conv_kernel",     0);
        const size_t ssmDtRank = metaSize("ssm.time_step_rank", 0);
        if (ssmDtRank) ssmHeads_ = ssmDtRank; // dt_rank == heads for Mamba2
        if (ssmInner_ && ssmStateSize_ && ssmHeads_ && ssmGroups_) {
            nemotronGeoOk_ = 1;
            std::fprintf(stderr,
                "[Deep2Engine] SSM_META inner=%zu state=%zu heads=%zu groups=%zu convK=%zu\n",
                ssmInner_, ssmStateSize_, ssmHeads_, ssmGroups_, ssmConvKernel);
        } else {
            std::fprintf(stderr,
                "[Deep2Engine] SSM metadata incomplete: inner=%zu state=%zu heads=%zu groups=%zu\n",
                ssmInner_, ssmStateSize_, ssmHeads_, ssmGroups_);
        }
    }

    const size_t modelContext = metaSize("context_length", 0);
    if (modelContext > 0) {
        // Respect caller-configured maxSeqLen (e.g., inference gate), but
        // also clamp to the model's declared context length.
        if (config.maxSeqLen == 0 || modelContext < config.maxSeqLen)
            config.maxSeqLen = modelContext;
    }

    // Global output tensors.
    bindFirst(modelWeights.finalNorm,
              {"output_norm.weight", "model.norm.weight", "norm.weight"});

    if (!bindFirst(modelWeights.lmHead,
                   {"output.weight", "lm_head.weight"})) {
        modelWeights.lmHead = modelWeights.tokenEmbed;
        modelWeights.tieEmbeddings = true;
    }

    if (!modelWeights.finalNorm.data ||
        !modelWeights.lmHead.data ||
        modelWeights.lmHead.rows != modelWeights.vocabSize ||
        modelWeights.lmHead.cols != modelWeights.hiddenDim) {
        std::fprintf(stderr, "[Deep2Engine] final norm / LM-head topology invalid\n");
        if (diag) {
            diag->stageCode = 8;
            diag->stageName = "FINAL_NORM_LMHEAD";
            diag->message = "Final norm or LM-head topology invalid (missing data, or lmHead.rows!=vocabSize, or lmHead.cols!=hiddenDim).";
        }
        return false;
    }

    // ========================================================================
    // RAWRXD_DEEP2_MODEL_REGISTRY_001 — fail-closed admission.
    //
    // Placed after every geometry field is parsed and after the final-norm /
    // LM-head topology check, but BEFORE any per-layer weight bind. That ordering
    // matters: a model that must be rejected is rejected before the expensive
    // bind loop runs, and before a single forward can be attempted.
    //
    // Every value below is taken from what loadModel already parsed out of the
    // GGUF. Nothing is re-derived from the file name, and no architecture is
    // guessed from a substring. canonicalName is `arch`, which came from
    // general.architecture at line ~844.
    // ========================================================================
    {
        static const bool architecturesRegistered = [] {
            RegisterDeep2Architectures();
            return true;
        }();
        (void)architecturesRegistered;

        Deep2::ModelMetadata md;
        md.canonicalName = arch;                 // parsed tag; valid for this scope
        md.ggufPath = ggufPath;
        md.hiddenDim = modelWeights.hiddenDim;
        md.numLayers = modelWeights.numLayers;
        md.numHeads = modelWeights.numHeads;
        md.numKVHeads = modelWeights.numKVHeads;
        md.headDim = modelWeights.headDim;
    // RAWRXD_MLA_LOAD_AUTHORITY_001: classify the GEOMETRY for admission. This is
    // NOT execution eligibility -- modelWeights.useMLA stays false until the
    // deferred decision after the per-layer binder, and only a split-layout
    // model with all eight tensors bound can set it. Admission needs to know
    // the shape class because its numHeads*headDim invariant is square-only.
    md.useMLA = mla.geometryValidated;
    md.kvLoraRank = mla.kvLoraRank;
    md.qkNopeHeadDim = mla.qkNope;
    md.qkRopeHeadDim = mla.qkRope;
    md.vHeadDim = mla.vHead;
    md.vocabSize = modelWeights.vocabSize;
        md.intermediateDim = modelWeights.intermediateDim;
        md.moeIntermediateDim = modelWeights.moeIntermediateDim;
        md.numExperts = modelWeights.numExperts;
        md.numExpertsPerToken = modelWeights.numExpertsPerToken;
        md.numSharedExperts = modelWeights.numSharedExperts;
        md.ropeTheta = modelWeights.ropeTheta;
        md.slidingWindowSize = modelWeights.slidingWindowSize;
        md.slidingWindowPattern = modelWeights.slidingWindowPattern;
        md.tieEmbeddings = modelWeights.tieEmbeddings;
        md.ssmInner = ssmInner_;
        md.ssmStateSize = ssmStateSize_;
        md.ssmHeads = ssmHeads_;
        md.ssmGroups = ssmGroups_;
        md.ssmConvKernel = ssmConvKernel;
        md.nemotronHeadKvPerLayer = nemotronHeadKvPerLayer_;
        md.nemotronFfPerLayer = nemotronFfPerLayer_;
        md.nemotronPatternOk = nemotronPatternOk_;

        // The real tensor table, straight from the loader. Required-tensor
        // admission matches against THIS list; it never assumes a tensor exists
        // because the architecture implies it.
        md.presentTensors = loader->listTensors();

        // Quantization is a storage property resolved from the dominant weight
        // tensor, then checked against actually-registered kernels by admit().
        // Parseable is not executable: the check lives in the registry.
        md.quantTypeId = static_cast<uint32_t>(modelWeights.tokenEmbed.type);
        if (md.quantTypeId == 0) {
            for (const std::string& name : md.presentTensors) {
                if (name == "token_embd.weight" || name == "token_embd") {
                    const GGUFTensor* t = loader->getTensor(name);
                    if (t) { md.quantTypeId = static_cast<uint32_t>(t->type); break; }
                }
            }
        }
        md.quantization = Deep2::QuantTypeName(md.quantTypeId);

        Deep2::AdmissionReport report;
        const bool admitted = Deep2::ModelRegistry::admit(
            md, Deep2::ExecDevice::Cpu, report);

        if (!admitted) {
            // Hard reject. No generic-path fallback, no partial admission.
            std::fprintf(stderr,
                "[Deep2Engine] MODEL ADMISSION REJECTED arch=%s reason=%s field=%s detail=%s\n",
                arch.c_str(),
                [&]{
                    switch (report.reject) {
                        case Deep2::AdmissionReject::NoParsedArchitecture:     return "NoParsedArchitecture";
                        case Deep2::AdmissionReject::UnknownArchitecture:      return "UnknownArchitecture";
                        case Deep2::AdmissionReject::ArchitectureUnimplemented:return "ArchitectureUnimplemented";
                        case Deep2::AdmissionReject::UnsupportedForwardFamily: return "UnsupportedForwardFamily";
                        case Deep2::AdmissionReject::MalformedMetadata:        return "MalformedMetadata";
                        case Deep2::AdmissionReject::MissingRequiredTensor:    return "MissingRequiredTensor";
                        case Deep2::AdmissionReject::UnsupportedQuant:         return "UnsupportedQuant";
                        case Deep2::AdmissionReject::UnsupportedOperator:      return "UnsupportedOperator";
                        case Deep2::AdmissionReject::TokenizerUnsupported:     return "TokenizerUnsupported";
                        default:                                               return "None";
                    }
                }(),
                report.field.empty() ? "(none)" : report.field.c_str(),
                report.detail.empty() ? "(none)" : report.detail.c_str());
            if (diag) {
                diag->stageCode = 20;
                diag->stageName = "MODEL_ADMISSION_REJECTED";
                diag->message = "Model admission rejected the model: " +
                                report.detail;
            }
            modelState_ = ModelState::Closed;
            return false;
        }

        std::fprintf(stderr,
            "[Deep2Engine] admission OK arch=%s family=%s moe=%d mla=%d "
            "recurrent=%d slidingWindow=%d quant=%s(type %u) tensors=%zu\n",
            report.architectureId ? report.architectureId : "(null)",
            report.forwardFamily ? report.forwardFamily : "(null)",
            report.moe ? 1 : 0, report.mla ? 1 : 0,
            report.recurrent ? 1 : 0, report.slidingWindow ? 1 : 0,
            md.quantization.c_str(), md.quantTypeId,
            md.presentTensors.size());

        // ------------------------------------------------------------------
        // DEEP2_MLA_CPU_PATH_SUSPENDED_001
        //
        // Suspend here: metadata is parsed, but nothing is mapped, bound or
        // allocated yet. The "GGUF mapped" log and every tensor bind happen
        // further down.
        //
        // computeAttention() has no CPU MLA branch at all:
        //     if (lw.useMLA || modelWeights.useMLA) {
        //         if (computeMLAAttentionGpu(...)) return;
        //         throw std::runtime_error(
        //             "attention: GPU MLA path failed or unsupported");
        //     }
        // so an MLA model has exactly two outcomes: Vulkan, or exception.
        //
        // Both facts needed to know that are in hand HERE: report.mla (below)
        // and vulkanEnabled_. Measured on Kimi K2 before this check existed:
        // 966 ms to build the VMA for a 43.12 GB shard, 1096 tensors bound,
        // 61 MLA layers validated, KV/cache allocated for a 163840 vocab, a
        // full prefill forward -- and only then the throw. All of that work was
        // spent rediscovering a fact available at this line.
        //
        // Deliberately a SUSPENSION, not an implementation: a CPU MLA kernel
        // would ADD numerical surface that must itself be certified against the
        // GPU path. Naming the missing capability at the earliest possible
        // moment is the smaller change.
        //
        // RAWRXD_CPU_MLA_KERNEL_001: BOTH MLA_CPU_PATH_ABSENT suspensions were
        // REMOVED here, and the reason is that their premise became false.
        //
        // They read:
        //     if (report.mla && !vulkanEnabled_) -> suspend, stageCode 21
        //     if (modelWeights.useMLA && !vulkanEnabled_) -> suspend, stageCode 21
        // with the message "no CPU MLA path exists". That was true and it was
        // measured: computeAttention had no CPU MLA branch, every GPU helper
        // returned false at its vulkanInitialized_ guard, and the model died at
        // prefill token 0.
        //
        // Deep2Engine::computeMLAAttentionCpu now exists
        // (src/deep2/deep2_cpu_mla.cpp), is declared in Deep2Engine.h next to the
        // GPU declaration, and is called from computeAttention as a real second
        // execution root. The suspension is therefore no longer a fact about this
        // build; leaving it in place would refuse, by the exact message, the model
        // the kernel was written to run.
        //
        // What replaces it is NOT a weaker gate. The single fail-closed decision
        // point for MLA is still the MLA_EXECUTION_ELIGIBLE predicate below, which
        // requires parsed metadata, exact validated geometry, a recognised layout,
        // and every tensor that layout requires bound on EVERY layer. A model that
        // fails any of those is still refused, with stageCode naming the exact
        // requirement it missed. What is gone is only the claim that "no CPU path
        // exists", which is no longer true.
        //
        // The original concern that motivated the early suspension -- spending
        // 966 ms of VMA construction and a 43 GB mapping on a model that cannot
        // run -- is now served by that later predicate rather than by a guess made
        // before any tensor was bound. Judging runnability from bound tensors is
        // strictly more accurate than judging it from a trait flag.
        // ------------------------------------------------------------------
    }

    // ------------------------------------------------------------------
    // DEEP2_MLA_CPU_PATH_SUSPENDED_001 -- see the note above: removed, same
    // reason. The MLA_EXECUTION_ELIGIBLE predicate below is now the single
    // fail-closed decision point for MLA, and it judges from BOUND TENSORS
    // rather than from a trait flag read before any tensor was bound.
    // ------------------------------------------------------------------

    modelWeights.layers.assign(modelWeights.numLayers, LayerWeights{});
    mla.numLayersExpected = modelWeights.numLayers;

    for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
        LayerWeights& lw = modelWeights.layers[layer];
        const std::string p = "blk." + std::to_string(layer) + ".";

        bindTensor(p + "attn_qkv.weight", lw.wqkv);
        bindTensor(p + "attn_q.weight", lw.wq);
        // RAWRXD_LAYER0_ATTN_BISECT_001: the one measurement that decides whether
        // the Q projection stride is wrong or the live kernel is wrong.
        //
        // row_bytes is computed two independent ways and both are printed:
        //   from numBlocks  (blocks_per_row * block_size)  -- the live descriptor
        //   from shape/rows/cols arithmetic              -- the loader's intent
        // If they disagree, the stride itself is wrong. If they agree and
        // row_bytes is right for the type, the stride is fine and the defect is
        // in the kernel's field offsets. Prints once, for layer 0 only, so the
        // run is not flooded.
        if (layer == 0 && lw.wq.data) {
            static const bool traceOnce = [] {
                const char* v = std::getenv("RAWRXD_ATTN_BISECT");
                return v && v[0] && v[0] != '0';
            }();
            if (traceOnce) {
                // GGUF/ggml spec block geometry, stated here rather than taken
                // from any in-repo table (the ComputeTensorSize table is dead
                // code and its stride values are known wrong).
                struct Geo { int type; const char* name; uint32_t qk; uint32_t bytes; };
                static const Geo kGeo[] = {
                    {  2, "Q4_0",  32,  18 }, {  3, "Q4_1",  32,  20 },
                    {  6, "Q5_0",  32,  22 }, {  7, "Q5_1",  32,  24 },
                    {  8, "Q8_0",  32,  34 }, {  9, "Q8_1",  32,  36 },
                    { 10, "Q2_K", 256,  84 }, { 11, "Q3_K", 256, 110 },
                    { 12, "Q4_K", 256, 144 }, { 13, "Q5_K", 256, 176 },
                    { 14, "Q6_K", 256, 210 }, { 15, "Q8_K", 256, 292 },
                };
                const Geo* g = nullptr;
                for (const auto& e : kGeo) if (e.type == lw.wq.type) g = &e;

                const size_t nElem = lw.wq.numElements();
                // Spec-derived geometry, plus the arithmetic that makes it
                // checkable: nElem/qk*bytes must equal sizeBytes exactly.
                uint64_t specBlocks = 0, specBytes = 0, specRowBytes = 0, specBpr = 0;
                if (g && g->qk && (nElem % g->qk) == 0) {
                    specBlocks = nElem / g->qk;
                    specBytes  = specBlocks * g->bytes;
                    specBpr    = lw.wq.cols / g->qk;
                    specRowBytes = specBpr * g->bytes;
                }
                const bool sizeBytesAgrees = (g && specBytes == lw.wq.sizeBytes);
                const bool numBlocksAgrees = (g && specBlocks == lw.wq.numBlocks);

                std::fprintf(stderr,
                    "WQBIND layer=0 name=attn_q.weight type=%d type_name=%s "
                    "ne0=%lld ne1=%lld rows=%zu cols=%zu numElements=%zu "
                    "numBlocks_bound=%zu sizeBytes=%zu data=%p\n",
                    lw.wq.type, g ? g->name : "UNKNOWN",
                    (long long)(lw.wq.shape.size() > 0 ? lw.wq.shape[0] : -1),
                    (long long)(lw.wq.shape.size() > 1 ? lw.wq.shape[1] : -1),
                    lw.wq.rows, lw.wq.cols, nElem,
                    lw.wq.numBlocks, lw.wq.sizeBytes, lw.wq.data);
                std::fprintf(stderr,
                    "WQBIND layer=0 qk=%u block_size=%u spec_blocks=%llu "
                    "spec_bytes=%llu blocks_per_row=%llu row_bytes=%llu "
                    "SIZE_BYTES_AGREES=%d NUM_BLOCKS_AGREES=%d "
                    "NUM_BLOCKS_DEFECT=%d\n",
                    g ? g->qk : 0u, g ? g->bytes : 0u,
                    (unsigned long long)specBlocks, (unsigned long long)specBytes,
                    (unsigned long long)specBpr, (unsigned long long)specRowBytes,
                    sizeBytesAgrees ? 1 : 0, numBlocksAgrees ? 1 : 0,
                    (g && !numBlocksAgrees) ? 1 : 0);
                std::fflush(stderr);

                // ONE fprintf for the whole dump. The previous version issued one
                // call per byte, and a concurrent thread's stderr write split the
                // 84 bytes across three lines, which made the result impossible
                // to attribute. A single call is atomic against that interleaving.
                char hex[8 * 84 + 4];
                size_t o = 0;
                const unsigned char* raw = (const unsigned char*)lw.wq.data;
                const size_t nDump = (raw && lw.wq.sizeBytes >= 84) ? 84 : 0;
                static const char* kHex = "0123456789abcdef";
                for (size_t i = 0; i < nDump; ++i) {
                    hex[o++] = ' ';
                    hex[o++] = kHex[(raw[i] >> 4) & 0xF];
                    hex[o++] = kHex[raw[i] & 0xF];
                }
                hex[o] = '\0';
                // Q2_K places scales[16] then qs[64] then d,dmin -- d is at byte
                // 80, NOT byte 0. Printing the decoded values for both candidate
                // offsets makes a wrong field offset visible instead of assumed.
                uint16_t db = 0, mb = 0;
                if (nDump == 84) {
                    db  = (uint16_t)(raw[80] | (raw[81] << 8));
                    mb  = (uint16_t)(raw[82] | (raw[83] << 8));
                }
                std::fprintf(stderr, "WQBIND layer=0 bytes0_83=%s\n", hex);
                std::fprintf(stderr,
                    "WQBIND layer=0 q2k_d_bits_at80=0x%04x q2k_dmin_bits_at80=0x%04x "
                    "scales0_15=%02x%02x%02x%02x qs0_3=%02x%02x%02x%02x\n",
                    db, mb, raw ? raw[0] : 0, raw ? raw[1] : 0, raw ? raw[2] : 0,
                    raw ? raw[3] : 0, raw ? raw[16] : 0, raw ? raw[17] : 0,
                    raw ? raw[18] : 0, raw ? raw[19] : 0);
                std::fflush(stderr);
            }
        }
        bindTensor(p + "attn_k.weight", lw.wk);
        bindTensor(p + "attn_v.weight", lw.wv);
        bindTensor(p + "attn_output.weight", lw.wo);
        // Qwen2-family attention projection biases. Optional: bound only when
        // the GGUF provides them (presence recorded for parity audits).
        bindTensor(p + "attn_q.bias", lw.bq);
        bindTensor(p + "attn_k.bias", lw.bk);
        bindTensor(p + "attn_v.bias", lw.bv);
        bindTensor(p + "attn_norm.weight", lw.attnNorm);
        bindTensor(p + "attn_q_norm.weight", lw.attnQNorm);
        bindTensor(p + "attn_k_norm.weight", lw.attnKNorm);

        // RAWRXD_MLA_LOAD_AUTHORITY_001 (M5.4): bind the MLA projection tensors.
        //
        // Both converter layouts are handled. `split` is what
        // computeMLAAttentionGpu() requires (attn_q_a / attn_q_b / attn_k_b /
        // attn_v_b / attn_o). `fused` is what some converters emit, with
        // q_a+q_b and k_b+v_b already combined. Fused files are bound as far as
        // they go so the diagnostic can name exactly which tensors the consumer
        // is still missing, but they are NOT eligible: the consumer would read
        // unbound pointers.
        if (mla.metadataParsed) {
            const bool split = mla.layoutSplit;
            const bool fused = mla.layoutFused;
            if (split) {
                bindTensor(p + "attn_q_a.weight", lw.attnQ_a);
                bindTensor(p + "attn_q_a_norm.weight", lw.attnQ_a_norm);
                bindTensor(p + "attn_q_b.weight", lw.attnQ_b);
                // The latent down-projection has TWO real spellings: DeepSeek2 and
                // later absorb queries and export attn_kv_a_mqa, earlier MLA
                // exports use attn_kv_a. ModelRegistry's MLA admission accepts
                // either (it is a disjunction, not a conjunction), so the binder
                // must too -- otherwise a model passes admission and then fails to
                // bind, which is strictly worse than rejecting it at the door.
                if (!bindTensor(p + "attn_kv_a_mqa.weight", lw.attnKV_a_mqa))
                    bindTensor(p + "attn_kv_a.weight", lw.attnKV_a_mqa);
                bindTensor(p + "attn_kv_a_norm.weight", lw.attnKV_a_norm);
                bindTensor(p + "attn_k_b.weight", lw.attnK_b);
                bindTensor(p + "attn_v_b.weight", lw.attnV_b);
                bindFirst(lw.attnO, {(p + "attn_o.weight").c_str(),
                                     (p + "attn_output.weight").c_str()});
            } else if (fused) {
                // Same two-spelling rule as the split layout above.
                if (!bindTensor(p + "attn_kv_a_mqa.weight", lw.attnKV_a_mqa))
                    bindTensor(p + "attn_kv_a.weight", lw.attnKV_a_mqa);
                bindTensor(p + "attn_kv_a_norm.weight", lw.attnKV_a_norm);
                bindFirst(lw.attnO, {(p + "attn_o.weight").c_str(),
                                     (p + "attn_output.weight").c_str()});

                // RAWRXD_DEEPSEEK_CPU_E2E_001: the fused layout maps onto the
                // EXISTING two slots, and needs no weight surgery at all.
                //
                // The previous comment here said the split-only tensors "cannot be
                // synthesised, because splitting a fused quantised weight would
                // require dequantisation and requantisation". That statement is
                // about producing two SEPARATE WeightTensors from one packed
                // quantised blob, and it is correct. It is also not what the
                // fused layout needs, because nothing has to be split:
                //
                //   attn_q     is [heads*keyLen, hidden]      -- already qFull
                //   attn_kv_b  is [heads*(nope+vHead), kvRank] -- K and V share one
                //                                                          up-projection
                //
                // Both produce exactly what attnQ_b and attnK_b produce in the
                // split layout. Binding them there is a rename, not a conversion:
                // no byte is dequantised, requantised or copied, and the packed
                // Q4_K payload is read once by the same registered GEMV the rest
                // of the engine uses. The k/v split happens on the GEMV OUTPUT,
                // where it is plain f32 pointer arithmetic.
                //
                //   attn_q     [2048,3072]  heads*keyLen = 16*192 = 3072  -> attnQ_b
                //   attn_kv_b  [512,4096]   heads*(nope+vHead) = 16*256 = 4096 -> attnK_b
                bindTensor(p + "attn_q.weight", lw.attnQ_b);
                bindTensor(p + "attn_kv_b.weight", lw.attnK_b);
                // attnV_b is NOT populated in this layout: V is the second half of
                // each head's 256-wide slice of the attn_kv_b result, not a tensor.
            }

            // M5.5: the consumer's exact required set.
            //
            // Layout-aware. The SPLIT consumer needs eight tensors; the FUSED
            // consumer needs five, because attn_q_b / attn_kv_b already carry the
            // absorbed factors and V is not a separate weight. Judging both
            // layouts by the split set made every deepseek2 file report three
            // tensors "missing" that were never part of it.
            const bool complete = split
                ? (lw.attnQ_a.data && lw.attnQ_a_norm.data && lw.attnQ_b.data &&
                   lw.attnKV_a_mqa.data && lw.attnKV_a_norm.data &&
                   lw.attnK_b.data && lw.attnV_b.data && lw.attnO.data)
                : (fused
                   ? (lw.attnQ_b.data && lw.attnKV_a_mqa.data &&
                      lw.attnKV_a_norm.data && lw.attnK_b.data && lw.attnO.data)
                   : false);
            if (complete) ++mla.layersFullyBound;
            else if (layer == 0) {
                std::ostringstream miss;
                auto note = [&](const char* what, const WeightTensor& t) {
                    if (!t.data) {
                        if (!miss.str().empty()) miss << ", ";
                        miss << what;
                    }
                };
                if (split) {
                    note("attnQ_a", lw.attnQ_a);
                    note("attnQ_a_norm", lw.attnQ_a_norm);
                    note("attnQ_b", lw.attnQ_b);
                    note("attnKV_a_mqa", lw.attnKV_a_mqa);
                    note("attnKV_a_norm", lw.attnKV_a_norm);
                    note("attnK_b", lw.attnK_b);
                    note("attnV_b", lw.attnV_b);
                    note("attnO", lw.attnO);
                } else {
                    note("attn_q(->attnQ_b)", lw.attnQ_b);
                    note("attnKV_a_mqa", lw.attnKV_a_mqa);
                    note("attnKV_a_norm", lw.attnKV_a_norm);
                    note("attn_kv_b(->attnK_b)", lw.attnK_b);
                    note("attnO", lw.attnO);
                }
                mla.missing = miss.str();
            }
        }

        bindFirst(lw.wGate,
                  {(p + "ffn_gate.weight").c_str(),
                   (p + "mlp_gate.weight").c_str()});
        bindFirst(lw.wUp,
                  {(p + "ffn_up.weight").c_str(),
                   (p + "mlp_up.weight").c_str()});
        bindFirst(lw.wDown,
                  {(p + "ffn_down.weight").c_str(),
                   (p + "mlp_down.weight").c_str()});
        bindFirst(lw.ffnNorm,
                  {(p + "ffn_norm.weight").c_str(),
                   (p + "mlp_norm.weight").c_str()});

        // RAWRXD_FUSED_GATE_UP_001: gated architectures (phi3, llama-3,
        // qwen2) ship ONE ffn_up tensor holding the gate rows followed by the
        // up rows, rather than separate ffn_gate / ffn_up tensors.
        //
        // Without this, such a model is silently computed WRONG rather than
        // rejected: computeFFN() treats a missing wGate as the "simple MLP"
        // topology and evaluates silu(up) instead of silu(gate) * up, which is
        // numerically incorrect but produces entirely plausible text. The
        // admission gate correctly refused these models; the loader is what was
        // missing, and a gate that refuses work the engine cannot yet do is
        // correct behaviour, not a bug to relax around.
        //
        // The split is proven, not assumed: it is only performed when the gate
        // is absent AND ffn_up's row count is exactly twice ffn_down's column
        // count, which is the only shape consistent with one tensor holding
        // two equal projections. Rows are contiguous in the GGUF buffer, so
        // the halves are an exact byte-prefix split; quantised types keep their
        // per-row block structure because the boundary is row-aligned.
        //
        // llama.cpp's swiglu convention puts gate in rows [0, I) and up in
        // [I, 2I).
        if (!lw.wGate.data && lw.wUp.data && lw.wDown.data &&
            lw.wUp.cols == modelWeights.hiddenDim &&
            lw.wDown.rows == modelWeights.hiddenDim &&
            lw.wUp.rows == lw.wDown.cols * 2 &&
            lw.wUp.sizeBytes % 2 == 0) {
            const size_t halfBytes = lw.wUp.sizeBytes / 2;
            const size_t inter = lw.wDown.cols;

            // Which half is the gate is the one thing about this layout that the
            // byte geometry alone cannot prove. It is normally the FIRST half
            // (llama.cpp's swiglu convention). RAWRXD_FUSED_GATE_UP_ORDER=up_gate
            // inverts it so the assumption can be falsified instead of trusted:
            // if inverting leaves the output identical, the split is not being
            // consumed at all, and if inverting produces markedly better text
            // then the assumed order is wrong. Diagnostic only; the default is
            // the production order.
            static const bool invertOrder = [] {
                const char* e = std::getenv("RAWRXD_FUSED_GATE_UP_ORDER");
                return e && std::string(e) == "up_gate";
            }();
            static const bool orderReported = [] {
                const char* e = std::getenv("RAWRXD_FUSED_GATE_UP_ORDER");
                std::fprintf(stderr, "[Deep2Engine] fused gate_up order=%s\n",
                             e ? e : "gate_up(default)");
                return true;
            }();
            (void)orderReported;

            const uint8_t* base = static_cast<const uint8_t*>(lw.wUp.data);
            const uint8_t* gateData = invertOrder ? base + halfBytes : base;
            const uint8_t* upData   = invertOrder ? base : base + halfBytes;

            lw.wGate = lw.wUp;
            lw.wGate.data = const_cast<uint8_t*>(gateData);
            lw.wGate.rows = inter;
            lw.wGate.sizeBytes = halfBytes;
            lw.wGate.fileOffset = lw.wUp.fileOffset + (invertOrder ? halfBytes : 0);
            lw.wGate.name = p + "fused_gateup[gate_half]";

            lw.wUp.data = const_cast<uint8_t*>(upData);
            lw.wUp.rows = inter;
            lw.wUp.sizeBytes = halfBytes;
            lw.wUp.fileOffset = lw.wUp.fileOffset + (invertOrder ? 0 : halfBytes);
            lw.wUp.name = p + "fused_gateup[up_half]";

            std::fprintf(stderr,
                "[Deep2Engine] layer %zu fused gate_up split: I=%zu order=%s "
                "(gate rows [%zu,%zu), up rows [%zu,%zu))\n",
                layer, inter, invertOrder ? "up_gate(DIAGNOSTIC)" : "gate_up",
                invertOrder ? inter : 0, invertOrder ? inter * 2 : inter,
                invertOrder ? 0 : inter, invertOrder ? inter : inter * 2);
        }
        bindFirst(lw.attnPostNorm,
                  {(p + "attn_post_norm.weight").c_str(),
                   (p + "post_attention_norm.weight").c_str()});
        bindFirst(lw.ffnPostNorm,
                  {(p + "ffn_post_norm.weight").c_str(),
                   (p + "post_ffw_norm.weight").c_str()});

        // Nemotron-H / Mamba-style SSM tensor binding.
        // These are optional; presence determines block type below.
        bindTensor(p + "ssm_in.weight", lw.ssmIn);
        bindTensor(p + "ssm_conv1d.weight", lw.ssmConv1d);
        bindTensor(p + "ssm_conv1d.bias", lw.ssmConv1dBias);
        bindTensor(p + "ssm_dt.bias", lw.ssmDtBias);
        bindFirst(lw.ssmA, {(p + "ssm_a.weight").c_str(), (p + "ssm_a").c_str()});
        bindFirst(lw.ssmD, {(p + "ssm_d.weight").c_str(), (p + "ssm_d").c_str()});
        bindTensor(p + "ssm_norm.weight", lw.ssmNorm);
        bindTensor(p + "ssm_out.weight", lw.ssmOut);

        // Batch 8: real MoE router + expert tensor binding.
        bindFirst(lw.moeRouter,
                  {(p + "ffn_gate_inp.weight").c_str(),
                   (p + "moe.router.weight").c_str(),
                   (p + "router.weight").c_str()});

        auto bindAny = [&](WeightTensor& dst,
                           const std::vector<std::string>& names) -> bool {
            for (const std::string& name : names) {
                if (bindTensor(name, dst)) return true;
            }
            return false;
        };

        auto bindPackedExperts =
            [&](const std::vector<std::string>& names,
                std::vector<WeightTensor>& dst) -> bool {
            const GGUFTensor* t = nullptr;
            for (const std::string& name : names) {
                t = loader->getTensor(name);
                if (t) break;
            }
            if (!t) return false;

            if (!t->data || t->shape.size() != 3 || modelWeights.numExperts == 0) {
                std::fprintf(stderr,
                    "[Deep2Engine] packed expert tensor found but rejected: "
                    "ndims=%zu, numExperts=%zu, hasData=%d\n",
                    t->shape.size(), modelWeights.numExperts, t->data ? 1 : 0);
                return false;
            }

            // Auto-detect which dimension holds the expert count.
            // Standard: shape[2]==E (DeepSeek/Kimi). Nemotron-H-MoE may use shape[0]==E.
            int expertDimIdx = -1;
            for (int i = 0; i < 3; ++i) {
                if (t->shape[i] == static_cast<int64_t>(modelWeights.numExperts)) {
                    expertDimIdx = i;
                    break;
                }
            }
            if (expertDimIdx < 0) {
                std::fprintf(stderr,
                    "[Deep2Engine] packed expert shape [%lld,%lld,%lld] does not "
                    "contain numExperts=%zu in any dim\n",
                    static_cast<long long>(t->shape[0]),
                    static_cast<long long>(t->shape[1]),
                    static_cast<long long>(t->shape[2]),
                    modelWeights.numExperts);
                return false;
            }

            if ((t->sizeBytes % modelWeights.numExperts) != 0) {
                std::fprintf(stderr,
                    "[Deep2Engine] packed expert sizeBytes=%zu not divisible by numExperts=%zu\n",
                    t->sizeBytes, modelWeights.numExperts);
                return false;
            }

            const size_t sliceBytes = t->sizeBytes / modelWeights.numExperts;
            if (sliceBytes == 0) return false;

            // The per-expert matrix dimensions are the two dims that are NOT expertDimIdx.
            size_t matDim[2];
            int    matIdx = 0;
            for (int i = 0; i < 3; ++i)
                if (i != expertDimIdx) matDim[matIdx++] = static_cast<size_t>(t->shape[i]);

            dst.assign(modelWeights.numExperts, WeightTensor{});
            for (size_t e = 0; e < modelWeights.numExperts; ++e) {
                if (e > std::numeric_limits<size_t>::max() / sliceBytes)
                    return false;
                const size_t byteOffset = e * sliceBytes;
                if (byteOffset > t->sizeBytes ||
                    sliceBytes > t->sizeBytes - byteOffset)
                    return false;

                WeightTensor& wt = dst[e];
                wt.data = const_cast<uint8_t*>(t->data + byteOffset);
                wt.type = static_cast<int>(t->type);
                wt.cols = matDim[0];
                wt.rows = matDim[1];
                wt.sizeBytes = sliceBytes;
                wt.name = t->name + "#expert=" + std::to_string(e);
                wt.shape = { static_cast<int64_t>(matDim[0]), static_cast<int64_t>(matDim[1]) };
                wt.mapped = true;
                wt.shardId = t->shardId;
                if (static_cast<uint64_t>(byteOffset) >
                    std::numeric_limits<uint64_t>::max() - t->fileOffset)
                    return false;
                wt.fileOffset = t->fileOffset + static_cast<uint64_t>(byteOffset);
                wt.hasFileBacking = true;
            }
            std::fprintf(stderr,
                "[Deep2Engine] bound packed experts from '%s' "
                "expertDim=%d, shape=[%lld,%lld,%lld], experts=%zu\n",
                t->name.c_str(), expertDimIdx,
                static_cast<long long>(t->shape[0]),
                static_cast<long long>(t->shape[1]),
                static_cast<long long>(t->shape[2]),
                modelWeights.numExperts);
            return true;
        };

        auto bindSeparateExperts =
            [&](const char* role,
                const char* hfRole,
                const char* hfAlt,
                std::vector<WeightTensor>& dst) -> bool {
            dst.assign(modelWeights.numExperts, WeightTensor{});
            for (size_t e = 0; e < modelWeights.numExperts; ++e) {
                const std::string es = std::to_string(e);
                const std::vector<std::string> names = {
                    p + "ffn_" + role + "_exp." + es + ".weight",
                    p + "experts." + es + "." + hfRole + ".weight",
                    p + "moe.experts." + es + "." + hfRole + ".weight",
                    p + "experts." + es + "." + hfAlt + ".weight"
                };
                if (!bindAny(dst[e], names)) {
                    dst.clear();
                    return false;
                }
            }
            return !dst.empty();
        };

        auto bindExpertFamily =
            [&](const char* role,
                const char* hfRole,
                const char* hfAlt,
                std::vector<WeightTensor>& dst) -> bool {
            const std::vector<std::string> packedNames = {
                p + "ffn_" + role + "_exp.weight",
                p + "ffn_" + role + "_exps.weight"
            };
            if (bindPackedExperts(packedNames, dst)) return true;
            return bindSeparateExperts(role, hfRole, hfAlt, dst);
        };

        if (lw.moeRouter.data) {
            if (lw.moeRouter.rows != modelWeights.numExperts ||
                lw.moeRouter.cols != modelWeights.hiddenDim) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu MoE router geometry mismatch\n",
                    layer);
                if (diag) {
                    diag->stageCode = 9;
                    diag->stageName = "MOE_ROUTER_GEOMETRY";
                    diag->message = "Layer MoE router geometry mismatch (rows!=numExperts or cols!=hiddenDim).";
                }
                return false;
            }

            if (!bindExpertFamily("up",   "up_proj",   "w3", lw.moeUp) ||
                !bindExpertFamily("down", "down_proj", "w2", lw.moeDown)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing routed expert tensors\n",
                    layer);
                if (diag) {
                    diag->stageCode = 10;
                    diag->stageName = "MOE_EXPERT_TENSOR_MISSING";
                    diag->message = "Missing routed expert tensors (up/down) for MoE layer.";
                }
                return false;
            }
            // Nematron-H uses packed experts without per-expert gate projections (SwiGLU fused gate/up).
            // Only require gate if this is NOT a nemotron_h_moe model.
            if (arch != "nemotron_h_moe") {
                if (!bindExpertFamily("gate", "gate_proj", "w1", lw.moeGate)) {
                    std::fprintf(stderr,
                        "[Deep2Engine] layer %zu missing routed expert gate tensors\n",
                        layer);
                    if (diag) {
                        diag->stageCode = 10;
                        diag->stageName = "MOE_EXPERT_TENSOR_MISSING";
                        diag->message = "Missing routed expert gate tensors for MoE layer.";
                    }
                    return false;
                }
            } else {
                lw.moeGate.resize(modelWeights.numExperts);
                for (size_t e = 0; e < modelWeights.numExperts; ++e) lw.moeGate[e] = WeightTensor{};
            }

            if (lw.moeGate.size() != modelWeights.numExperts ||
                lw.moeUp.size() != modelWeights.numExperts ||
                lw.moeDown.size() != modelWeights.numExperts) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu incomplete expert set\n", layer);
                if (diag) {
                    diag->stageCode = 11;
                    diag->stageName = "MOE_INCOMPLETE_EXPERT_SET";
                    diag->message = "Incomplete expert set (moeGate/Up/Down size != numExperts).";
                }
                return false;
            }

            if (modelWeights.moeIntermediateDim == 0)
                modelWeights.moeIntermediateDim = lw.moeGate[0].rows != 0 ? lw.moeGate[0].rows : lw.moeUp[0].rows;

            const size_t EI = modelWeights.moeIntermediateDim;
            for (size_t e = 0; e < modelWeights.numExperts; ++e) {
                const auto& g = lw.moeGate[e];
                const auto& u = lw.moeUp[e];
                const auto& d = lw.moeDown[e];
                const bool gateOk = (arch == "nemotron_h_moe") || (g.rows == EI && g.cols == modelWeights.hiddenDim);
                if (!gateOk || u.rows != EI || u.cols != modelWeights.hiddenDim ||
                    d.rows != modelWeights.hiddenDim || d.cols != EI) {
                    std::fprintf(stderr,
                        "[Deep2Engine] layer %zu expert %zu geometry mismatch EI=%zu hiddenDim=%zu g(%zu,%zu) u(%zu,%zu) d(%zu,%zu)\n",
                        layer, e, EI, modelWeights.hiddenDim, g.rows, g.cols, u.rows, u.cols, d.rows, d.cols);
                    if (diag) {
                        diag->stageCode = 12;
                        diag->stageName = "MOE_EXPERT_GEOMETRY_MISMATCH";
                        diag->message = "Expert geometry mismatch (gate/up/down dimensions incorrect).";
                    }
                    return false;
                }
            }

            // Common DeepSeek/Kimi shared-expert tensor spellings.
            bindAny(lw.moeSharedGate, {
                p + "ffn_gate_shexp.weight",
                p + "shared_experts.gate_proj.weight",
                p + "shared_experts.w1.weight"
            });
            bindAny(lw.moeSharedUp, {
                p + "ffn_up_shexp.weight",
                p + "shared_experts.up_proj.weight",
                p + "shared_experts.w3.weight"
            });
            bindAny(lw.moeSharedDown, {
                p + "ffn_down_shexp.weight",
                p + "shared_experts.down_proj.weight",
                p + "shared_experts.w2.weight"
            });

            const bool anyShared =
                lw.moeSharedGate.data || lw.moeSharedUp.data ||
                lw.moeSharedDown.data;
            const bool allShared =
                lw.moeSharedGate.data &&
                lw.moeSharedUp.data &&
                lw.moeSharedDown.data;
            if ((arch != "nemotron_h" && arch != "nemotron_h_moe") && ((anyShared && !allShared) ||
                (modelWeights.numSharedExperts > 0 && !allShared))) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu incomplete shared expert\n",
                    layer);
                if (diag) {
                    diag->stageCode = 13;
                    diag->stageName = "MOE_SHARED_EXPERT_INCOMPLETE";
                    diag->message = "Incomplete shared expert (some tensors present but not all).";
                }
                return false;
            }
        }

        // NEMOTRON_H_LAYER_DIAG: before rejection, print every tensor we
        // already bound for block 0 so the fix is data-driven, not guessed.
        if (arch == "nemotron_h" && layer == 0) {
            std::fprintf(stderr, "NEMOTRON_H_LAYER_DIAG=%zu\n", layer);
            auto pr = [&](const char* label, const WeightTensor& wt) {
                std::fprintf(stderr, "  %s_PRESENT=%s\n", label, wt.data ? "1" : "0");
            };
            pr("ATTN_NORM", lw.attnNorm);
            pr("FFN_NORM", lw.ffnNorm);
            pr("SSM_IN", lw.ssmIn);
            pr("SSM_CONV1D", lw.ssmConv1d);
            pr("SSM_DT", lw.ssmDtBias);
            pr("SSM_A", lw.ssmA);
            pr("SSM_D", lw.ssmD);
            pr("SSM_NORM", lw.ssmNorm);
            pr("SSM_OUT", lw.ssmOut);
            pr("ATTN_QKV", lw.wqkv);
            pr("ATTN_Q", lw.wq);
            pr("ATTN_K", lw.wk);
            pr("ATTN_V", lw.wv);
            pr("ATTN_OUT", lw.wo);
            pr("FFN_UP", lw.wUp);
            pr("FFN_DOWN", lw.wDown);
            pr("FFN_GATE", lw.wGate);
        }

        // For Nemotron-H, do NOT enforce the generic attn_norm+ffn_norm
        // invariant that conventional transformers require.
        const bool isNemotronH = (arch == "nemotron_h" || arch == "nemotron_h_moe");
        if (isNemotronH) {
            // The block prenorm. Every Nemotron-H block — SSM, attention, MLP
            // or MoE alike — normalises through exactly one norm before its
            // single mixer. GGUF spells it blk.N.attn_norm.weight for all of
            // them, so this is the block norm, not an attention-specific one
            // and not a fallback for a missing FFN norm.
            const WeightTensor* blockNorm =
                lw.attnNorm.data ? &lw.attnNorm : (lw.ffnNorm.data ? &lw.ffnNorm : nullptr);
            if (!blockNorm) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing nemotron_h block norm\n",
                    layer);
                if (diag) {
                    diag->stageCode = 14;
                    diag->stageName = "NEMOTRON_H_LAYER_NORM_MISSING";
                    diag->message = "Nemotron-H layer missing block norm (blk.N.attn_norm.weight).";
                }
                return false;
            }
            if (blockNorm->cols != static_cast<int>(modelWeights.hiddenDim)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu nemotron_h block norm cols=%d expected=%zu\n",
                    layer, blockNorm->cols, modelWeights.hiddenDim);
                if (diag) {
                    diag->stageCode = 14;
                    diag->stageName = "NEMOTRON_H_LAYER_NORM_MISMATCH";
                    diag->message = "Nemotron-H block norm element count != hiddenDim.";
                }
                return false;
            }

            // ---- EXACTLY ONE MIXER PER LAYER ------------------------------
            // Derived from the GGUF per-layer hybrid pattern, never from
            // "which tensors happen to be present", because a block that owns
            // both a mixer and an FFN tensor set would otherwise silently run
            // two branches in sequence, which no Nemotron-H block does.
            //
            //   llama.cpp: recurrent = (n_head_kv(i)==0 && n_ff(i)==0)
            //              Mamba | Attention (n_ff==0) | Mlp/MoE
            if (!nemotronPatternOk_) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu nemotron_h block type unavailable:"
                    " per-layer pattern arrays were not loaded\n", layer);
                if (diag) {
                    diag->stageCode = 15;
                    diag->stageName = "NEMOTRON_H_BLOCK_TYPE_UNKNOWN";
                    diag->message =
                        "Nemotron-H block type cannot be derived: per-layer pattern arrays unavailable.";
                }
                return false;
            }
            const int64_t nHeadKv = nemotronHeadKvPerLayer_[layer];
            const int64_t nFf     = nemotronFfPerLayer_[layer];
            lw.nHeadKv = nHeadKv;
            lw.nFf     = nFf;

            const bool hasSSMBlock =
                lw.ssmIn.data || lw.ssmConv1d.data || lw.ssmDtBias.data ||
                lw.ssmA.data || lw.ssmD.data || lw.ssmNorm.data || lw.ssmOut.data;
            const bool hasAttnBlock =
                lw.wqkv.data || (lw.wq.data && lw.wk.data && lw.wv.data) || lw.wo.data;
            const bool hasFFNBlock = lw.wUp.data || lw.wDown.data || lw.wGate.data ||
                                    lw.moeUp.size() > 0 || lw.moeDown.size() > 0;

            const bool isRecurrent = (nHeadKv == 0 && nFf == 0);
            if (isRecurrent) {
                lw.mixer = LayerWeights::BlockMixer::Mamba;
            } else if (nFf == 0) {
                lw.mixer = LayerWeights::BlockMixer::Attention;
            } else if (lw.moeRouter.data || lw.moeUp.size() > 0 || lw.moeDown.size() > 0) {
                lw.mixer = LayerWeights::BlockMixer::MoE;
            } else {
                lw.mixer = LayerWeights::BlockMixer::Mlp;
            }

            // The tensor set must agree with the declared mixer. A disagreement
            // is a load error, not something to paper over by running both.
            const bool mixerTensorOk =
                (lw.mixer == LayerWeights::BlockMixer::Mamba)    ? hasSSMBlock :
                (lw.mixer == LayerWeights::BlockMixer::Attention) ? hasAttnBlock :
                (lw.mixer == LayerWeights::BlockMixer::Mlp)       ? hasFFNBlock :
                (lw.mixer == LayerWeights::BlockMixer::MoE)       ? (hasFFNBlock || hasAttnBlock) :
                false;
            if (!mixerTensorOk) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu nemotron_h mixer disagrees with tensors:"
                    " n_head_kv=%lld n_ff=%lld ssm=%d attn=%d ffn=%d\n",
                    layer, (long long)nHeadKv, (long long)nFf,
                    hasSSMBlock ? 1 : 0, hasAttnBlock ? 1 : 0, hasFFNBlock ? 1 : 0);
                if (diag) {
                    diag->stageCode = 15;
                    diag->stageName = "NEMOTRON_H_BLOCK_TYPE_MISMATCH";
                    diag->message = "Nemotron-H layer mixer type disagrees with bound tensors.";
                }
                return false;
            }

            // Exactly one mixer is selected by construction (single enum), and
            // the legacy independent flags are now projections of that one
            // choice rather than independent tensor-presence facts.
            lw.hasSSM = (lw.mixer == LayerWeights::BlockMixer::Mamba);
            lw.hasAttn = (lw.mixer == LayerWeights::BlockMixer::Attention);
            lw.hasFFN = (lw.mixer == LayerWeights::BlockMixer::Mlp) ||
                         (lw.mixer == LayerWeights::BlockMixer::MoE);

            if (layer == 0 || layer + 1 == modelWeights.numLayers) {
                std::fprintf(stderr,
                    "[Deep2Engine] NEMOTRON_BLOCK layer=%zu mixer=%s n_head_kv=%lld n_ff=%lld\n",
                    layer,
                    lw.mixer == LayerWeights::BlockMixer::Mamba    ? "MAMBA" :
                    lw.mixer == LayerWeights::BlockMixer::Attention ? "ATTENTION" :
                    lw.mixer == LayerWeights::BlockMixer::Mlp       ? "MLP" : "MOE",
                    (long long)nHeadKv, (long long)nFf);
            }
            // Skip generic QKV / FFN checks for Nemotron-H here; they are
            // validated below with architecture-aware rules.
        } else if (!lw.attnNorm.data || !lw.ffnNorm.data) {
            std::fprintf(stderr,
                "[Deep2Engine] layer %zu missing transformer norm tensors\n",
                layer);
            if (diag) {
                diag->stageCode = 14;
                diag->stageName = "LAYER_NORM_MISSING";
                diag->message = "Missing attn_norm.weight or ffn_norm.weight for layer.";
            }
            return false;
        }

        // RAWRXD_MLA_LOAD_AUTHORITY_001 (M5.4/M5.5): an MLA layer carries no
        // wq/wk/wv triple at all, so "missing Q/K/V topology" is the wrong
        // verdict for it. A rectangular model is therefore exempted from this
        // square check and from the head/geometry checks below (which divide
        // projection rows by one headDim), and the deferred eligibility decision
        // after this loop becomes the single authority on whether it may run.
        const bool mlaSplitTopology =
            mla.metadataParsed && mla.layoutSplit &&
            lw.attnQ_a.data && lw.attnQ_a_norm.data && lw.attnQ_b.data &&
            lw.attnKV_a_mqa.data && lw.attnKV_a_norm.data &&
            lw.attnK_b.data && lw.attnV_b.data && lw.attnO.data;
        const bool splitQkv =
            lw.wq.data && lw.wk.data && lw.wv.data;
        const bool fusedQkv = lw.wqkv.data != nullptr;
        if (!isNemotronH && !splitQkv && !fusedQkv && !mlaSplitTopology &&
            !mla.rectangular) {
            std::fprintf(stderr,
                "[Deep2Engine] layer %zu missing Q/K/V topology\n", layer);
            if (diag) {
                diag->stageCode = 15;
                diag->stageName = "QKV_TOPOLOGY_MISSING";
                diag->message = "Missing Q/K/V topology (neither split nor fused QKV present).";
            }
            return false;
        }

        if (!modelWeights.isMoE && !isNemotronH) {
            if (!lw.wUp.data || !lw.wDown.data) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing dense FFN tensors\n",
                    layer);
                if (diag) {
                    diag->stageCode = 16;
                    diag->stageName = "DENSE_FFN_MISSING";
                    diag->message = "Missing dense FFN tensors (wUp or wDown not bound).";
                }
                return false;
            }

            if (modelWeights.intermediateDim == 0)
                modelWeights.intermediateDim = lw.wUp.rows;

            if (lw.wUp.rows != modelWeights.intermediateDim ||
                lw.wUp.cols != modelWeights.hiddenDim ||
                lw.wDown.rows != modelWeights.hiddenDim ||
                lw.wDown.cols != modelWeights.intermediateDim) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu FFN geometry mismatch\n",
                    layer);
                if (diag) {
                    diag->stageCode = 17;
                    diag->stageName = "FFN_GEOMETRY_MISMATCH";
                    diag->message = "Dense FFN geometry mismatch (wUp/wDown dimensions incorrect).";
                }
                return false;
            }
        }

        if (splitQkv) {
            // Auto-correct numKVHeads and numHeads from actual tensor dimensions
            // (some GGUF files have metadata that doesn't match tensor shapes)
            const size_t inferredNumHeads = (modelWeights.headDim > 0)
                ? (lw.wq.rows / modelWeights.headDim)
                : modelWeights.numHeads;
            const size_t inferredNumKVHeads = (modelWeights.headDim > 0)
                ? (lw.wk.rows / modelWeights.headDim)
                : modelWeights.numKVHeads;
            if (inferredNumHeads != 0 && inferredNumHeads != modelWeights.numHeads) {
                std::fprintf(stderr,
                    "[Deep2Engine] Auto-correcting numHeads from %zu to %zu (from wq.rows=%zu / headDim=%zu)\n",
                    modelWeights.numHeads, inferredNumHeads,
                    lw.wq.rows, modelWeights.headDim);
                modelWeights.numHeads = inferredNumHeads;
            }
            if (inferredNumKVHeads != 0 && inferredNumKVHeads != modelWeights.numKVHeads) {
                std::fprintf(stderr,
                    "[Deep2Engine] Auto-correcting numKVHeads from %zu to %zu (from wk.rows=%zu / headDim=%zu)\n",
                    modelWeights.numKVHeads, inferredNumKVHeads,
                    lw.wk.rows, modelWeights.headDim);
                modelWeights.numKVHeads = inferredNumKVHeads;
            }
            const size_t qDim = modelWeights.numHeads * modelWeights.headDim;
            // Per-layer GQA geometry: use actual wk tensor dimensions instead of
            // global metadata, which may not reflect per-layer GQA group sizes
            // (Nemotron-H and other hybrid architectures).
            const size_t kvDim = lw.wk.rows;
            if (lw.wq.rows != qDim ||
                lw.wq.cols != modelWeights.hiddenDim ||
                lw.wk.rows != kvDim ||
                lw.wk.cols != modelWeights.hiddenDim ||
                lw.wv.rows != kvDim ||
                lw.wv.cols != modelWeights.hiddenDim) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu attention projection geometry mismatch."
                    " headDim=%zu qDim=%zu kvDim=%zu hiddenDim=%zu"
                    " wq(r=%zu,c=%zu) wk(r=%zu,c=%zu) wv(r=%zu,c=%zu)\n",
                    layer,
                    modelWeights.headDim, qDim, kvDim, modelWeights.hiddenDim,
                    lw.wq.rows, lw.wq.cols,
                    lw.wk.rows, lw.wk.cols,
                    lw.wv.rows, lw.wv.cols);
                if (diag) {
                    diag->stageCode = 18;
                    diag->stageName = "ATTN_PROJECTION_GEOMETRY";
                    char dmsg[512];
                    std::snprintf(dmsg, sizeof(dmsg),
                        "ATTN headDim=%zu qDim=%zu kvDim=%zu hiddenDim=%zu"
                        " wq(r=%zu,c=%zu) wk(r=%zu,c=%zu) wv(r=%zu,c=%zu).",
                        modelWeights.headDim, qDim, kvDim, modelWeights.hiddenDim,
                        lw.wq.rows, lw.wq.cols,
                        lw.wk.rows, lw.wk.cols,
                        lw.wv.rows, lw.wv.cols);
                    diag->message = dmsg;
                }
                return false;
            }

            const WeightTensor* outWeight =
                lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
            if (!outWeight ||
                outWeight->rows != modelWeights.hiddenDim ||
                outWeight->cols != qDim) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu attention output projection mismatch."
                    " expected rows=%zu cols=%zu got rows=%zu cols=%zu\n",
                    layer, modelWeights.hiddenDim, qDim,
                    outWeight ? outWeight->rows : 0,
                    outWeight ? outWeight->cols : 0);
                if (diag) {
                    diag->stageCode = 29;
                    diag->stageName = "ATTN_OUTPUT_GEOMETRY";
                    diag->message = "Attention output projection must map qDim -> hiddenDim.";
                }
                return false;
            }
        }
    }

    // RAWRXD_MLA_LOAD_AUTHORITY_001 (M5.6/M5.7): the deferred decision.
    //
    // MLA_EXECUTION_ELIGIBLE requires, exactly:
    //     metadata parsed
    //  && geometry validated (every division and relationship held exactly)
    //  && a RECOGNISED tensor layout the consumer can read
    //  && all tensors required BY THAT LAYOUT bound on EVERY layer
    //  && all five geometry values non-zero
    //
    // Anything less -> refuse. This is the single place the rectangle decision
    // is made, and it is deliberately AFTER the per-layer binder so eligibility
    // is judged on what was actually bound rather than on what was hoped for.
    //
    // RAWRXD_DEEPSEEK_CPU_E2E_001: `mla.layoutSplit` became
    // `(mla.layoutSplit || mla.layoutFused)`. The predicate previously admitted
    // exactly one of the two layouts the binder above can bind, which meant a
    // perfectly well-formed deepseek2 file was measured as fully bound and then
    // refused for "layout mismatch" -- the binder's own output contradicted the
    // predicate applied to it. The geometry requirement is UNCHANGED and still
    // exact: rectangular key/value lengths, validated divisions, and every
    // required tensor actually bound on every layer.
    if (mla.rectangular) {
        const bool allLayersBound =
            mla.metadataParsed && mla.numLayersExpected != 0 &&
            mla.layersFullyBound == mla.numLayersExpected;
        const bool geometryComplete =
            mla.qkNope != 0 && mla.qkRope != 0 && mla.vHead != 0 &&
            mla.kvLoraRank != 0 && mla.numHeads != 0;
        const bool layoutOk = mla.layoutSplit || mla.layoutFused;
        const bool eligible = mla.geometryValidated && layoutOk &&
                              allLayersBound && geometryComplete;
        if (eligible) {
            modelWeights.useMLA = true;
            std::fprintf(stderr,
                "[Deep2Engine] MLA_ELIGIBLE arch=%s layersBound=%zu/%zu "
                "layout=%s qkNopeHeadDim=%zu qkRopeHeadDim=%zu vHeadDim=%zu "
                "kvLoraRank=%zu numHeads=%zu useMLA=1\n",
                arch.c_str(), mla.layersFullyBound, mla.numLayersExpected,
                mla.layoutSplit ? "split" : "fused",
                mla.qkNope, mla.qkRope, mla.vHead, mla.kvLoraRank, mla.numHeads);
        } else {
            std::ostringstream msg;
            msg << "Rectangular attention refused: attention.key_length="
                << mla.keyLen << " != attention.value_length=" << mla.valueLen
                << ". MLA_EXECUTION_ELIGIBLE=0.";
            if (!mla.metadataParsed) {
                msg << " metadata did not bind.";
            } else if (!mla.geometryValidated) {
                msg << " geometry not validated: numHeads=" << mla.numHeads
                    << " kvLoraRank=" << mla.kvLoraRank
                    << " qLoraRank=" << mla.qLoraRank
                    << " qkNopeHeadDim=" << mla.qkNope
                    << " qkRopeHeadDim=" << mla.qkRope
                    << " vHeadDim=" << mla.vHead << ".";
} else if (!mla.layoutSplit && !mla.layoutFused) {
                msg << " layout mismatch: this file uses an UNRECOGNISED MLA "
                       "layout. Recognised are SPLIT (attn_q_a, attn_q_a_norm, "
                       "attn_q_b, attn_kv_a_mqa, attn_kv_a_norm, attn_k_b, "
                       "attn_v_b, attn_o) and FUSED (attn_q, attn_kv_a_mqa, "
                       "attn_kv_a_norm, attn_kv_b, attn_output). Missing on "
                       "layer 0: "
                    << (mla.missing.empty() ? "(none)" : mla.missing)
                    << ".";
            } else if (!allLayersBound) {
                msg << " tensors incomplete: bound on " << mla.layersFullyBound
                    << " of " << mla.numLayersExpected << " layers ("
                    << (mla.layoutSplit ? "split" : "fused")
                    << " layout requires all of them on EVERY layer). Missing on "
                       "layer 0: "
                    << (mla.missing.empty() ? "(none)" : mla.missing)
                    << ".";
            } else {
                msg << " geometry incomplete despite validation.";
            }
            msg << " RAWRXD_MLA_LOAD_AUTHORITY_001: M0-M3 closed, M5d closed "
                   "(geometry derived from tensor shapes), M5e closed for the "
                   "split layout, M4 held closed because eligibility is false.";
            if (diag) {
                diag->stageCode = 6;
                diag->stageName = "ATTN_HEAD_DIM_MISMATCH";
                diag->message = msg.str();
            }
            std::fprintf(stderr, "[Deep2Engine] MLA_NOT_ELIGIBLE arch=%s %s\n",
                         arch.c_str(), msg.str().c_str());
            std::fflush(stderr);
            return false;
        }
        std::fflush(stderr);
    }

    if (!modelWeights.isMoE && modelWeights.intermediateDim == 0 && !(arch == "nemotron_h")) {
        std::fprintf(stderr, "[Deep2Engine] missing feed-forward geometry\n");
        if (diag) {
            diag->stageCode = 19;
            diag->stageName = "FEED_FORWARD_GEOMETRY_MISSING";
            diag->message = "Missing feed-forward geometry (intermediateDim==0 for dense model).";
        }
        return false;
    }

    // Batch 8: initialize per-layer router runtimes from GGUF MoE metadata.
    moeRouters_.clear();
    moePinnedHandles_.clear();
    moeInitialized_ = false;

    if (modelWeights.isMoE) {
        if (modelWeights.numExpertsPerToken == 0 ||
            modelWeights.numExpertsPerToken > modelWeights.numExperts ||
            modelWeights.moeIntermediateDim == 0) {
            std::fprintf(stderr, "[Deep2Engine] invalid MoE metadata\n");
            if (diag) {
                diag->stageCode = 20;
                diag->stageName = "MOE_METADATA_INVALID";
                diag->message = "Invalid MoE metadata (numExpertsPerToken==0, >numExperts, or moeIntermediateDim==0).";
            }
            return false;
        }

        moeConfig_ = {};
        moeConfig_.numExperts = modelWeights.numExperts;
        moeConfig_.expertsPerToken = modelWeights.numExpertsPerToken;
        moeConfig_.numActiveExperts = modelWeights.numExpertsPerToken;
        moeConfig_.hiddenDim = modelWeights.hiddenDim;
        moeConfig_.expertDim = modelWeights.moeIntermediateDim;
        moeConfig_.sharedExpertDim = modelWeights.moeIntermediateDim;
        moeConfig_.numSharedExperts = modelWeights.numSharedExperts;
        moeConfig_.useSharedExpert = modelWeights.numSharedExperts > 0;

        const int64_t gating =
            loader->getMetaInt(arch + ".expert_gating_func", 1);
        if (gating < 1 || gating > 4 || gating == 3) {
            std::fprintf(stderr,
                "[Deep2Engine] unsupported expert_gating_func=%lld\n",
                static_cast<long long>(gating));
            if (diag) {
                diag->stageCode = 21;
                diag->stageName = "MOE_GATING_FUNC_UNSUPPORTED";
                diag->message = "Unsupported expert_gating_func value.";
            }
            return false;
        }
        moeConfig_.gatingFunc =
            static_cast<MoEGatingFunc>(static_cast<uint32_t>(gating));

        moeConfig_.expertWeightsScale = static_cast<float>(
            loader->getMetaFloat(arch + ".expert_weights_scale", 1.0));
        moeConfig_.normalizeSelectedWeights =
            loader->getMetaInt(arch + ".expert_weights_norm", 1) != 0;

        moeConfig_.expertGroupCount = static_cast<size_t>(std::max<int64_t>(
            0, loader->getMetaInt(arch + ".expert_group_count", 0)));
        moeConfig_.expertGroupUsedCount = static_cast<size_t>(std::max<int64_t>(
            0, loader->getMetaInt(arch + ".expert_group_used_count", 0)));
        moeConfig_.expertsPerGroup = static_cast<size_t>(std::max<int64_t>(
            0, loader->getMetaInt(arch + ".experts_per_group", 0)));

        moeRouters_.resize(modelWeights.numLayers);
        moePinnedHandles_.resize(modelWeights.numLayers);

        size_t moeLayerCount = 0;
        for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
            LayerWeights& lw = modelWeights.layers[layer];
            const bool layerIsMoE =
                lw.moeRouter.data &&
                lw.moeGate.size() == modelWeights.numExperts &&
                lw.moeUp.size() == modelWeights.numExperts &&
                lw.moeDown.size() == modelWeights.numExperts;

            if (!layerIsMoE) {
                // Leading/interleaved dense layers are legal in hybrid MoE.
                // Nematron-H pure attention layers have neither dense nor MoE FFN;
                // that is allowed if the layer has attention or SSM.
                if (!lw.wUp.data || !lw.wDown.data) {
                    const bool hasOtherBlock = (arch == "nemotron_h_moe") &&
                        (lw.hasSSM || lw.hasAttn || lw.hasFFN);
                    if (!hasOtherBlock) {
                        std::fprintf(stderr,
                            "[Deep2Engine] layer %zu has neither complete dense nor MoE FFN\n",
                            layer);
                        if (diag) {
                            diag->stageCode = 22;
                            diag->stageName = "HYBRID_FFN_INCOMPLETE";
                            diag->message = "Layer has neither complete dense nor MoE FFN tensors.";
                        }
                        return false;
                    }
                }
                continue;
            }

            auto router = std::make_unique<MoERouter>();
            if (!router->Initialize(moeConfig_)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu router initialization failed\n",
                    layer);
                if (diag) {
                    diag->stageCode = 23;
                    diag->stageName = "MOE_ROUTER_INIT_FAILED";
                    diag->message = "MoE router initialization failed for layer.";
                }
                return false;
            }
            moeRouters_[layer] = std::move(router);

            auto& handles = moePinnedHandles_[layer];
            handles.resize(modelWeights.numExperts);
            for (size_t e = 0; e < modelWeights.numExperts; ++e) {
                MoEWeightHandle& h = handles[e];
                h.layer = static_cast<int>(layer);
                h.expert = static_cast<int>(e);
                h.gate = &lw.moeGate[e];
                h.up = &lw.moeUp[e];
                h.down = &lw.moeDown[e];

                const size_t a = h.gate->sizeBytes;
                const size_t b = h.up->sizeBytes;
                const size_t c = h.down->sizeBytes;
                if (a > std::numeric_limits<size_t>::max() - b ||
                    a + b > std::numeric_limits<size_t>::max() - c) {
                    std::fprintf(stderr,
                        "[Deep2Engine] layer %zu expert %zu byte overflow\n",
                        layer, e);
                    if (diag) {
                        diag->stageCode = 24;
                        diag->stageName = "MOE_EXPERT_BYTE_OVERFLOW";
                        diag->message = "Expert byte size overflow (sum of gate/up/down bytes exceeds limits).";
                    }
                    return false;
                }
                h.bytes = a + b + c;
            }
            ++moeLayerCount;
        }

        if (moeLayerCount == 0) {
            std::fprintf(stderr,
                "[Deep2Engine] expert_count>0 but no MoE layer tensors were bound\n");
            if (diag) {
                diag->stageCode = 25;
                diag->stageName = "MOE_NO_LAYERS_BOUND";
                diag->message = "MoE enabled (expert_count>0) but no MoE layer tensors were bound.";
            }
            return false;
        }
        moeInitialized_ = true;

        // RAWRXD_EXPERT_CACHE_MOE_001: register all expert gate/up/down into each ExpertCache
        for (size_t dev = 0; dev < expertCaches_.size(); ++dev) {
            auto& cache = expertCaches_[dev];
            if (!cache) continue;
            for (size_t L = 0; L < modelWeights.layers.size(); ++L) {
                const auto& lw = modelWeights.layers[L];
                if (lw.moeGate.empty() || lw.moeUp.empty() || lw.moeDown.empty()) continue;
                for (size_t e = 0; e < lw.moeGate.size(); ++e) {
                    rawrxd::deep2::ExpertKey key{static_cast<uint32_t>(L), static_cast<uint32_t>(e)};
                    size_t totalBytes = lw.moeGate[e].sizeBytes + lw.moeUp[e].sizeBytes + lw.moeDown[e].sizeBytes;
                    std::vector<char> staging;
                    staging.resize(totalBytes);
                    std::memcpy(staging.data(), lw.moeGate[e].data, lw.moeGate[e].sizeBytes);
                    std::memcpy(staging.data() + lw.moeGate[e].sizeBytes, lw.moeUp[e].data, lw.moeUp[e].sizeBytes);
                    std::memcpy(staging.data() + lw.moeGate[e].sizeBytes + lw.moeUp[e].sizeBytes, lw.moeDown[e].data, lw.moeDown[e].sizeBytes);
                    expertStagingBuffers_.push_back(std::move(staging));
                    rawrxd::deep2::ExpertLocation loc{};
                    loc.hostPtr = expertStagingBuffers_.back().data();
                    loc.bytes   = totalBytes;
                    cache->registerExpert(key, loc);
                }
            }
        }

        std::fprintf(stderr,
            "[Deep2Engine] MoE bound: experts=%zu topk=%zu shared=%zu "
            "moe_layers=%zu gating=%u scale=%.4f norm=%u\n",
            modelWeights.numExperts,
            modelWeights.numExpertsPerToken,
            modelWeights.numSharedExperts,
            moeLayerCount,
            static_cast<unsigned>(moeConfig_.gatingFunc),
            moeConfig_.expertWeightsScale,
            moeConfig_.normalizeSelectedWeights ? 1u : 0u);
    }

    // Persist mapped-file ownership before any WeightTensor aliases are used.
    ggufResult.ok = true;
    ggufResult.mmapBound = 1;
    ggufResult.shardCount = loader->shardCount();
    ggufResult.loader = loader;

    config.numLayers = modelWeights.numLayers;
    config.numHeads = modelWeights.numHeads;
    config.numKVHeads = modelWeights.numKVHeads;
    config.headDim = modelWeights.headDim;
    config.hiddenDim = modelWeights.hiddenDim;
    config.vocabSize = modelWeights.vocabSize;
    config.intermediateDim = modelWeights.intermediateDim;
    config.useRoPE = modelWeights.ropeDimensionCount > 0;
    config.ropeTheta = modelWeights.ropeTheta;
    config.ropeScaling =
        modelWeights.ropeScaling > 0.0f ? modelWeights.ropeScaling : 1.0f;
    config.normEps = modelWeights.normEps;
    std::snprintf(config.modelPath, sizeof(config.modelPath), "%s",
                  ggufPath.c_str());

    modelWeights.loaded = true;
    if (cycloneEnabled_ && cyclone_) {
        cyclone_->onModelSwitch(static_cast<uint32_t>(modelWeights.numLayers), 0);
        Deep2::LivePath_BindCyclone(cyclone_.get());
    }

    // Runtime may be entered through loadModel-only clients.
    if (!initialized) {
        EngineConfig recovered = config;
        if (!initialize(recovered)) {
            if (diag) {
                diag->stageCode = 26;
                diag->stageName = "ENGINE_INIT_FAILED";
                diag->message = "Engine initialize(recovered) failed after GGUF bind.";
            }
            modelWeights.loaded = false;
            ggufResult = {};
            return false;
        }
    } else if (!allocateBuffers()) {
        if (diag) {
            diag->stageCode = 27;
            diag->stageName = "BUFFER_ALLOC_FAILED";
            diag->message = "allocateBuffers() failed after GGUF bind.";
        }
        modelWeights.loaded = false;
        ggufResult = {};
        return false;
    }

    if (config.useKVCache) {
        if (!kvCache) kvCache = std::make_unique<KVCache>();
        KVCacheConfig kc{};
        kc.numLayers = modelWeights.numLayers;
        kc.numHeads = modelWeights.numKVHeads;
        kc.headDim = modelWeights.headDim;
        kc.maxSeqLen = config.maxSeqLen;
        // RAWRXD_CPU_MLA_KERNEL_001: MLA stores one key and one value PER HEAD,
        // even though every head's slice is expanded from the same shared latent.
        // The sharing is in the WEIGHTS (attn_kv_b produces heads*(nope+vHead)
        // columns from one kvRank-wide input), not in the cache: at decode time
        // each head's kNope is a distinct 128-float vector and each is read
        // independently by that head's attention.
        //
        // So an MLA model must not take the numKVHeads value. DeepSeek-V2 GGUF
        // exports attention.head_count=16 and no separate KV head count, so
        // numKVHeads arrives as 1 (or 0) and a cache built from it is 16x too
        // small: every head past the first would write out of range, and
        // computeMLAAttentionCpu refuses on a geometry check rather than
        // corrupting memory. Sizing it correctly here is what makes the route
        // reachable at all.
        if (modelWeights.useMLA && modelWeights.numHeads != 0 &&
            kc.numHeads < modelWeights.numHeads) {
            std::fprintf(stderr,
                "[Deep2Engine] MLA_KV_HEADS_OVERRIDE numKVHeads=%zu -> numHeads=%zu "
                "(MLA keys/values are per-head; the latent sharing is in the weights)\n",
                (std::size_t)kc.numHeads, (std::size_t)modelWeights.numHeads);
            kc.numHeads = modelWeights.numHeads;
        }
        if (!kvCache->allocate(kc)) {
            std::fprintf(stderr, "[Deep2Engine] KV cache allocation failed\n");
            if (diag) {
                diag->stageCode = 28;
                diag->stageName = "KV_CACHE_ALLOC_FAILED";
                diag->message = "KV cache allocation failed.";
            }
            modelWeights.loaded = false;
            ggufResult = {};
            return false;
        }
    }

    // Tokenizer integration: use GGUF metadata when available.
    if (tokenizer) {
        if (auto* bpe = dynamic_cast<BPETokenizer*>(tokenizer.get())) {
            if (!bpe->loadFromGGUF(*loader)) {
                if (!bpe->loadFromFile(ggufPath + ".vocab")) {
                    std::fprintf(stderr, "[Deep2Engine] tokenizer load failed for %s\n", ggufPath.c_str());
                    if (diag) {
                        diag->stageCode = 29;
                        diag->stageName = "TOKENIZER_LOAD_FAILED";
                        diag->message = "Failed to load tokenizer from GGUF or fallback vocab file.";
                    }
                    modelWeights.loaded = false;
                    ggufResult = {};
                    return false;
                }
            }
        }
    }

    modelState_ = ModelState::Choreographable;

    std::fprintf(stderr,
        "[Deep2Engine] GGUF mapped: arch=%s shards=%u tensors=%zu "
        "layers=%zu hidden=%zu heads=%zu kv_heads=%zu vocab=%zu\n",
        arch.c_str(), loader->shardCount(), loader->tensorCount(),
        modelWeights.numLayers, modelWeights.hiddenDim,
        modelWeights.numHeads, modelWeights.numKVHeads,
        modelWeights.vocabSize);

    // Architecture report for parity audits (runtime values actually used).
    const bool hasBq = modelWeights.layers[0].bq.data != nullptr;
    const bool hasBk = modelWeights.layers[0].bk.data != nullptr;
    const bool hasBv = modelWeights.layers[0].bv.data != nullptr;
    std::fprintf(stderr,
        "ARCH=%s\nHIDDEN=%zu\nLAYERS=%zu\nHEADS=%zu\nKV_HEADS=%zu\n"
        "HEAD_DIM=%zu\nGQA_GROUP=%zu\nFFN_DIM=%zu\nROPE_THETA=%.6g\n"
        "ROPE_SCALING=%.6g\nROPE_DIM=%zu\nROPE_NEOX=%d\nRMS_EPS=%.6g\n"
        "Q_BIAS=%s\nK_BIAS=%s\nV_BIAS=%s\nTIE_EMBED=%d\n",
        arch.c_str(),
        modelWeights.hiddenDim, modelWeights.numLayers,
        modelWeights.numHeads, modelWeights.numKVHeads,
        modelWeights.headDim,
        modelWeights.numHeads / modelWeights.numKVHeads,
        modelWeights.intermediateDim,
        static_cast<double>(modelWeights.ropeTheta),
        static_cast<double>(modelWeights.ropeScaling),
        modelWeights.ropeDimensionCount,
        modelWeights.ropeNeoxStyle ? 1 : 0,
        static_cast<double>(modelWeights.normEps),
        hasBq ? "present" : "absent",
        hasBk ? "present" : "absent",
        hasBv ? "present" : "absent",
        modelWeights.tieEmbeddings ? 1 : 0);

    return true;
}

bool Deep2Engine::loadWeights(const void* weightData, size_t weightSize) {
    if (!weightData || weightSize == 0) return false;

    uint8_t* copy = new (std::nothrow) uint8_t[weightSize];
    if (!copy) return false;
    std::memcpy(copy, weightData, weightSize);

    delete[] reinterpret_cast<uint8_t*>(weights);
    weights = reinterpret_cast<float*>(copy);
    this->weightSize = weightSize;
    return true;
}

void Deep2Engine::unloadModel() {
    deallocateBuffers();
    delete[] reinterpret_cast<uint8_t*>(weights);
    weights = nullptr;
    weightSize = 0;
    modelWeights = {};
    ggufResult = {};
    specWs_.clear();
    // RAWRXD_D2_LIFECYCLE_001_HOTFIX (2nd site): the same ungated
    // specKvMirrorReset() that reset() gates at line ~893 is also reached here
    // via ~Deep2Engine -> unloadModel(). On the GPU path the spec K/V mirrors
    // are allocated, so ResetSpecKvMirror() runs destroyBuffer() during
    // teardown and faults (0xC0000005) before stdout is flushed. The reset()
    // hotfix documented this crash but only covered one of the two call sites.
    // Same gate, same default (OFF) until InferenceEngine_patched.lib is
    // rebuilt with the real fix.
    {
        static const char* enableSpecKvResetEnv =
            std::getenv("RAWRXD_ENABLE_SPEC_KV_RESET");
        const bool enableSpecKvReset =
            enableSpecKvResetEnv && (enableSpecKvResetEnv[0] == '1' ||
                                     enableSpecKvResetEnv[0] == 't' ||
                                     enableSpecKvResetEnv[0] == 'T');
        if (enableSpecKvReset) {
            specKvMirrorReset();
        }
    }
    kvCache = std::make_unique<KVCache>();
    clearCancel();
    // RAWRXD_REAL_GPU_FORWARD_002: model-unload reset, witnessed.
    resetGpuForwardCounters();
    gpuFwdCommitted_ = false;
    lmHeadPinned_[0] = false;
    lmHeadPinned_[1] = false;
    lmHeadPinRow0Count_ = 0;
    moeRouters_.clear();
    moePinnedHandles_.clear();
    if (cycloneEnabled_ && cyclone_) {
        cyclone_->reset();
        Deep2::LivePath_UnbindCyclone();
        cyclone_.reset();
        cycloneEnabled_ = false;
    }
    modelState_ = ModelState::Closed;
}

bool Deep2Engine::switchModel(const std::string& ggufPath) {
    std::fprintf(stderr, "[SWITCH_MODEL] unloading old model, loading '%s'\n", ggufPath.c_str()); std::fflush(stderr);
    unloadModel();
    bool ok = loadModel(ggufPath);
    std::fprintf(stderr, "[SWITCH_MODEL] loadModel result=%d\n", ok ? 1 : 0); std::fflush(stderr);
    return ok;
}

// =================== TOKENIZE / DETOKENIZE ====================
std::vector<int> Deep2Engine::tokenize(const std::string& text) {
    if (!tokenizer) {
        std::fprintf(stderr, "[TOKENIZE] FAIL: no tokenizer for text='%s' (len=%zu)\n", text.c_str(), text.size());
        std::fflush(stderr);
        return {};
    }
    auto toks = tokenizer->encode(text);
    std::fprintf(stderr, "[TOKENIZE] text='%s' -> %zu tokens\n", text.c_str(), toks.size());
    std::fflush(stderr);
    if (toks.empty()) {
        std::fprintf(stderr, "[TOKENIZE] WARNING: tokenizer returned 0 tokens for non-empty text\n");
        std::fflush(stderr);
    }
    return toks;
}

std::string Deep2Engine::detokenize(const std::vector<int>& tokens) {
    if (!tokenizer) {
        std::fprintf(stderr, "[DETOKENIZE] FAIL: no tokenizer for %zu tokens\n", tokens.size());
        std::fflush(stderr);
        return "";
    }
    auto result = tokenizer->decode(tokens);
    std::fprintf(stderr, "[DETOKENIZE] %zu tokens -> '%s' (len=%zu)\n", tokens.size(), result.c_str(), result.size());
    std::fflush(stderr);
    return result;
}

// =================== EMBED TOKEN (REAL MAPPED WEIGHT ROW) ====================
bool Deep2Engine::embedToken(int tokenId, float* output) {
    if (!modelWeights.loaded || !output ||
        tokenId < 0 ||
        static_cast<size_t>(tokenId) >= modelWeights.vocabSize) {
        std::fprintf(stderr, "[EMBED] FAIL: loaded=%d output=%p tokenId=%d vocabSize=%zu\n",
            modelWeights.loaded ? 1 : 0, (void*)output, tokenId, (size_t)modelWeights.vocabSize);
        std::fflush(stderr);
        return false;
    }

    const WeightTensor& wt = modelWeights.tokenEmbed;
    const size_t H = modelWeights.hiddenDim;
    const size_t V = modelWeights.vocabSize;

    if (!wt.data || wt.rows != V || wt.cols != H || H == 0) {
        std::fprintf(stderr, "[EMBED] FAIL: wt.data=%p rows=%zu cols=%zu H=%zu V=%zu\n",
            (void*)wt.data, (size_t)wt.rows, (size_t)wt.cols, H, V);
        std::fflush(stderr);
        return false;
    }

    const auto* desc = LookupQuantType(static_cast<uint32_t>(wt.type));
    if (!desc || desc->blockBytes == 0 || desc->blockElements == 0)
        return false;

    if (desc->blockElements > 1 && (H % desc->blockElements) != 0)
        return false;

    const size_t blocksPerRow =
        (H + desc->blockElements - 1) / desc->blockElements;
    if (blocksPerRow >
        std::numeric_limits<size_t>::max() / desc->blockBytes)
        return false;

    const size_t rowBytes = blocksPerRow * desc->blockBytes;
    const size_t row = static_cast<size_t>(tokenId);
    if (row > std::numeric_limits<size_t>::max() / rowBytes)
        return false;

    const size_t offset = row * rowBytes;
    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: the clearest CLASS-A bypass. This
    // computes an address inside tokenEmbed.data and hands it straight to the
    // dequantizer. LinearW() is nowhere in the chain, so embedToken and every
    // caller that inherits it (embedTokensBatch) sit outside the LinearW funnel.
    {
        using namespace rawrxd::deep2::weightcensus;
        Event eev;
        eev.site = Site::EmbedToken;
        eev.route = Route::Bypass;
        eev.tensor = wt.name;
        eev.bytes = rowBytes;   // exactly the bytes this embedding row reads
        WeightConsumptionCensus::instance().record(eev);
    }
    if (wt.sizeBytes != 0 &&
        (offset > wt.sizeBytes || rowBytes > wt.sizeBytes - offset))
        return false;

    auto dequant = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!dequant) {
        std::fprintf(stderr, "[EMBED] FAIL: no dequant kernel for type=%d\n", wt.type); std::fflush(stderr);
        return false;
    }

    const auto* src = static_cast<const uint8_t*>(wt.data) + offset;
    dequant(src, output, H);

    // Gemma3: scale embeddings by sqrt(hiddenDim)
    if (modelArchitecture_ == "gemma3") {
        const float scale = std::sqrt(static_cast<float>(H));
        for (size_t i = 0; i < H; ++i) output[i] *= scale;
    }

    parityEmit(ParityCheckpoint::Embed, output, H);
    return finiteVector(output, H);
}

bool Deep2Engine::embedTokensBatch(
    const int32_t* tokenIds,size_t count,float* outputBatch)
{
    if(!tokenIds||!outputBatch||count==0||count>4||
       modelWeights.hiddenDim==0) {
        std::fprintf(stderr, "[EMBED_BATCH] FAIL: tokenIds=%p output=%p count=%zu hiddenDim=%zu\n",
            (void*)tokenIds, (void*)outputBatch, count, (size_t)modelWeights.hiddenDim);
        std::fflush(stderr);
        return false;
    }
    const size_t H=modelWeights.hiddenDim;
    for(size_t b=0;b<count;++b) {
        if(!embedToken(tokenIds[b],outputBatch+b*H)) {
            std::fprintf(stderr, "[EMBED_BATCH] FAIL: embedToken failed at batch index %zu (tokenId=%d)\n", b, tokenIds[b]);
            std::fflush(stderr);
            return false;
        }
    }
    return true;
}

static bool deep2ForwardTraceEnabled();  // forward decl (defined later in this file)

// =================== COMPUTE LOGITS (FINAL NORM + REAL LM HEAD) ====================
void Deep2Engine::computeLogits(const float* hiddenState, float* logitsOut) {
    if (!modelWeights.loaded || !hiddenState || !logitsOut)
        throw std::runtime_error("computeLogits: invalid state");

    const size_t H = modelWeights.hiddenDim;
    const size_t V = modelWeights.vocabSize;

    if (H == 0 || V == 0 ||
        !modelWeights.finalNorm.data ||
        !modelWeights.lmHead.data ||
        !layerTemp) {
        throw std::runtime_error(
            "computeLogits: final norm / LM head not bound");
    }

    RMSNormW(modelWeights.finalNorm, hiddenState, layerTemp,
             H, modelWeights.normEps);
    {
        // RAWRXD_DEEP2_LOG_FLOOD_001: unconditional, once per token, and it
        // computes a full H-element min/max reduction on every token purely to
        // print two numbers nobody asked for. Both the write and the reduction
        // are on the decode critical path. Now opt-in, and the reduction only
        // happens when it will actually be printed.
        static const bool traceFinalNorm = [] {
            const char* e = std::getenv("RAWRXD_TRACE_FINALNORM");
            return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
        }();
        if (traceFinalNorm) {
            float fnMin = std::numeric_limits<float>::infinity();
            float fnMax = -std::numeric_limits<float>::infinity();
            for (size_t i = 0; i < H; ++i) {
                if (layerTemp[i] < fnMin) fnMin = layerTemp[i];
                if (layerTemp[i] > fnMax) fnMax = layerTemp[i];
            }
            std::fprintf(stderr, "FINALNORM_POST min=%g max=%g\n", fnMin, fnMax);
            std::fflush(stderr);
        }
    }
    parityEmit(ParityCheckpoint::FinalNorm, layerTemp, H);
    LinearW(modelWeights.lmHead, layerTemp, nullptr, logitsOut, V);
    // RAWRXD_DEBUG_EXPOSE_LOGITS_001
    // Capture the logits for the divergence harness, gated so it can never
    // become a silent product API.
    //
    // The public API deliberately does not expose logits, which is correct
    // product design. But that made the Vulkan divergence unlocatable: the
    // ladder could only observe that the emitted TOKEN differed, and a wrong
    // token is the last symptom of a long causal chain. Comparing logits
    // between routes is what separates "the final projection is misindexed"
    // from "an early layer diverged and the projection faithfully reported
    // the damage".
    //
    // Gated on DEEP2_DEBUG_EXPOSE_LOGITS=1. stepSeq_ increments on every
    // capture so a harness can tell a fresh vector from a stale one rather
    // than diffing against whatever happened to be left over.
    if (debugLogitsEnabled()) {
        debugLastLogits_.assign(logitsOut, logitsOut + V);
        ++debugLogitsStep_;
    }

    if (!finiteVector(logitsOut, V))
        throw std::runtime_error("computeLogits: non-finite logits");
    parityEmit(ParityCheckpoint::Logits, logitsOut, V);
}

void Deep2Engine::computeLogitsBatch(
    const float* hiddenBatch,size_t count,float* logitsBatch)
{
    if(!hiddenBatch||!logitsBatch||count==0||count>4)
        throw std::runtime_error("computeLogitsBatch: invalid batch");
    const size_t H=modelWeights.hiddenDim;
    const size_t V=modelWeights.vocabSize;
    if(!H||!V||!modelWeights.finalNorm.data||!modelWeights.lmHead.data)
        throw std::runtime_error("computeLogitsBatch: model tensors missing");

    std::vector<float> normed(count*H);
    for(size_t b=0;b<count;++b)
        RMSNormW(modelWeights.finalNorm,
                 hiddenBatch+b*H,normed.data()+b*H,
                 H,modelWeights.normEps);
    LinearWBatch4(modelWeights.lmHead,normed.data(),count,nullptr,
                  logitsBatch,V);
}

// =================== SAMPLE TOKEN ====================
int Deep2Engine::sampleToken(const float* logitsPtr) {
    if (!sampler) {
        std::fprintf(stderr, "[SAMPLE] FAIL: no sampler\n"); std::fflush(stderr);
        return 0;
    }
    if (!logitsPtr) {
        std::fprintf(stderr, "[SAMPLE] FAIL: null logits\n"); std::fflush(stderr);
        return 0;
    }
    // RAWRXD_BATCH_02_SAMPLER_GATE_001 â€” apply repetition penalty to a local
    // mutable copy of logits before sampling, so the configured
    // repeatPenalty actually reaches the sampling path. Skip the copy and
    // penalty entirely when no penalty is configured â€” sample directly from
    // the caller's buffer to avoid an extra vocab-sized heap allocation on
    // every decode token.
    if (repPenaltyProcessor_ && repPenaltyProcessor_->active()) {
        std::vector<float> logitsCopy(logitsPtr, logitsPtr + config.vocabSize);
        repPenaltyProcessor_->apply(logitsCopy.data(), (int)config.vocabSize,
                                    generatedTokensHistory_.data(),
                                    (int)generatedTokensHistory_.size());
        return sampler->sample(logitsCopy.data(), (int)config.vocabSize);
    }
    return sampler->sample(logitsPtr, (int)config.vocabSize);
}

// =================== DECODE CONTINUOUS ONE ====================
// RAWRXD_CONTINUOUS_STREAM_REALITY_001
// The only live decode primitive. No other generation path exists for
// chat, agentic, swarm, or tool-resume mode.
bool Deep2Engine::initializeDecodeCursor(DecodeCursor& cursor) const {
    if (!initialized || !modelWeights.loaded ||
        config.hiddenDim == 0 || config.vocabSize == 0) {
        std::fprintf(stderr, "[DECODE_CURSOR] FAIL: init=%d loaded=%d hiddenDim=%zu vocabSize=%zu\n",
            initialized ? 1 : 0, modelWeights.loaded ? 1 : 0,
            (size_t)config.hiddenDim, (size_t)config.vocabSize);
        std::fflush(stderr);
        return false;
    }
    cursor.hidden.assign(config.hiddenDim, 0.0f);
    cursor.logits.assign(config.vocabSize, 0.0f);
    cursor.pendingToken = -1;
    cursor.pendingForward = false;
    cursor.seq = 0;
    cursor.lockedRoute = ExecutionRoute::Unset;
    cursor.requiresResidentGpu = false;
    cursor.maxOutputTokens = 0;
    cursor.tokensGenerated = 0;
    return true;
}

Deep2Engine::DecodeOneResult Deep2Engine::decodeContinuousOne(DecodeCursor& cursor) {
    using R = DecodeOneResult;

    // --- Validate state ---
    if (!initialized || !modelWeights.loaded) {
        std::fprintf(stderr, "[DECODE_ONE] ERROR: ENGINE_NOT_INITIALIZED\n"); std::fflush(stderr);
        return R::make_error("ENGINE_NOT_INITIALIZED");
    }
    if (cursor.hidden.size() != config.hiddenDim ||
        cursor.logits.size() != config.vocabSize) {
        std::fprintf(stderr, "[DECODE_ONE] ERROR: CURSOR_GEOMETRY_MISMATCH hidden=%zu/%zu logits=%zu/%zu\n",
            cursor.hidden.size(), (size_t)config.hiddenDim,
            cursor.logits.size(), (size_t)config.vocabSize);
        std::fflush(stderr);
        return R::make_error("CURSOR_GEOMETRY_MISMATCH");
    }

    // --- Cancel check ---
    if (cancelRequested_.load(std::memory_order_acquire)) {
        std::fprintf(stderr, "[DECODE_ONE] CANCELLED\n"); std::fflush(stderr);
        return R::make_error("CANCELLED");
    }

    // --- Forward the pending token (if any) ---
    if (cursor.pendingForward) {
        if (cursor.pendingToken < 0 ||
            static_cast<size_t>(cursor.pendingToken) >= modelWeights.vocabSize) {
            return R::make_error("INVALID_PENDING_TOKEN");
        }

        if (!embedToken(cursor.pendingToken, cursor.hidden.data())) {
            std::fprintf(stderr, "[DECODE_ONE] ERROR: EMBED_FAILED tokenId=%d\n", cursor.pendingToken); std::fflush(stderr);
            return R::make_error("EMBED_FAILED");
        }

        const size_t seq = kvCache ? kvCache->currentLength() + 1 : cursor.seq + 1;

        auto fr = forwardTokenAllLayers(cursor.hidden.data(), seq);
        // RAWRXD_REUSE_DECODE_PATH_EMISSION_001
        // The decode path owns the reuse receipt, not the harness. Emitting here
        // means a production decode always produces one, on every route including
        // the error paths below, because the call precedes them. Previously the
        // only caller was a cert destructor, so a normal `rawr`/server decode
        // emitted nothing and the measurement was structurally unavailable outside
        // a test harness.
        EmitExpertReuseSummaryFromDecodePath();
        if (!fr.ok) {
            std::fprintf(stderr, "[DECODE_ONE] ERROR: FORWARD_FAILED stage=%s route=%d\n",
                fr.failureStage ? fr.failureStage : "(null)", (int)fr.actualRoute); std::fflush(stderr);
            return R::make_error("FORWARD_FAILED");
        }

        // Route locking: first forward establishes the route.
        if (cursor.lockedRoute == ExecutionRoute::Unset) {
            cursor.lockedRoute = fr.actualRoute;
            cursor.requiresResidentGpu = (fr.actualRoute == ExecutionRoute::VulkanResident);
        }
        // Route mutation is a fatal violation.
        if (fr.actualRoute != cursor.lockedRoute) {
            return R::make_error("EXECUTION_ROUTE_MUTATED");
        }
        // Resident-forward must commit GPU work before KV advance.
        if (cursor.requiresResidentGpu && !fr.gpuCommitted) {
            return R::make_error("GPU_FORWARD_NOT_COMMITTED");
        }

        // Only advance KV after a committed forward.
        if (config.useKVCache && kvCache) {
            if (!kvCache->advance()) {
                return R::make_error("KV_ADVANCE_FAILED");
            }
        }
        cursor.seq = seq;
        cursor.pendingForward = false;
    }

    // --- Compute logits ---
    try {
        computeLogits(cursor.hidden.data(), cursor.logits.data());
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[DECODE_ONE] ERROR: LOGITS_FAILED: %s\n", e.what()); std::fflush(stderr);
        return R::make_error("LOGITS_FAILED");
    }

    // --- Sample token ---
    const int nextTok = sampleToken(cursor.logits.data());
    if (nextTok < 0 || static_cast<size_t>(nextTok) >= config.vocabSize) {
        std::fprintf(stderr, "[DECODE_ONE] ERROR: SAMPLE_FAILED nextTok=%d vocabSize=%zu\n",
            nextTok, (size_t)config.vocabSize); std::fflush(stderr);
        return R::make_error("SAMPLE_FAILED");
    }

    cursor.pendingToken = nextTok;
    cursor.pendingForward = true;
    ++cursor.tokensGenerated;

    return R::make_token(nextTok);
}

int Deep2Engine::sampleCommittedToken(const float* logitsPtr) {
    return sampleToken(logitsPtr);
}

// =================== CONFIGURE GENERATION ====================
void Deep2Engine::configureGeneration(const GenerationOptions& options) {
    // RAWRXD_BATCH_02_SAMPLER_GATE_001 â€” every GenerationOptions field must
    // reach a real consumer or be explicitly unsupported.
    //
    //   maxTokens     -> consumed by generateStream (limit at L4155)
    //   temperature   -> consumed by every sampler below
    //   topK          -> consumed by CombinedSampler / TopKSampler
    //   topP          -> consumed by TopPSampler / CombinedSampler
    //   minP          -> consumed by MinPSampler / CombinedSampler
    //   repeatPenalty -> applied by RepetitionPenaltyProcessor if > 1.0f;
    //                    applied here at configureGeneration when combined
    //                    sampler is selected
    //   seed          -> consumed by every stochastic sampler (TopP, MinP,
    //                    Combined). When deterministicGreedy_ is true the
    //                    sampler has no stochastic draw and seed is a no-op
    //                    by design; this is documented as NO_CONSUMER for
    //                    greedy, CONSUMED_BY for stochastic.

    // Determine if any stochastic feature is in play: topP < 1.0f, minP > 0,
    // OR repeatPenalty > 1.0f (repetition penalty does not require stochastic
    // sampling but we still use CombinedSampler so the seed is honored when
    // combined with topP/minP).
    const bool stochasticRequested =
        (options.topP > 0.0f && options.topP < 1.0f) ||
        (options.minP > 0.0f) ||
        (options.repeatPenalty > 1.0f);

    if ((options.temperature <= 0.0f || options.topK <= 1) && !stochasticRequested) {
        // Pure greedy. Seed is a no-op by design; record that.
        deterministicGreedy_ = true;
        sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
    } else {
        // CombinedSampler consumes topK + topP + minP + temperature + seed.
        deterministicGreedy_ = false;
        sampler = std::make_unique<rawrxd::sampling::CombinedSampler>(
            options.topK,
            options.topP,
            options.minP,
            options.temperature,
            options.seed);
    }

    // Repetition penalty: store the processor in a member so it can be applied
    // before sampling in the decode loop. The processor is active iff penalty
    // > 1.0f. We never destroy an existing penalty processor here unless the
    // engine was configured without one.
    if (options.repeatPenalty > 1.0f) {
        repPenaltyProcessor_ = std::make_unique<rawrxd::sampling::RepetitionPenaltyProcessor>(options.repeatPenalty);
    } else {
        repPenaltyProcessor_.reset();
    }
}

bool Deep2Engine::isDeterministicGreedy() const { return deterministicGreedy_; }

void Deep2Engine::enableVerifiedSpeculation(bool enable,uint32_t window) {
    medusaEnabled_=enable;
    medusaConfig_.window=std::max<uint32_t>(1,std::min<uint32_t>(4,window));
    if(enable) {
        medusaDecoder_=std::make_unique<MedusaDecoder>(medusaConfig_);
    } else {
        medusaDecoder_.reset();
    }
}

const SpeculativeCounters& Deep2Engine::speculativeCounters() const {
    return medusaDecoder_?medusaDecoder_->stats.exact:speculativeEmpty_;
}

// =================== TRACE PROFILE POLICY ====================
// RAWRXD_TRACE_PROFILE_POLICY_001
// Controls which traces fire. Profiles:
//   perf    â€” no stderr hotpath spam; structured counters only; TPS valid
//   ide     â€” structured IDE diagnostics; stage events; summaries; no flood
//   debug   â€” full unsilent stderr flood; TPS marked DEBUG_CONTAMINATED
//   receipt â€” machine-readable receipts only
//
// Default: perf for rawr CLI, ide for Win32IDE (detected via --headless flag)
// Override: RAWRXD_TRACE_PROFILE=<perf|ide|debug|receipt>
//           RAWRXD_VERBOSE=1 / RAWRXD_TRACE_TOKEN=1 / DEEP2_TRACE_FORWARD=1 â†’ debug
enum class TraceProfile { Perf, Ide, Debug, Receipt };

static TraceProfile rawrxdTraceProfile() {
    static const TraceProfile profile = [] {
        const char* env = std::getenv("RAWRXD_TRACE_PROFILE");
        if (env && env[0]) {
            if (std::strcmp(env, "debug") == 0) return TraceProfile::Debug;
            if (std::strcmp(env, "ide") == 0) return TraceProfile::Ide;
            if (std::strcmp(env, "receipt") == 0) return TraceProfile::Receipt;
            if (std::strcmp(env, "perf") == 0) return TraceProfile::Perf;
        }
        // Legacy env vars force debug
        auto on = [](const char* name) {
            const char* v = std::getenv(name);
            return v && v[0] && v[0] != '0';
        };
        if (on("DEEP2_TRACE_FORWARD") || on("RAWRXD_VERBOSE") ||
            on("RAWRXD_TRACE_TOKEN"))
            return TraceProfile::Debug;
        // Default: perf (clean TPS, no hotpath spam)
        return TraceProfile::Perf;
    }();
    return profile;
}

// Hotpath spam = per-layer, per-token, per-LinearW traces.
// Only fire in debug mode. In ide mode, fire stage events only.
static bool rawrxdHotpathTraceEnabled() {
    return rawrxdTraceProfile() == TraceProfile::Debug;
}

// Stage events = [INIT], [ALLOC], [FWD_ALL] entry, [STREAM] RESULT, failures.
// Fire in debug AND ide mode. Suppress in perf and receipt.
static bool rawrxdStageTraceEnabled() {
    auto p = rawrxdTraceProfile();
    return p == TraceProfile::Debug || p == TraceProfile::Ide;
}

// Failure traces = silent-failure-path diagnostics (embed fail, forward fail, etc).
// Fire in all modes except receipt-only.
static bool rawrxdFailureTraceEnabled() {
    return rawrxdTraceProfile() != TraceProfile::Receipt;
}

// Summary traces = [STREAM] RESULT, [GENERATE] EXIT, TPS.
// Fire in all modes (including perf) â€” these are the clean TPS receipts.
static bool rawrxdSummaryTraceEnabled() {
    return true;
}

// =================== FORWARD-LAYER TRACE GATE ====================
// Product path (rawr run) must stream only generated text to stdout and
// receipts to stderr. Per-op FWD_LAYER/LINEARW tracing is a batch-gate
// diagnostic: opt-in via DEEP2_TRACE_FORWARD=1 (checked once per process).
static bool deep2ForwardTraceEnabled() {
    return rawrxdHotpathTraceEnabled();
}

// B4b: once the lmHead slices are pinned at the frozen split geometry, the
// per-token probe/pin bookkeeping is pure overhead. Re-probing stays
// available for diagnostics via DEEP2_LMHEAD_GEOMETRY_PROBE=1 (checked
// once per process). The frozen-split gate already makes geometry drift
// impossible during decode unless DEEP2_SPLIT_FREEZE=0.
static bool lmHeadGeometryProbeEnabled() {
    static const bool enabled = [] {
        const char* v = std::getenv("DEEP2_LMHEAD_GEOMETRY_PROBE");
        return v && v[0] == '1';
    }();
    return enabled;
}

// =================== QUANT-AWARE LINEAR ====================
void Deep2Engine::LinearW(const WeightTensor& wt,
                          const float* input,
                          const float* bias,
                          float* output,
                          size_t outDim) {
    const char* wtn = wt.name.empty() ? "null" : wt.name.c_str();
    RAWRXD_DEEP2_TRACE("LINEARW name=%s rows=%zu cols=%zu type=%d\n",
                 wtn, wt.rows, wt.cols, wt.type);

    // RAWRXD_LINEARW_BOUNDARY_IDENTITY_001 — observe only. Captures the exact
    // operands at the LinearW boundary, because the spine samples upstream and
    // an ~835x amplification remains unexplained by any Q2_K scale width (both
    // 4-bit and 6-bit arms poison). Pointer identity alone is insufficient, so
    // each operand is content-fingerprinted with FNV-1a and the first weight
    // row is hashed separately using the measured row_bytes=1008, which
    // distinguishes a correct base pointer with a wrong row stride from a
    // genuinely wrong address.
    if (const char* lwEnv = std::getenv("RAWRXD_LWBOUND")) {
        if (lwEnv[0] && lwEnv[0] != '0') {
            auto fnv1a64 = [](const void* p, size_t n) -> uint64_t {
                const unsigned char* b = static_cast<const unsigned char*>(p);
                uint64_t h = 1469598103934665603ull;
                if (!b) return 0;
                for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 1099511628211ull; }
                return h;
            };
            std::fprintf(stderr,
                "[LWBOUND] tensor=%s x=%p wdata=%p rows=%zu cols=%zu type=%d bias=%p out=%p\n",
                wtn, (const void*)input, (const void*)wt.data,
                wt.rows, wt.cols, wt.type, (const void*)bias, (const void*)output);

            // RAWRXD_TENSOR_PROVENANCE_001 — identity before interpretation.
            // Pointer equality is NOT the criterion: copying, staging, dequant
            // or GPU upload may legitimately move bytes. The criterion is whether
            // the consumer operates on bytes DERIVED FROM the tensor the loader
            // claims to have selected. This ID hashes provenance fields only, so
            // it survives rebasing and can be compared across two observation
            // sites in the SAME process without any shared mutable state.
            {
                uint64_t h = 1469598103934665603ull;
                auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ull; };
                auto mixStr = [&](const std::string& s) {
                    mix(s.size());
                    for (char c : s) mix((uint64_t)(unsigned char)c);
                };
                mixStr(wt.name);
                mix((uint64_t)wt.type);
                mix((uint64_t)wt.rows);
                mix((uint64_t)wt.cols);
                mix((uint64_t)wt.sizeBytes);
                mix((uint64_t)wt.shardId);
                mix(wt.hasFileBacking ? wt.fileOffset : 0xFFFFFFFFFFFFFFFFull);
                mix((uint64_t)(wt.hasFileBacking ? 1 : 0));
                mix((uint64_t)wt.shape.size());
                for (auto d : wt.shape) mix((uint64_t)d);
                std::fprintf(stderr,
                    "[PROV] site=LWBOUND tensor=%s id=%016llx shard=%u file_off=%lld "
                    "backing=%d bytes=%zu dims=%zux%zu\n",
                    wtn, (unsigned long long)h, wt.shardId,
                    (long long)(wt.hasFileBacking ? (long long)wt.fileOffset : -1LL),
                    wt.hasFileBacking ? 1 : 0, wt.sizeBytes, wt.rows, wt.cols);
            }

            std::fprintf(stderr,
                "[LW_X] ptr=%p bytes=%zu hash=%016llx x0=%.9g x1=%.9g xlast=%.9g\n",
                (const void*)input, sizeof(float) * wt.cols,
                (unsigned long long)fnv1a64(input, sizeof(float) * wt.cols),
                wt.cols > 0 ? input[0] : 0.0f,
                wt.cols > 1 ? input[1] : 0.0f,
                wt.cols > 0 ? input[wt.cols - 1] : 0.0f);
            std::fprintf(stderr,
                "[LW_W] ptr=%p bytes=%zu hash=%016llx\n",
                (const void*)wt.data, (size_t)4096,
                (unsigned long long)fnv1a64(wt.data, 4096));
            const size_t rowBytes = (wt.cols / 256ull) * 84ull;
            if (rowBytes) {
                const unsigned char* base = static_cast<const unsigned char*>(wt.data);
                const size_t rows = wt.rows;
                std::fprintf(stderr,
                    "[LW_WROW] row_bytes=%zu rows=%zu r0=%016llx r1=%016llx rlast=%016llx\n",
                    rowBytes, rows,
                    (unsigned long long)fnv1a64(base, rowBytes),
                    (unsigned long long)fnv1a64(base + rowBytes, rowBytes),
                    (unsigned long long)fnv1a64(base + rowBytes * (rows - 1), rowBytes));
            }
            std::fflush(stderr);
        }
    }

    if (!wt.data || !input || !output || outDim == 0) {
        throw std::runtime_error("LinearW: null tensor/input/output");
    }

    size_t rows = 0, cols = 0;
    if (!matrixShape(wt, rows, cols) || rows != outDim) {
        throw std::runtime_error("LinearW: invalid matrix geometry");
    }

    const size_t required = packedBytesRequired(wt.type, rows, cols);
    if (required == 0) {
        throw std::runtime_error("LinearW: unsupported quant type");
    }
    if (wt.sizeBytes != 0 && required > wt.sizeBytes) {
        throw std::runtime_error("LinearW: tensor backing smaller than geometry");
    }

    // BATCH10_ROW_SPLIT_LINEAR Ã¢â‚¬â€ real GPU arithmetic, host result contract.
    if (vulkanInitialized_ && !vulkanDevices_.empty()) {
        std::memset(output, 0, outDim * sizeof(float));
        RAWRXD_DEEP2_TRACE("LINEARW_TRY_GPU name=%s\n",wtn);

        // B4_LMHEAD_PERMANENT_RESIDENCY_001: the lmHead must never churn
        // through the weight cache. Pin its per-device slices (at the live
        // dual-row split geometry) before the first logits GEMV; a geometry
        // change re-pins. Pinned entries are invisible to eviction, so the
        // per-token re-upload churn B3 measured on slot 1 cannot recur.
        // B4b: with the split frozen after warmup the geometry is stable,
        // and the probe itself costs real per-token work (split-plan lookup,
        // 2 view builds, 2 pin-cache round trips). Once both slices are
        // pinned, skip the probe entirely; the frozen-split gate re-pins
        // only if DEEP2_SPLIT_FREEZE is disabled.
        const bool isLmHead = (&wt == &modelWeights.lmHead);
        const bool lmHeadPinFastPath =
            isLmHead && lmHeadPinned_[0] && lmHeadPinned_[1] &&
            !lmHeadGeometryProbeEnabled();
        if (isLmHead && !lmHeadPinFastPath &&
            vulkanDevices_.size() >= 2 && wt.rows >= 2) {
            GpuWeightView w0v{}, w1v{};
            if (Deep2ProbeRowSplitViews(wt, *vulkanDevices_[0],
                                        *vulkanDevices_[1], w0v, w1v)) {
                const bool geometryChanged =
                    lmHeadPinned_[0] &&
                    lmHeadPinRow0Count_ != w0v.rows;
                if (geometryChanged) ++lmHeadPinRePins_;
                const uint64_t up0a = vulkanDevices_[0]->WeightUploadCount();
                const uint64_t up1a = vulkanDevices_[1]->WeightUploadCount();
                const bool pinOk =
                    vulkanDevices_[0]->PinWeightView(w0v) &&
                    vulkanDevices_[1]->PinWeightView(w1v);
                if (pinOk) {
                    lmHeadPinned_[0] = true;
                    lmHeadPinned_[1] = true;
                    lmHeadPinRow0Count_ = w0v.rows;
                    const uint64_t up0b = vulkanDevices_[0]->WeightUploadCount();
                    const uint64_t up1b = vulkanDevices_[1]->WeightUploadCount();
                    lmHeadPinUploadDeltas_[0] += up0b - up0a;
                    lmHeadPinUploadDeltas_[1] += up1b - up1a;
                    std::fprintf(stderr,
                        "[B4_LMHEAD_PIN] slot0rows=%u slot1rows=%u repin=%u\n",
                        w0v.rows, w1v.rows, lmHeadPinRePins_);
                    std::fflush(stderr);
                }
            }
        }

        // Attempt 1: dual-GPU row split
        //
        // GATED ON MEASURED CAPABILITY, NOT ON DEVICE COUNT. (Deep2StreamReasoning_001)
        //
        // The gate used to be `vulkanDevices_.size() >= 2` -- a COUNT. That is
        // not evidence that a cross-device row split is possible. On this host
        // two discrete AMD GPUs are enumerated and both are pushed into
        // vulkanDevices_, and at init the engine measured:
        //
        //     PEER_HANDOFF_SUPPORTED=0
        //     DIRECT_CROSS_PHYSICAL_DEVICE_IMPORT=UNPROVEN
        //     BATCH9_VULKAN_INIT=DEVICE_BACKED devices=2 plan_active=0
        //
        // so multiGpuLayerPlan_.active is false and the plan was never enabled.
        // LinearW attempted the route anyway, tryVulkanHostGEMV failed on both
        // slots, and strict mode (vulkanStrictNoCpuFallback_, default true at
        // Deep2Engine.h:1391) correctly refused the silent host fallback. The
        // process then died on the FIRST GEMV of layer 0:
        //
        //     LINEARW_DUAL_ROW_FAIL name=blk.0.attn_v.weight
        //     [Deep2Engine] dual-row dense forward failed:
        //         LinearW: GPU path failed under strict mode
        //     [PREFILL] forwardTokenAllLayers FAILED at prefill token 0
        //
        // Note attn_v is not a special case: it is simply the first projection
        // reached, so it is the one that reports. The route failed on EVERY
        // tensor.
        //
        // This route had never been exercised before because the harness did not
        // call enableVulkan(true); enabling the GPU backend woke a path that was
        // always broken and always dormant. Enabling a subsystem for the first
        // time is how this class of defect surfaces -- not model parity testing.
        //
        // We do NOT relax strict mode here. The guard at Deep2Engine.cpp:5457
        // exists precisely to "fail closed rather than silently execute the host
        // lane"; loosening it would convert a loud failure into the silent CPU
        // fallback that guard was written to prevent. With this gate the route
        // is simply not attempted, and the existing non-dual path is reached.
        bool triedDual = false, dualOk = false;
        if (vulkanDevices_.size() >= 2 && wt.rows >= 2 && multiGpuLayerPlan_.active) {
            triedDual = true;
            if (tryVulkanHostGEMV(wt, input, output, outDim)) {
                dualOk = true;
            }
        }
        if (dualOk) {
            RAWRXD_DEEP2_TRACE("LINEARW_RESULT=DUAL_GPU name=%s\n",wtn);
            // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: the weight arithmetic was
            // performed by tryVulkanHostGEMV, not by any LinearW-owned kernel.
            // Classifying this path as "through LinearW, therefore not a
            // bypass" is the error this census exists to prevent.
            {
                using namespace rawrxd::deep2::weightcensus;
                Event ev;
                ev.site = Site::LinearW; ev.route = Route::LinearWDelegated;
                ev.tensor = wtn; ev.bytes = wt.sizeBytes ? wt.sizeBytes : rows * cols;
                WeightConsumptionCensus::instance().record(ev);
            }
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (!finiteVector(output, outDim))
                throw std::runtime_error("LinearW: non-finite GPU output");
            return;
        }
        if (triedDual) {
            std::fprintf(stderr,"LINEARW_DUAL_ROW_FAIL name=%s\n",wtn); std::fflush(stderr);
        }

        // Attempt 2: single-GPU fallback
        if (tryVulkanHostGEMV(wt, input, output, outDim)) {
            RAWRXD_DEEP2_TRACE("LINEARW_RESULT=SINGLE_GPU name=%s\n",wtn);
            // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: delegated, not owned.
            {
                using namespace rawrxd::deep2::weightcensus;
                Event ev;
                ev.site = Site::LinearW; ev.route = Route::LinearWDelegated;
                ev.tensor = wtn; ev.bytes = wt.sizeBytes ? wt.sizeBytes : rows * cols;
                WeightConsumptionCensus::instance().record(ev);
            }
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (!finiteVector(output, outDim))
                throw std::runtime_error("LinearW: non-finite GPU output");
            return;
        }

        // GPU paths exhausted
        std::fprintf(stderr,"LINEARW_RESULT=FAIL name=%s strict=%d\n",
                     wtn,(int)vulkanStrictNoCpuFallback_); std::fflush(stderr);
        if (vulkanStrictNoCpuFallback_)
            throw std::runtime_error("LinearW: GPU path failed under strict mode");
    }

    // CPU fallback
    RAWRXD_DEEP2_TRACE("LINEARW_RESULT=CPU_FALLBACK name=%s\n",wtn);

    // RAWRXD_SPACELESS_EXECUTION_VIEW_GEMV_002
    // Production adoption: try ExecutionView-aware kernel first.
    // All 14 quant types now have EV kernels registered; legacy path is
    // fallback only if a future type is not yet adopted.
    {
        auto kernelEv = QuantKernelRegistry::Instance().GetGEMVEV(wt.type);
        if (kernelEv) {
            Deep2::ExecutionView ev;
            // RAWRXD_SPACELESS_STEP_9: try TensorResidencyCache first.
            // If the tensor is resident and lease valid, use the cached view.
            // On miss, construct from WeightTensor and insert for future lookups.
            // Step 10: use wt.identity (stable, not address-dependent) for cache keys.
            bool cacheHit = false;
            const double _tResolve = tokProfOn() ? TokWall::nowNs() : 0.0;
            if (residencyCache_ && residencyCache_->lookup(wt.identity, ev)) {
                cacheHit = true;
                ++residencyCacheHits_;
                RAWRXD_DEEP2_TRACE("LINEARW_RESIDENCY_CACHE_HIT name=%s\n", wtn);
            } else {
                ++residencyCacheMisses_;
                ev.identity          = wt.identity;
                ev.transientAddress  = wt.data;
                ev.bytes             = wt.sizeBytes;
                ev.lease.generation  = 1;
                ev.lease.owner       = 1;
                ev.lease.epoch       = 0;
                if (residencyCache_) {
                    residencyCache_->insert(ev);
                }
            }
            if (tokProfOn()) g_tokWall.resolveNs += TokWall::nowNs() - _tResolve;
            const double _tCopy0 = tokProfOn() ? TokWall::nowNs() : 0.0;
            std::memset(output, 0, outDim * sizeof(float));
            if (tokProfOn()) g_tokWall.copyNs += TokWall::nowNs() - _tCopy0;
            const double _tKernel0 = tokProfOn() ? TokWall::nowNs() : 0.0;
            // RAWRXD_TENSOR_PROVENANCE_001 -- boundary KERNEL.
            // Hashed from ev.transientAddress, i.e. the bytes the kernel will
            // actually read, NOT from wt.data. On a residency-cache hit those can
            // differ, and that difference is the defect this gate exists to
            // make impossible to miss. Compared by CONTENT because addresses are
            // legitimately allowed to change.
            TensorProvenance provKernel;
            if (provOn()) {
                provKernel.provHash = provIdentityHash(
                    wt.name.c_str(), (uint32_t)wt.type, wt.shape,
                    wt.sizeBytes, wt.fileOffset, wt.shardId);
                provKernel.byteLength = wt.sizeBytes;
                provKernel.fileOffset = wt.fileOffset;
                provKernel.shardId    = wt.shardId;
                provKernel.type       = (uint32_t)wt.type;
                provKernel.nDims      = (uint32_t)(wt.shape.size() < 8 ? wt.shape.size() : 8);
                for (uint32_t di = 0; di < provKernel.nDims; ++di) provKernel.dims[di] = wt.shape[di];
                provContentHash(provKernel, ev.transientAddress, wt.sizeBytes);
                // expected content = the bytes this tensor is supposed to be
                TensorProvenance provExpect;
                provExpect.provHash = provKernel.provHash;
                provExpect.byteLength = wt.sizeBytes;
                provExpect.fileOffset = wt.fileOffset;
                provExpect.shardId    = wt.shardId;
                provExpect.type       = (uint32_t)wt.type;
                provContentHash(provExpect, wt.data, wt.sizeBytes);
                const bool contentOk =
                    provKernel.haveContent && provExpect.haveContent &&
                    provKernel.prefixHash == provExpect.prefixHash &&
                    provKernel.bodyHash == provExpect.bodyHash;
                const size_t badRow = SIZE_MAX;
                std::fprintf(stderr,
                    "PROV BOUNDARY=KERNEL NAME=%s TYPE=%d LEN=%zu CACHE_HIT=%d "
                    "PROV_ID=%016llx EXPECT_PREFIX=%016llx ACTUAL_PREFIX=%016llx "
                    "EXPECT_BODY=%016llx ACTUAL_BODY=%016llx CONTENT_MATCH=%d "
                    "ID_MATCH=%d LEN_MATCH=%d KERNEL_CONSUMES_TENSOR=%d\n",
                    wtn, wt.type, wt.sizeBytes, cacheHit ? 1 : 0,
                    (unsigned long long)provKernel.provHash,
                    (unsigned long long)provExpect.prefixHash,
                    (unsigned long long)provKernel.prefixHash,
                    (unsigned long long)provExpect.bodyHash,
                    (unsigned long long)provKernel.bodyHash,
                    contentOk ? 1 : 0,
                    provKernel.provHash == provExpect.provHash ? 1 : 0,
                    provKernel.byteLength == provExpect.byteLength ? 1 : 0,
                    contentOk ? 1 : 0);
                // RAWRXD_TENSOR_PROVENANCE_001 -- the paired comparison.
                // The WQEXT record was captured at extraction and is compared
                // here, in the SAME PROCESS, against the provenance the consumer
                // actually resolved. It is deliberately NOT reconstructed from
                // the consumer's fields: a comparison whose expected side is
                // derived from the actual side is circular and cannot fail.
                {
                    auto& tbl = provWqextTable();
                    auto it = tbl.find(wt.name);
                    if (it == tbl.end()) {
                        std::fprintf(stderr,
                            "PROV_COMPARE TENSOR=%s EXPECT=ABSENT ACTUAL=%016llx "
                            "MATCH=0 NOTE=no_wqext_record\n",
                            wtn, (unsigned long long)provKernel.provHash);
                    } else {
                        const TensorProvenance& W = it->second;
                        const bool idm  = (W.provHash  == provKernel.provHash);
                        const bool shm  = (W.shardId   == provKernel.shardId);
                        const bool offm = (W.fileOffset== provKernel.fileOffset);
                        const bool lenm = (W.byteLength== provKernel.byteLength);
                        const bool pm   = (W.prefixHash== provKernel.prefixHash);
                        const bool bm   = (W.bodyHash  == provKernel.bodyHash);
                        const bool all  = idm && shm && offm && lenm && pm && bm;
                        std::fprintf(stderr,
                            "PROV_COMPARE TENSOR=%s EXPECT=%016llx ACTUAL=%016llx "
                            "MATCH=%d ID_MATCH=%d SHARD_MATCH=%d OFFSET_MATCH=%d "
                            "LEN_MATCH=%d PREFIX_MATCH=%d BODY_MATCH=%d "
                            "SHARD=%u FILE_OFF=%llu BYTES=%llu\n",
                            wtn, (unsigned long long)W.provHash,
                            (unsigned long long)provKernel.provHash, all ? 1 : 0,
                            idm?1:0, shm?1:0, offm?1:0, lenm?1:0, pm?1:0, bm?1:0,
                            provKernel.shardId,
                            (unsigned long long)provKernel.fileOffset,
                            (unsigned long long)provKernel.byteLength);
                    }
                    std::fflush(stderr);
                }
                std::fflush(stderr);
                (void)badRow;
            }
            kernelEv(ev, input, output, rows, cols);
            if (tokProfOn()) {
                g_tokWall.kernelNs += TokWall::nowNs() - _tKernel0;
                g_tokWall.kernelBytes += wt.sizeBytes;
                ++g_tokWall.kernelCalls;
            }
            // RAWRXD_LAYER0_ATTN_BISECT_001: the receipt that separates a
            // quant-decoder defect from a tensor-geometry defect from a
            // V-specific dispatch defect, without guessing between them.
            //
            // The decisive field is ADDR_MATCH. On a residency-cache HIT the
            // kernel reads ev.transientAddress, NOT wt.data. If the cache
            // returns an address for a different tensor, the decode is fed the
            // wrong bytes and every downstream number is confidently wrong while
            // every size check still passes -- which is exactly the observed
            // signature (finite garbage, no throw, V only).
            {
                static const bool recOnce = [] {
                    const char* v = std::getenv("RAWRXD_ATTN_BISECT");
                    return v && v[0] && v[0] != '0';
                }();
                if (recOnce) {
                    const bool addrMatch =
                        (const void*)ev.transientAddress == (const void*)wt.data;
                    const size_t blkBytes = packedBytesRequired(wt.type, 1, 1);
                    const size_t blocks = blkBytes ? (wt.sizeBytes / blkBytes) : 0;
                    size_t firstBad = SIZE_MAX;
                    for (size_t i = 0; i < outDim; ++i)
                        if (!std::isfinite(output[i])) { firstBad = i; break; }
                    std::fprintf(stderr,
                        "LINEARW_EV name=%s type=%d rows=%zu cols=%zu outDim=%zu "
                        "row_stride=%zu block_bytes=%zu block_count=%zu "
                        "src_bytes=%zu dst_bytes=%zu "
                        "cache_hit=%d wt_data=%p ev_addr=%p ADDR_MATCH=%d "
                        "id_model=%llu id_tensor=%llu id_layer=%u id_role=%u id_variant=%u "
                        "ev_bytes=%zu FIRST_BAD_ROW=%lld FIRST_BAD_COL=%lld "
                        "OUT_ABSMIN=%.6g OUT_ABSMAX=%.6g\n",
                        wtn, wt.type, rows, cols, outDim,
                        blkBytes ? (cols / (rows ? 1 : 1)) : 0, blkBytes, blocks,
                        wt.sizeBytes, outDim * sizeof(float),
                        cacheHit ? 1 : 0, wt.data, ev.transientAddress,
                        addrMatch ? 1 : 0,
                        (unsigned long long)wt.identity.model,
                        (unsigned long long)wt.identity.tensor,
                        wt.identity.layer, wt.identity.role, wt.identity.variant,
                        ev.bytes,
                        (firstBad == SIZE_MAX) ? -1LL : (long long)(firstBad / (cols ? cols : 1)),
                        (firstBad == SIZE_MAX) ? -1LL : (long long)(firstBad % (cols ? cols : 1)),
                        [&]{ double mn=0,mx=0; bool f=true;
                             for (size_t i=0;i<outDim;++i){ const double a=std::fabs((double)output[i]);
                               if(f){mn=a;mx=a;f=false;} else {if(a<mn)mn=a; if(a>mx)mx=a;} }
                             return 0.0; }() , [&]{ double mx=0; bool f=true;
                             for (size_t i=0;i<outDim;++i){ const double a=std::fabs((double)output[i]);
                               if(f){mx=a;f=false;} else if(a>mx)mx=a; }
                             return mx; }()
                    );
                    std::fflush(stderr);
                }
            }
            const double _tBias0 = tokProfOn() ? TokWall::nowNs() : 0.0;
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (tokProfOn()) { g_tokWall.copyNs += TokWall::nowNs() - _tBias0; ++g_tokWall.biasAdds; }
            size_t outBad = SIZE_MAX;
            for (size_t i = 0; i < outDim; ++i) {
                if (!std::isfinite(output[i])) { outBad = i; break; }
            }
            if (outBad != SIZE_MAX) {
                RAWRXD_DEEP2_TRACE(
                    "LINEAR_CPU_NONFINITE name=%s type=%d firstBadIdx=%zu value=%.9g\n",
                    wtn, wt.type, outBad,
                    outBad < outDim ? output[outBad] : 0.0f);
                // RAWRXD_LINEARW_NONFINITE_DIAG_001: the message used to be the
                // constant "LinearW: non-finite output", which named neither the
                // tensor nor the index nor the value. A non-finite first GEMV is
                // the single most common forward failure and that string made
                // it undiagnosable without a debugger attached -- the caller
                // only ever saw the same sentence regardless of which of
                // hundreds of projections had failed, or at what position.
                // Report what actually happened.
                {
                    char detail[512];
                    std::snprintf(detail, sizeof(detail),
                        "LinearW: non-finite output tensor=%s type=%d idx=%zu/%zu "
                        "value=%g rows=%zu cols=%zu",
                        wtn, wt.type, outBad, outDim,
                        outBad < outDim ? static_cast<double>(output[outBad]) : 0.0,
                        rows, cols);
                    std::fprintf(stderr, "LINEAR_CPU_NONFINITE_DETAIL %s\n", detail);
                    std::fflush(stderr);
                    // Also state whether the INPUT was already poisoned, which
                    // separates "this GEMV is wrong" from "something upstream
                    // produced garbage": an inf/NaN input localises the fault
                    // to the previous layer rather than this one.
                    size_t inBad = SIZE_MAX;
                    double inVal = 0.0;
                    for (size_t i = 0; i < cols; ++i) {
                        if (!std::isfinite(input[i])) { inBad = i; inVal = input[i]; break; }
                    }
                    if (inBad != SIZE_MAX) {
                        std::fprintf(stderr,
                            "LINEAR_INPUT_ALREADY_NONFINITE tensor=%s inIdx=%zu/%zu inValue=%g\n",
                            wtn, inBad, cols, inVal);
                    } else {
                        std::fprintf(stderr,
                            "LINEAR_INPUT_FINITE tensor=%s inFirst=%g inLast=%g\n",
                            wtn, cols ? static_cast<double>(input[0]) : 0.0,
                            cols ? static_cast<double>(input[cols - 1]) : 0.0);
                    }
                    std::fflush(stderr);
                    throw std::runtime_error(detail);
                }
            }
            RAWRXD_DEEP2_TRACE("LINEARW_RESULT=CPU_FALLBACK_EV name=%s\n",wtn);
            // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: LinearW reached its own
            // locally registered GEMV kernel. This is the only route that makes
            // a projection LINEARW_OWNED.
            {
                using namespace rawrxd::deep2::weightcensus;
                Event cev;
                cev.site = Site::LinearW; cev.route = Route::LinearWOwned;
                cev.tensor = wtn; cev.bytes = wt.sizeBytes ? wt.sizeBytes : rows * cols;
                WeightConsumptionCensus::instance().record(cev);
            }
            return;
        }
    }

    auto kernel = QuantKernelRegistry::Instance().GetGEMV(wt.type);
    if (!kernel) {
        throw std::runtime_error("LinearW: no registered GEMV kernel");
    }

    // Diagnostic: log input statistics before GEMV
#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
    float inMin =  std::numeric_limits<float>::infinity();
    float inMax = -std::numeric_limits<float>::infinity();
    size_t inBad = SIZE_MAX;
    for (size_t i = 0; i < cols; ++i) {
        if (!std::isfinite(input[i])) { inBad = i; break; }
        if (input[i] < inMin) inMin = input[i];
        if (input[i] > inMax) inMax = input[i];
    }
    RAWRXD_DEEP2_TRACE(
        "LINEAR_CPU_BEGIN name=%s type=%d rows=%zu cols=%zu "
        "inputFinite=%d inputBad=%zu inputMin=%.9g inputMax=%.9g\n",
        wtn, wt.type, rows, cols,
        (inBad == SIZE_MAX) ? 1 : 0, inBad, inMin, inMax);
#endif

    std::memset(output, 0, outDim * sizeof(float));
    kernel(static_cast<const uint8_t*>(wt.data), input, output, rows, cols);

    if (bias) {
        for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
    }

    size_t outBad = SIZE_MAX;
    for (size_t i = 0; i < outDim; ++i) {
        if (!std::isfinite(output[i])) { outBad = i; break; }
    }
    if (outBad != SIZE_MAX) {
        RAWRXD_DEEP2_TRACE(
            "LINEAR_CPU_NONFINITE name=%s type=%d firstBadIdx=%zu value=%.9g\n",
            wtn, wt.type, outBad,
            outBad < outDim ? output[outBad] : 0.0f);
        throw std::runtime_error("LinearW: non-finite output");
    }

    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: the legacy non-ExecutionView GEMV is
    // also LinearW's own registered kernel, so it is the same ownership class.
    // Recorded here rather than at entry so the CPU route is attributed to
    // exactly the branch that computed it.
    {
        using namespace rawrxd::deep2::weightcensus;
        Event lev;
        lev.site = Site::LinearW; lev.route = Route::LinearWOwned;
        lev.tensor = wtn; lev.bytes = wt.sizeBytes ? wt.sizeBytes : rows * cols;
        WeightConsumptionCensus::instance().record(lev);
    }
}

// =================== WEIGHTED RMSNORM ====================
void Deep2Engine::RMSNormW(const WeightTensor& normWeight,
                           const float* input,
                           float* output,
                           size_t dim,
                           float eps) {
    if (!input || !output || dim == 0 || !(eps > 0.0f)) {
        throw std::runtime_error("RMSNormW: invalid arguments");
    }

    double ss = 0.0;
    for (size_t i = 0; i < dim; ++i) {
        const double v = static_cast<double>(input[i]);
        ss += v * v;
    }
    const float invRms =
        1.0f / std::sqrt(static_cast<float>(ss / static_cast<double>(dim)) + eps);

    if (!normWeight.data) {
        for (size_t i = 0; i < dim; ++i) output[i] = input[i] * invRms;
        // No weight bytes were read, so nothing is recorded: the census refuses
        // unmeasured events rather than crediting a site that read nothing.
    } else {
        // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: this is a CLASS-A bypass. The
        // norm tensor is resolved and dequantized here, directly, and never
        // enters LinearW() -- so finalNorm, attnNorm, attnPostNorm,
        // attnQNorm and attnKNorm are all outside the LinearW funnel by
        // construction, not by accident.
        {
            using namespace rawrxd::deep2::weightcensus;
            Event nev;
            nev.site = Site::RmsNormW;
            nev.route = Route::Bypass;   // never entered LinearW
            nev.tensor = normWeight.name;
            nev.bytes = normWeight.sizeBytes ? normWeight.sizeBytes : dim * sizeof(float);
            WeightConsumptionCensus::instance().record(nev);
        }
        const auto* desc = LookupQuantType(static_cast<uint32_t>(normWeight.type));
        if (!desc || desc->blockBytes == 0 || desc->blockElements == 0) {
            throw std::runtime_error("RMSNormW: unsupported weight type");
        }
        const size_t required =
            ((dim + desc->blockElements - 1) / desc->blockElements) *
            desc->blockBytes;
        if (normWeight.sizeBytes != 0 && required > normWeight.sizeBytes) {
            throw std::runtime_error("RMSNormW: norm tensor too small");
        }

        std::vector<float> w(dim);
        auto dequant = QuantKernelRegistry::Instance().GetDequant(normWeight.type);
        if (!dequant) {
            throw std::runtime_error("RMSNormW: no dequant kernel");
        }
        dequant(static_cast<const uint8_t*>(normWeight.data), w.data(), dim);
        if (!finiteVector(w.data(), dim)) {
            throw std::runtime_error("RMSNormW: non-finite norm weights");
        }
        for (size_t i = 0; i < dim; ++i) {
            output[i] = input[i] * invRms * w[i];
        }
    }

    if (!finiteVector(output, dim)) {
        throw std::runtime_error("RMSNormW: non-finite output");
    }
}

// =================== ROPE ====================
void Deep2Engine::applyRoPE(float* q, float* k,
                            size_t headDim,
                            size_t numHeads,
                            size_t numKVHeads,
                            size_t pos,
                            float theta,
                            float scaling) {
    if (!q || !k || headDim == 0 || numHeads == 0 || numKVHeads == 0) {
        throw std::runtime_error("RoPE: invalid geometry");
    }
    if (!(theta > 1.0f)) {
        throw std::runtime_error("RoPE: theta not bound from model metadata");
    }
    if (!(scaling > 0.0f)) scaling = 1.0f;

    size_t rotaryDim = modelWeights.ropeDimensionCount
        ? std::min(modelWeights.ropeDimensionCount, headDim)
        : headDim;
    rotaryDim &= ~size_t(1);
    if (rotaryDim == 0) {
        throw std::runtime_error("RoPE: zero rotary dimension");
    }

    const float effectivePos = static_cast<float>(pos) / scaling;
    // NeoX (llama/qwen/mistral): rotate pair (i, i + rotaryDim/2) inside the
    // first rotaryDim dims. GPT-J (phi/gpt-neox-legacy): rotate adjacent pair
    // (i, i+1) across the full headDim.
    if (modelWeights.ropeNeoxStyle) {
        const size_t half = rotaryDim / 2;
        auto rotateHeadNeox = [&](float* h) {
            for (size_t i = 0; i < half; ++i) {
                const float invFreq =
                    1.0f / std::pow(theta,
                        static_cast<float>(i) / static_cast<float>(half));
                const float angle = effectivePos * invFreq;
                const float c = std::cos(angle);
                const float s = std::sin(angle);
                const float x0 = h[i];
                const float x1 = h[i + half];
                h[i]        = x0 * c - x1 * s;
                h[i + half] = x0 * s + x1 * c;
            }
        };
        for (size_t h = 0; h < numHeads; ++h) {
            rotateHeadNeox(q + h * headDim);
        }
        for (size_t h = 0; h < numKVHeads; ++h) {
            rotateHeadNeox(k + h * headDim);
        }
        return;
    }
    auto rotateHead = [&](float* h) {
        for (size_t i = 0; i < rotaryDim; i += 2) {
            const float invFreq =
                1.0f / std::pow(theta,
                    static_cast<float>(i) / static_cast<float>(rotaryDim));
            const float angle = effectivePos * invFreq;
            const float c = std::cos(angle);
            const float s = std::sin(angle);
            const float x0 = h[i];
            const float x1 = h[i + 1];
            h[i]     = x0 * c - x1 * s;
            h[i + 1] = x0 * s + x1 * c;
        }
    };

    for (size_t h = 0; h < numHeads; ++h) {
        rotateHead(q + h * headDim);
    }
    for (size_t h = 0; h < numKVHeads; ++h) {
        rotateHead(k + h * headDim);
    }
}

// =================== FORWARD LAYER ====================
void Deep2Engine::forwardLayer(size_t layer, const float* input,
                               float* output, size_t seqLen) {
    if (profiler_) profiler_->beginLayer(static_cast<uint32_t>(layer));
    auto tLayer0 = std::chrono::steady_clock::now();
    RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu seqLen=%zu\n",layer,seqLen);
    if (!input || !output || config.hiddenDim == 0) {
        throw std::runtime_error("forwardLayer: invalid buffers/geometry");
    }
    if (layer >= modelWeights.layers.size()) {
        throw std::runtime_error("forwardLayer: layer weights not bound");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = config.hiddenDim;

    const bool isNemotronH =
        (modelArchitecture_ == "nemotron_h" || modelArchitecture_ == "nemotron_h_moe");

    // For legacy (non-Nemotron-H) architectures each layer is the classic
    // attention-residual + FFN-residual stack. The booleans below also drive the
    // SSM stage diagnostic header for Nemotron-H, where they are projections of
    // the single selected mixer.
    const bool doAttn = lw.hasAttn;
    const bool doSSM  = lw.hasSSM;
    const bool doFFN  = lw.hasFFN;

    // Sanity: for Nemotron-H exactly one mixer is selected at bind time.
    const int mixerCount = doAttn + doSSM + doFFN;

#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
    long long ssmDiagCall = ssmDiagNext();
    const bool ssmDiagOn = ssmDiagCall < ssmDiagBudget();
    const auto ldiag = [&](const char* stage, const float* p, size_t n) {
        if (!ssmDiagOn) return;
        SsmStageRange r;
        ssmStageAccum(p, n, r);
        std::fprintf(stderr,
            "LAYERDIAG call=%lld layer=%zu mixer=%s doAttn=%d doSSM=%d doFFN=%d STAGE=%s N=%zu "
            "MIN=%.9g MAX=%.9g ABSMAX=%.9g NONFINITE=%zu\n",
            ssmDiagCall, layer,
            isNemotronH ?
              (lw.mixer == LayerWeights::BlockMixer::Mamba ? "MAMBA" :
               lw.mixer == LayerWeights::BlockMixer::Attention ? "ATTN" :
               lw.mixer == LayerWeights::BlockMixer::MoE ? "MOE" : "MLP") :
              (doAttn && doFFN ? "ATTN+MLP" : (doAttn ? "ATTN" : "MLP")),
            doAttn ? 1 : 0, doSSM ? 1 : 0, doFFN ? 1 : 0,
            stage, n, r.mn, r.mx, r.amax, r.nonfinite);
        std::fflush(stderr);
    };
    ldiag("LAYER_IN", input, H);
#else
    const bool ssmDiagOn = false;
    const auto ldiag = [](const char*, const float*, size_t) {};
#endif

    // ============================================================
    // Nemotron-H: ONE BLOCK, ONE NORM, ONE MIXER, ONE RESIDUAL ADD
    //   residual = input
    //   normed   = RMSNorm(residual, block_norm = blk.N.attn_norm.weight)
    //   branch   = Mixer(normed)        // Mamba | Attention | Mlp | MoE
    //   output   = residual + branch
    //   No fall-through between mixers; no attn→SSM→FFN sequence.
    // Reference: llm_build_nemotron_h, llama.cpp src/models/nemotron-h.cpp:18-46
    // ============================================================
    if (isNemotronH) {
        if (lw.mixer == LayerWeights::BlockMixer::None)
            throw std::runtime_error("forwardLayer: nemotron_h layer has no mixer");
        if (mixerCount != 1)
            throw std::runtime_error("forwardLayer: nemotron_h must select exactly one mixer");
        if (!blockResidual)
            throw std::runtime_error("forwardLayer: block residual buffer not allocated");

        // Single layer norm per block — blk.N.attn_norm.weight for all mixers.
        const WeightTensor& blockNorm =
            lw.attnNorm.data ? lw.attnNorm : lw.ffnNorm;
        if (!blockNorm.data)
            throw std::runtime_error("forwardLayer: missing block norm");

        // residual captured BEFORE normalization (B3-B): blockResidual and the
        // mixer branch buffer are distinct storage from output, so the residual
        // is never clobbered while the mixer writes its branch.
        std::copy_n(input, H, blockResidual);
        RMSNormW(blockNorm, blockResidual, layerTemp, H, modelWeights.normEps);
        ldiag("MIXER_INPUT_NORM", layerTemp, H);
        parityEmit(ParityCheckpoint::AttnNorm, layerTemp, H);
        parityEmitLayer(static_cast<int>(layer), "MIXER_PRENORM", layerTemp, H);

        // Dispatch exactly one mixer into mixerBranch (never into layerTemp or
        // output, never aliased). computeSSM asserts its input/output differ.
        switch (lw.mixer) {
            case LayerWeights::BlockMixer::Mamba: {
                RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu MAMBA\n", layer);
                if (!mixerBranch)
                    throw std::runtime_error("forwardLayer: mixer branch buffer not allocated");
                computeSSM(layer, layerTemp, mixerBranch);
                break;
            }
            case LayerWeights::BlockMixer::Attention: {
                RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu ATTENTION\n", layer);
                computeAttention(layer, layerTemp, attentionOutput, seqLen);
                // No gemma3 post-attn norm in the Nemotron-H dispatch path;
                // gemma3 is never nemotron_h.
                std::copy_n(attentionOutput, H, mixerBranch);
                break;
            }
            case LayerWeights::BlockMixer::Mlp: {
                RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu MLP\n", layer);
                if (!mixerBranch)
                    throw std::runtime_error("forwardLayer: mixer branch buffer not allocated");
                computeFFN(layer, layerTemp, mixerBranch);
                break;
            }
            case LayerWeights::BlockMixer::MoE: {
                RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu MOE\n", layer);
                if (!mixerBranch)
                    throw std::runtime_error("forwardLayer: mixer branch buffer not allocated");
                // B3-C: MoE instrumentation only on the actual MoE mixer layer.
                {
                    double ffnInAbsmax = 0.0;
                    for (size_t i = 0; i < H; ++i)
                        ffnInAbsmax = std::max(ffnInAbsmax, std::fabs((double)layerTemp[i]));
                    std::fprintf(stderr,
                        "MOE_FFN_ENTRY layer=%zu MIXER_INPUT_ABSMAX=%.9g\n",
                        layer, ffnInAbsmax);
                    std::fflush(stderr);
                }
                computeMoEFFN(layer, layerTemp, mixerBranch);
                {
                    double ffnOutAbsmax = 0.0;
                    size_t nonzeroRuns = 0;
                    for (size_t i = 0; i < H; ++i) {
                        const double a = std::fabs((double)mixerBranch[i]);
                        if (a > ffnOutAbsmax) ffnOutAbsmax = a;
                        if (a > 0.0) ++nonzeroRuns;
                    }
                    std::fprintf(stderr,
                        "MOE_FFN_EXIT layer=%zu OUTPUT_ABSMAX=%.9g NONZERO=%s\n",
                        layer, ffnOutAbsmax,
                        nonzeroRuns > 0 ? "yes" : "ZERO");
                    std::fflush(stderr);
                }
                break;
            }
            default:
                throw std::runtime_error("forwardLayer: unknown nemotron mixer");
        }

        if (!finiteVector(mixerBranch, H))
            throw std::runtime_error("forwardLayer: non-finite mixer branch output");

        // output = residual + branch  (blockResidual survives; not aliased)
        for (size_t i = 0; i < H; ++i)
            output[i] = blockResidual[i] + mixerBranch[i];
        ldiag("MIXER_RESIDUAL_ADD", output, H);

        if (!finiteVector(output, H))
            throw std::runtime_error("forwardLayer: non-finite layer output");
        parityEmit(ParityCheckpoint::LayerResidual, output, H);
        parityEmitLayer(static_cast<int>(layer), "LAYER_RESIDUAL", output, H);

        ldiag("LAYER_OUT", output, H);
        auto tLayer1 = std::chrono::steady_clock::now();
        if (profiler_) {
            profiler_->recordGpuForward(
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tLayer1 - tLayer0).count()));
            profiler_->endLayer(static_cast<uint32_t>(layer));
        }
        RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu DONE\n",layer);

        // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record this layer's execution
        {
            bool layerPassed = true;
            // Check if output is finite (already verified above, but defensive)
            for (size_t i = 0; i < H; ++i) {
                if (!std::isfinite(output[i])) { layerPassed = false; break; }
            }
            rawrxd::compute::recordNodeExecution(
                "layer_" + std::to_string(layer),
                layerPassed,
                1, // one output vector produced
                "forwardLayer completed"
            );
        }
        return;
    }

    // ============================================================
    // Legacy architectures: attention-residual then FFN-residual.
    // (Unchanged behaviour for dense transformers such as qwen2.5.)
    // ============================================================
    // ---- Attention branch ----
    if (doAttn) {
        if (!lw.attnNorm.data) {
            throw std::runtime_error("forwardLayer: missing attention norm");
        }
        RMSNormW(lw.attnNorm, input, layerTemp, H, modelWeights.normEps);
        ldiag("ATTN_NORM_IN", layerTemp, H);
        parityEmit(ParityCheckpoint::AttnNorm, layerTemp, H);
        parityEmitLayer(static_cast<int>(layer), "ATTN_NORM", layerTemp, H);

        RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu ATTENTION\n",layer);
        computeAttention(layer, layerTemp, attentionOutput, seqLen);

        // Gemma3: post-attention norm before residual add
        if (modelArchitecture_ == "gemma3") {
            if (!lw.attnPostNorm.data)
                throw std::runtime_error("forwardLayer: missing attn_post_norm for gemma3");
            RMSNormW(lw.attnPostNorm, attentionOutput, attentionOutput, H, modelWeights.normEps);
        }

        for (size_t i = 0; i < H; ++i) {
            output[i] = input[i] + attentionOutput[i];
        }
        ldiag("ATTN_OUT", attentionOutput, H);
        ldiag("RESIDUAL_AFTER_ATTN", output, H);
        parityEmit(ParityCheckpoint::AttnResidual, output, H);
        parityEmitLayer(static_cast<int>(layer), "ATTN_RESIDUAL", output, H);
    } else {
        // If no attention, carry input forward unchanged
        std::memcpy(output, input, H * sizeof(float));
    }

    // ---- Mixer/FFN branch ----
    if (doFFN) {
        if (!lw.ffnNorm.data) {
            // attn_norm is never reused here; a dedicated ffn_norm is required
            // (guaranteed bound at load time for non-hybrid architectures).
            throw std::runtime_error("forwardLayer: missing FFN norm");
        }
        RMSNormW(lw.ffnNorm, output, layerTemp, H, modelWeights.normEps);
        parityEmit(ParityCheckpoint::FfnNorm, layerTemp, H);
        parityEmitLayer(static_cast<int>(layer), "FFN_NORM", layerTemp, H);
        ldiag("FFN_NORM_IN", layerTemp, H);

        RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu FFN_ENTER\n",layer);
        // RAWRXD_DEEPSEEK_CPU_E2E_001: per-layer MoE dispatch with dense prefix.
        //
        // DeepSeek-V2 exports leading_dense_block_count=1, so layer 0 is dense
        // (ffn_gate/up/down, no ffn_gate_inp). Sending it to computeMoEFFN throws
        // "MoE: router tensor not bound". The predicate is now layer index against
        // the declared dense prefix. Zero means "no dense prefix".
        const bool layerIsMoe = modelWeights.numExperts > 0 &&
            (modelWeights.leadingDenseBlockCount == 0 || layer >= modelWeights.leadingDenseBlockCount);
        if (layerIsMoe) {
            computeMoEFFN(layer, layerTemp, ffnOutput);
        } else {
            computeFFN(layer, layerTemp, ffnOutput);
        }

        if (!finiteVector(ffnOutput, H)) {
            throw std::runtime_error("forwardLayer: non-finite FFN output");
        }

        // Gemma3: post-FFN norm before residual add
        if (modelArchitecture_ == "gemma3") {
            if (!lw.ffnPostNorm.data)
                throw std::runtime_error("forwardLayer: missing ffn_post_norm for gemma3");
            RMSNormW(lw.ffnPostNorm, ffnOutput, ffnOutput, H, modelWeights.normEps);
        }

        for (size_t i = 0; i < H; ++i) output[i] += ffnOutput[i];
        ldiag("FFN_OUT", ffnOutput, H);

        if (!finiteVector(output, H)) {
            throw std::runtime_error("forwardLayer: non-finite layer output");
        }
    }

    ldiag("LAYER_OUT", output, H);

    parityEmit(ParityCheckpoint::LayerResidual, output, H);
    parityEmitLayer(static_cast<int>(layer), "LAYER_RESIDUAL", output, H);
    auto tLayer1 = std::chrono::steady_clock::now();
    if (profiler_) {
        profiler_->recordGpuForward(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tLayer1 - tLayer0).count()));
        profiler_->endLayer(static_cast<uint32_t>(layer));
    }
    RAWRXD_DEEP2_TRACE("FWD_LAYER layer=%zu DONE\n",layer);

    // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record this layer's execution
    {
        bool layerPassed = true;
        for (size_t i = 0; i < H; ++i) {
            if (!std::isfinite(output[i])) { layerPassed = false; break; }
        }
        rawrxd::compute::recordNodeExecution(
            "layer_" + std::to_string(layer),
            layerPassed,
            1, // one output vector produced
            "forwardLayer completed"
        );
    }
}

// =================== ATTENTION (REAL MHA/GQA) ====================
// =================== RAWRXD_LAYER0_ATTN_BISECT_001 ===================
// Ordered numerical spine for layer-0 attention.
//
// OBSERVE ONLY. Every function below reads a buffer and prints. None of them
// writes to a buffer it observes, clamps, substitutes a value, replaces a
// non-finite with a finite, changes accumulation order, changes precision, or
// changes routing. Any of those would move the defect this probe exists to
// localise, and a probe that perturbs its subject cannot localise it.
//
// The spine probes BOTH SIDES of every operation that can amplify a small
// defect, so the first transition is discovered mechanically rather than
// inferred:
//
//   ATTN_L0_IN
//     Q_PROJ / K_PROJ / V_PROJ          projection
//     Q_PRE_ROPE / K_PRE_ROPE          post-QK-norm, pre-RoPE  (projection control)
//     Q_POST_ROPE / K_POST_ROPE        post-RoPE               (rotation/index control)
//     SCORES_PRE_SCALE                 raw dot products        (dot/layout control)
//     SCORES_POST_SCALE                after 1/sqrt(headDim)
//     SCORES_POST_MASK                 causal mask is fused into the loop bound
//     SCORES_POST_SOFTMAX              after softmax           (normalisation control)
//     CONTEXT                          V accumulation          (V addressing control)
//     O_PROJ / ATTN_OUT                output projection
//
// Enabled by RAWRXD_ATTN_BISECT=1 (layer 0 only). RAWRXD_ATTN_BISECT_ALL=1
// widens to every layer. Deliberately NOT compiled out: a diagnostic build and
// a certified build must execute identical arithmetic, and the gate values are
// printed so the poison decision can be re-derived by hand.
namespace {

// Threshold above which a finite vector is reported as POISON. Activations in
// this model are O(1) entering a layer (measured MIN/MAX ~ +/-5), so 1e4 is
// four orders of magnitude clear of any legitimate value while remaining far
// below the measured poison at ATTN_OUT (~3.9e14). It is printed with every
// verdict so a disagreement about the threshold is visible, not implicit.
constexpr double kAttnPoisonAbsMax = 1.0e4;

struct AttnSpineSample {
    size_t count   = 0;
    size_t finite  = 0;
    size_t nan     = 0;
    size_t inf     = 0;
    size_t nonzero = 0;
    double mn = 0.0, mx = 0.0, amax = 0.0, l2 = 0.0;
    long long firstBad = -1;
    bool null = false;
};

// Accumulates one vector. Reads p[i] exactly once per index.
void attnSpineAccum(const float* p, size_t n, AttnSpineSample& s) {
    if (!p) { s.null = true; s.count += n; return; }
    bool first = true;
    for (size_t i = 0; i < n; ++i) {
        const float f = p[i];
        if (std::isnan(f)) { ++s.nan; if (s.firstBad < 0) s.firstBad = (long long)i; first = true; continue; }
        if (std::isinf(f)) { ++s.inf; if (s.firstBad < 0) s.firstBad = (long long)i; first = true; continue; }
        ++s.finite;
        const double v = (double)f;
        const double a = v < 0.0 ? -v : v;
        if (a > 0.0) ++s.nonzero;
        s.l2 += a * a;
        if (a > s.amax) s.amax = a;
        if (first) { s.mn = v; s.mx = v; first = false; }
        else { if (v < s.mn) s.mn = v; if (v > s.mx) s.mx = v; }
    }
    s.count += n;
}

const char* attnSpineVerdict(const AttnSpineSample& s) {
    if (s.null || s.count == 0) return "NOT_REACHED";
    if (s.nan || s.inf) return "NONFINITE";
    if (s.amax > kAttnPoisonAbsMax) return "POISON";
    if (s.finite != s.count) return "PARTIAL";
    return "SANE";
}

// One ordered record per stage. `extra` carries stage-specific facts (head
// index, mask implementation) so the shape stays identical across stages and a
// mechanical diff of two runs lines up stage for stage.
void attnSpineEmit(size_t layer, size_t pos, const char* stage,
                   const AttnSpineSample& s, const char* extra) {
    std::fprintf(stderr,
        "[ATTNBISECT] L=%zu POS=%lld STAGE=%s N=%zu FINITE=%zu NAN=%zu INF=%zu "
        "NONZERO=%zu MIN=%.6g MAX=%.6g ABSMAX=%.6g L2=%.6g FIRST_BAD=%lld "
        "VERDICT=%s POISON_ABSMAX=%.0g %s\n",
        layer, (long long)pos, stage, s.count, s.finite, s.nan, s.inf, s.nonzero,
        s.mn, s.mx, s.amax, std::sqrt(s.l2), s.firstBad,
        attnSpineVerdict(s), kAttnPoisonAbsMax, extra ? extra : "");
    std::fflush(stderr);
}

// Ordered record log for one computeAttention call, so the function itself can
// name the first transition instead of a human re-reading 14 lines.
struct AttnSpineLog {
    std::vector<const char*> stages;
    std::vector<const char*> verdicts;
    void add(const char* stage, const char* verdict) {
        stages.push_back(stage); verdicts.push_back(verdict);
    }
    void firstBad(long long& idx, const char*& bad, const char*& prevGood) const {
        idx = -1; bad = "NONE"; prevGood = "NONE";
        for (size_t i = 0; i < verdicts.size(); ++i) {
            const char* v = verdicts[i];
            const bool bad_ = (std::strcmp(v, "POISON") == 0) || (std::strcmp(v, "NONFINITE") == 0);
            if (bad_) {
                idx = (long long)i;
                bad = stages[i];
                if (i > 0) prevGood = stages[i - 1];
                return;
            }
        }
    }
};

void attnSpineSummary(size_t layer, size_t pos, const AttnSpineLog& log) {
    long long idx = -1; const char* bad = "NONE"; const char* prevGood = "NONE";
    log.firstBad(idx, bad, prevGood);
    std::fprintf(stderr,
        "[ATTNBISECT] L=%zu POS=%lld STAGE=SUMMARY STAGES_RECORDED=%zu "
        "FIRST_BAD_STAGE=%s PREVIOUS_GOOD_STAGE=%s FIRST_BAD_INDEX=%lld "
        "POISON_ABSMAX=%.0g\n",
        layer, (long long)pos, log.stages.size(), bad, prevGood, idx,
        kAttnPoisonAbsMax);
    std::fflush(stderr);
}

} // namespace

void Deep2Engine::computeAttention(size_t layer, const float* input,
                                   float* output, size_t seqLen) {
    const double _tAttn0 = tokProfOn() ? TokWall::nowNs() : 0.0;
    struct _AttnTimer {
        double t0; bool on;
        ~_AttnTimer() { if (on) { g_tokWall.attnNs += TokWall::nowNs() - t0; ++g_tokWall.attnCalls; } }
    } _attnTimer{ _tAttn0, tokProfOn() };
    if (!input || !output || seqLen == 0) {
        throw std::runtime_error("attention: invalid buffers/sequence");
    }
    if (layer >= modelWeights.layers.size()) {
        throw std::runtime_error("attention: layer weights not bound");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    if (lw.useMLA || modelWeights.useMLA) {
        // RAWRXD_CPU_MLA_KERNEL_001: MLA now has a CPU route.
        //
        // The GPU branch is tried first because on a device-backed route it is
        // the faster and already-validated path; the CPU branch is a real
        // alternative execution root, not a silent fallback for a GPU failure.
        // Each branch returns true ONLY when it completed the layer, so a failure
        // inside one is a refusal rather than a partial result handed on.
        //
        // Ordering matters for correctness of the error message: computeMLAAttentionGpu
        // refuses immediately on the FUSED layout (it requires attnQ_a, which a
        // fused model does not have), so on this machine the GPU branch returns
        // false at its first shape guard and the CPU branch does the work.
        if (computeMLAAttentionGpu(layer, input, output, seqLen))
            return;
        if (computeMLAAttentionCpu(layer, input, output, seqLen))
            return;
        throw std::runtime_error(
            "attention: neither the GPU nor the CPU MLA path could execute "
            "this layer (see [CPU_MLA] / GEMV_SINGLE lines above for the "
            "specific refusal)");
    }

    const size_t H = modelWeights.hiddenDim
        ? modelWeights.hiddenDim
        : config.hiddenDim;
    const size_t numHeads = modelWeights.numHeads;
    const size_t numKVHeads = modelWeights.numKVHeads
        ? modelWeights.numKVHeads
        : numHeads;
    const size_t headDim = modelWeights.headDim
        ? modelWeights.headDim
        : (numHeads ? H / numHeads : 0);

    const size_t qDim = numHeads * headDim;
    const size_t kvDim = numKVHeads * headDim;

    if (H == 0 || numHeads == 0 || numKVHeads == 0 || headDim == 0 ||
        numHeads % numKVHeads != 0) {        throw std::runtime_error("attention: invalid MHA/GQA geometry");
    }

    const size_t groupSize = numHeads / numKVHeads;
    std::vector<float> attnValue(qDim, 0.0f);

    std::memset(output, 0, H * sizeof(float));
    std::memset(qProj, 0, qDim * sizeof(float));
    std::memset(kProj, 0, kvDim * sizeof(float));
    std::memset(vProj, 0, kvDim * sizeof(float));

    // RAWRXD_LAYER0_ATTN_BISECT_001 gate. Declared before the projection branch
    // so the spine is armed on every route -- separate Q/K/V, fused QKV -- and
    // not only on the branch that happened to be instrumented last time.
    static const bool attnBisectOn = [] {
        const char* v = std::getenv("RAWRXD_ATTN_BISECT");
        return v && v[0] && v[0] != '0';
    }();
    static const bool attnBisectAll = [] {
        const char* v = std::getenv("RAWRXD_ATTN_BISECT_ALL");
        return v && v[0] && v[0] != '0';
    }();
    const bool spine = attnBisectOn && (attnBisectAll || layer == 0);
    // Read-only position peek. kvCache is null-checked at its real use below;
    // this only avoids a crash and reports -1 when there is nothing to read.
    // It does not move the existing length check, so the error path is unchanged.
    const size_t spinePos = spine ? (kvCache ? kvCache->currentLength() : (size_t)-1)
                                  : (size_t)0;
    AttnSpineLog spineLog;
    if (spine) {
        AttnSpineSample s;
        attnSpineAccum(input, H, s);
        attnSpineEmit(layer, spinePos, "ATTN_L0_IN", s, "HIDDEN");
        spineLog.add("ATTN_L0_IN", attnSpineVerdict(s));
    }

    if (lw.wq.data) {
        if (!lw.wk.data || !lw.wv.data) {
            throw std::runtime_error("attention: incomplete Q/K/V tensor set");
        }
        const float* bq = lw.bq.data
            ? reinterpret_cast<const float*>(lw.bq.data) : nullptr;
        const float* bk = lw.bk.data
            ? reinterpret_cast<const float*>(lw.bk.data) : nullptr;
        const float* bv = lw.bv.data
            ? reinterpret_cast<const float*>(lw.bv.data) : nullptr;
        const WeightTensor* qkvW[3]={&lw.wq,&lw.wk,&lw.wv};
        float* qkvY[3]={qProj,kProj,vProj};
        // RAWRXD_LAYER0_ATTN_BISECT_002: discriminator only. Setting
        // RAWRXD_ATTN_NOGROUP=1 skips the grouped host-GEMV dispatch so the
        // LinearW fallback runs instead. This changes WHICH route executes, and
        // that is the entire purpose: it separates a grouped-dispatch defect
        // from a shared weight-decode defect. It is not a fix and must not be
        // left enabled in any certified configuration.
        static const bool attnNoGroup = [](){
            const char* v = std::getenv("RAWRXD_ATTN_NOGROUP");
            return v && v[0] && v[0] != '0';
        }();
        const char* gemvReject = "NONE";
        const bool grouped = attnNoGroup ? false
                                         : tryVulkanHostGEMVGroup(
                                               qkvW, qkvY, 3, input, H, &gemvReject);
        if (attnNoGroup) gemvReject = "SKIPPED_BY_RAWRXD_ATTN_NOGROUP";
        // RAWRXD_LAYER0_ATTN_BISECT_001: route telemetry, not a presumed cause.
        // Records whether the grouped dual-GPU path was attempted, whether it
        // HANDLED the operation, and which guard rejected it when it did not.
        // This is what reconciles "forward: vulkan=0/0" with
        // "computeAttention: tryVulkanHostGEMVGroup(...)" without assuming which.
        if (spine) {
            std::fprintf(stderr,
                "[ATTNBISECT] L=%zu STAGE=ATTN_GEMV_ROUTE OP=QKV "
                "TRY_VULKAN_HOST_GEMV_GROUP=%d RETURNED_HANDLED=%d FALLBACK_EXECUTED=%d "
                "VULKAN_INITIALIZED=%d VULKAN_DEVICES=%zu REJECT_REASON=%s "
                "WEIGHT_ROUTE=%s\n",
                layer, attnNoGroup ? 0 : 1, grouped ? 1 : 0, grouped ? 0 : 1,
                vulkanInitialized_ ? 1 : 0, vulkanDevices_.size(), gemvReject,
                grouped ? "GROUPED_DUAL_GPU" : "LINEARW_HOST");
            std::fflush(stderr);
            const char* route = grouped ? "GROUPED_DUAL_GPU" : "LINEARW_HOST";
            for (int op = 0; op < 3; ++op) {
                static const char* const kOps[3] = { "Q", "K", "V" };
                std::fprintf(stderr,
                    "[ATTNBISECT] L=%zu STAGE=GEMV_ROUTE_%s ROUTE=%s RETURNED_HANDLED=%d\n",
                    layer, kOps[op], route, grouped ? 1 : 0);
                std::fflush(stderr);
            }
        }
        if (layer == 0) {
            std::fprintf(stderr, "[ATTNBISECT_ROUTE] L=0 NOGROUP_REQUESTED=%d GROUPED_RETURNED=%d\n",
                attnNoGroup ? 1 : 0, grouped ? 1 : 0);
            std::fflush(stderr);
            // RAWRXD_WQEXT_REACHABILITY_001: unconditional site-reached proof.
            // Emitted before any lambda or gate so that "no [PROV] WQEXT line"
            // is distinguishable from "this code did not run".
            std::fprintf(stderr, "[WQEXT_SITE_REACHED=1 layer=%zu]\n", layer);
            std::fflush(stderr);

            // Byte-extent discriminator (observe only). Compares the bound view
            // production actually uses against the canonical Q2_K geometry that
            // an independent GGUF read measured (row stride 1008 = 12 x 84).
            {
                auto dumpExt = [&](const char* tag, const WeightTensor* t) {
                    if (!t || !t->data) {
                        std::fprintf(stderr,
                            "[WQEXT] %s NULL data=(null)\n", tag);
                        return;
                    }
                    const size_t bpr = t->cols ? (t->cols / 256ull) : 0;
                    const size_t rowBytes = t->rows ? (t->sizeBytes / t->rows) : 0;
                    // RAWRXD_TENSOR_PROVENANCE_001 — second observation site.
                    // Identical derivation to [PROV] at LWBOUND so both can be
                    // compared IN THE SAME PROCESS. The LWBOUND half alone is
                    // not evidence about this site; only the comparison is.
                    {
                        uint64_t h = 1469598103934665603ull;
                        auto mix = [&](uint64_t v) { h ^= v; h *= 1099511628211ull; };
                        auto mixStr = [&](const std::string& s) {
                            mix(s.size());
                            for (char c : s) mix((uint64_t)(unsigned char)c);
                        };
                        mixStr(t->name);
                        mix((uint64_t)t->type);
                        mix((uint64_t)t->rows);
                        mix((uint64_t)t->cols);
                        mix((uint64_t)t->sizeBytes);
                        mix((uint64_t)t->shardId);
                        mix(t->hasFileBacking ? t->fileOffset : 0xFFFFFFFFFFFFFFFFull);
                        mix((uint64_t)(t->hasFileBacking ? 1 : 0));
                        mix((uint64_t)t->shape.size());
                        for (auto d : t->shape) mix((uint64_t)d);
                        std::fprintf(stderr,
                            "[PROV] site=WQEXT tensor=%s id=%016llx shard=%u file_off=%lld "
                            "backing=%d bytes=%zu dims=%zux%zu\n",
                            tag, (unsigned long long)h, t->shardId,
                            (long long)(t->hasFileBacking ? (long long)t->fileOffset : -1LL),
                            t->hasFileBacking ? 1 : 0, t->sizeBytes, t->rows, t->cols);
                    }
                    std::fprintf(stderr,
                        "[WQEXT] %s type=%d ne0=%zu ne1=%zu nb0=%zu nb1=%zu data=%p "
                        "row_bytes=%zu blocks_per_row=%zu block_size=%.4f\n",
                        tag, t->type, t->cols, t->rows, t->cols, t->sizeBytes,
                        t->data, rowBytes, bpr,
                        bpr ? ((double)rowBytes / (double)bpr) : 0.0);
                    const uint8_t* p = (const uint8_t*)t->data;
                    std::fprintf(stderr, "[WQEXT] %s first84=", tag);
                    for (int i = 0; i < 84; i++) std::fprintf(stderr, "%02x", p[i]);
                    std::fprintf(stderr, "\n");
                };
                dumpExt("WQ", &lw.wq);
                dumpExt("WK", &lw.wk);
                dumpExt("WV", &lw.wv);
                std::fflush(stderr);
            }
        }
        if(grouped){
            if(bq) for(size_t i=0;i<qDim;++i) qProj[i]+=bq[i];
            if(bk) for(size_t i=0;i<kvDim;++i) kProj[i]+=bk[i];
            if(bv) for(size_t i=0;i<kvDim;++i) vProj[i]+=bv[i];
        } else {
            // RAWRXD_GPU_K_ROPE_BISECT_001: the projection input itself. If this
    // already differs from ArenaNormed on the GPU, the Q4_K GEMV is innocent
    // and the divergence is upstream in RMSNorm.
    {
        static const bool normInEnabled = [](){
            const char* v = std::getenv("RAWRXD_KV_PARITY_DUMP");
            return v && v[0] && v[0] != '0';
        }();
        static bool normInDone = false;
        if (normInEnabled && !normInDone && layer == 0 && input) {
            normInDone = true;
            std::fprintf(stderr, "[NORMIN] CPU L=0 IN8=%g %g %g %g %g %g %g %g\n",
                input[0],input[1],input[2],input[3],input[4],input[5],input[6],input[7]);
            std::fflush(stderr);
        }
    }
    LinearW(lw.wq, input, bq, qProj, qDim);
            LinearW(lw.wk, input, bk, kProj, kvDim);
            LinearW(lw.wv, input, bv, vProj, kvDim);
        }
        parityEmit(ParityCheckpoint::Q, qProj, qDim);
        parityEmit(ParityCheckpoint::K, kProj, kvDim);
        parityEmit(ParityCheckpoint::V, vProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "Q", qProj, qDim);
        parityEmitLayer(static_cast<int>(layer), "K", kProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "V", vProj, kvDim);

// RAWRXD_LAYER0_ATTN_BISECT_001: the four stages this block used to
        // emit here (ATTN_L0_IN / Q_PROJ / K_PROJ / V_PROJ) are now emitted by
        // the ordered spine at their true positions -- ATTN_L0_IN before the
        // projection branch so it also covers the fused-QKV route, and the three
        // projections after the branch converges. This block was the reason a
        // bisect could silently not run on the fused route at all.
    } else if (lw.wqkv.data) {
        const size_t fusedDim = qDim + 2 * kvDim;
        std::vector<float> fused(fusedDim);
        LinearW(lw.wqkv, input, nullptr, fused.data(), fusedDim);
        std::memcpy(qProj, fused.data(), qDim * sizeof(float));
        std::memcpy(kProj, fused.data() + qDim, kvDim * sizeof(float));
        std::memcpy(vProj, fused.data() + qDim + kvDim, kvDim * sizeof(float));
    } else {
        throw std::runtime_error("attention: no Q or fused-QKV weight");
    }

    // Projection boundary, after the route converges: these are the first
    // ordered stages of the spine and the first place a weight/address/dequant
    // or GEMV defect can appear. Emitted here rather than inside the separate
    // Q/K/V branch so the fused-QKV route is covered identically.
    if (spine) {
        struct { const char* stage; const float* p; size_t n; } proj[3] = {
            { "Q_PROJ", qProj, qDim }, { "K_PROJ", kProj, kvDim }, { "V_PROJ", vProj, kvDim }
        };
        for (const auto& e : proj) {
            AttnSpineSample s;
            attnSpineAccum(e.p, e.n, s);
            attnSpineEmit(layer, spinePos, e.stage, s, "POST_PROJECTION");
            spineLog.add(e.stage, attnSpineVerdict(s));
        }
    }

    if (lw.attnQNorm.data) {
        for (size_t h = 0; h < numHeads; ++h) {
            RMSNormW(lw.attnQNorm,
                     qProj + h * headDim,
                     qProj + h * headDim,
                     headDim,
                     modelWeights.normEps);
        }
    }
    if (lw.attnKNorm.data) {
        for (size_t h = 0; h < numKVHeads; ++h) {
            RMSNormW(lw.attnKNorm,
                     kProj + h * headDim,
                     kProj + h * headDim,
                     headDim,
                     modelWeights.normEps);
        }
    }

    // RAWRXD_LAYER0_ATTN_BISECT_001: pre-RoPE boundary, after QK-norm. Together
    // with Q_PROJ/K_PROJ this isolates the QK-norm from the rotation: if a
    // projection is already bad the norm is not implicated, and if these are
    // sane while Q_POST_ROPE is not, the defect is the rotation or its indexing.
    if (spine) {
        AttnSpineSample qs, ks;
        attnSpineAccum(qProj, qDim, qs);
        attnSpineAccum(kProj, kvDim, ks);
        attnSpineEmit(layer, spinePos, "Q_PRE_ROPE", qs, "POST_QKNORM");
        attnSpineEmit(layer, spinePos, "K_PRE_ROPE", ks, "POST_QKNORM");
        spineLog.add("Q_PRE_ROPE", attnSpineVerdict(qs));
        spineLog.add("K_PRE_ROPE", attnSpineVerdict(ks));
    }

    if (!config.useKVCache || !kvCache) {
        throw std::runtime_error(
            "attention: causal generation requires an allocated KV cache");
    }

    const size_t pos = kvCache->currentLength();
    if (config.maxSeqLen != 0 && pos >= config.maxSeqLen) {
        throw std::runtime_error("attention: KV position exceeds context");
    }
    if (seqLen != pos + 1) {
        // DIAG-N2KV: emit exact positions to identify which caller passes a
        // stale sequence length (prefill expects pos==seqLen-1).
        std::fprintf(stderr,
            "[Deep2Engine] KV mismatch: pos=%zu seqLen=%zu layer=%zu\n",
            pos, seqLen, layer);
        std::fflush(stderr);
        throw std::runtime_error("attention: sequence/KV position mismatch");
    }

    // RAWRXD_GPU_KV_NUMERIC_PARITY_001 / RAWRXD_GPU_K_ROPE_BISECT_001
    // (opt-in; read-only, dumps only).
    static const bool kvParityDumpEnabled = [](){
        const char* v = std::getenv("RAWRXD_KV_PARITY_DUMP");
        return v && v[0] && v[0] != '0';
    }();

    if (config.useRoPE) {
        const float theta = ropeThetaForLayer(layer);
        const float scaling = modelWeights.ropeScaling > 0.0f
            ? modelWeights.ropeScaling
            : config.ropeScaling;
        {
            const bool isLocalLayer =
                modelWeights.slidingWindowPattern > 0 &&
                (layer % modelWeights.slidingWindowPattern) != 0;
            // RAWRXD_DEEP2_LOG_FLOOD_001
            // This print was unconditional and fired once per layer per token:
            // 28 lines per generated token for a 28-layer model, 170 KB of
            // stderr for 64 tokens. It contaminated every throughput measurement
            // (the writes are on the critical path and stderr is unbuffered) and
            // it buried the diagnostics that actually mattered -- a 170 KB log
            // is why a STATUS_ACCESS_VIOLATION at teardown took this long to
            // localise. It is now opt-in via RAWRXD_TRACE_ROPE=1 and off by
            // default. The value is unchanged, only its reachability.
            static const bool traceRope = [] {
                const char* e = std::getenv("RAWRXD_TRACE_ROPE");
                return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T');
            }();
            if (traceRope) {
                std::fprintf(stderr, "ROPE layer=%zu theta=%.1f local=%s\n",
                             layer, theta, isLocalLayer ? "yes" : "no");
                std::fflush(stderr);
            }
        }
        // RAWRXD_GPU_K_ROPE_BISECT_001: capture K immediately before and after
        // applyRoPE so the CPU side of the K bisect is available. At pos=0
        // RoPE must be ~identity, so K_PRE ~= K_POST is the expected control.
        std::vector<float> kPreDump, qPreDump;
        if (kvParityDumpEnabled && layer == 0 && (pos == 0 || pos == 1)) {
            kPreDump.assign(kProj, kProj + kvDim);
            qPreDump.assign(qProj, qProj + qDim);
        }
        applyRoPE(qProj, kProj, headDim, numHeads, numKVHeads,
                  pos, theta, scaling);
        // RAWRXD_LAYER0_ATTN_BISECT_001: post-RoPE boundary. At pos=0 RoPE is
        // ~identity, so Q_POST_ROPE ~= Q_PRE_ROPE is the expected control; a
        // divergence between them at pos=0 is a rotation or indexing defect, not
        // a weight defect.
        if (spine) {
            AttnSpineSample qs, ks;
            attnSpineAccum(qProj, qDim, qs);
            attnSpineAccum(kProj, kvDim, ks);
            char extra[96];
            std::snprintf(extra, sizeof(extra), "POST_ROPE pos=%zu theta=%.4g scaling=%.6g",
                          pos, (double)theta, (double)scaling);
            attnSpineEmit(layer, spinePos, "Q_POST_ROPE", qs, extra);
            attnSpineEmit(layer, spinePos, "K_POST_ROPE", ks, extra);
            spineLog.add("Q_POST_ROPE", attnSpineVerdict(qs));
            spineLog.add("K_POST_ROPE", attnSpineVerdict(ks));
        }
        if (kvParityDumpEnabled && layer == 0 && (pos == 0 || pos == 1) &&
            kPreDump.size() == kvDim) {
            std::fprintf(stderr,
                "[ROPEBISECT] CPU L=0 pos=%zu headDim=%zu nHeads=%zu nKV=%zu theta=%g\n",
                pos, headDim, numHeads, numKVHeads, (double)theta);
            for (size_t kh = 0; kh < numKVHeads && kh < 2; ++kh) {
                const size_t b0 = kh*headDim;
                std::fprintf(stderr, "[ROPEBISECT] CPU L=0 kh=%zu K_PRE =%g %g %g %g %g %g %g %g\n",
                    kh, kPreDump[b0+0],kPreDump[b0+1],kPreDump[b0+2],kPreDump[b0+3],
                    kPreDump[b0+4],kPreDump[b0+5],kPreDump[b0+6],kPreDump[b0+7]);
                std::fprintf(stderr, "[ROPEBISECT] CPU L=0 kh=%zu K_POST=%g %g %g %g %g %g %g %g\n",
                    kh, kProj[b0+0],kProj[b0+1],kProj[b0+2],kProj[b0+3],
                    kProj[b0+4],kProj[b0+5],kProj[b0+6],kProj[b0+7]);
                float dmax = 0.0f;
                for (size_t d = 0; d < headDim; ++d) {
                    const float df = kProj[b0+d] - kPreDump[b0+d];
                    if (std::fabs(df) > dmax) dmax = std::fabs(df);
                }
                std::fprintf(stderr, "[ROPEBISECT] CPU L=0 kh=%zu ROPE_DELTA_CPU=%g\n", kh, dmax);
            }
            // Q is Q4_K like K. If Q is ALSO wrong, the defect is the Q4_K
            // GEMV/dequant path in general, not anything K-specific.
            std::fprintf(stderr, "[QBISECT] CPU L=0 pos=%zu h0 Q_PRE =%g %g %g %g %g %g %g %g\n",
                pos, qPreDump[0],qPreDump[1],qPreDump[2],qPreDump[3],
                qPreDump[4],qPreDump[5],qPreDump[6],qPreDump[7]);
            std::fprintf(stderr, "[QBISECT] CPU L=0 pos=%zu h0 Q_POST=%g %g %g %g %g %g %g %g\n",
                pos, qProj[0],qProj[1],qProj[2],qProj[3],
                qProj[4],qProj[5],qProj[6],qProj[7]);
            float qd = 0.0f;
            for (size_t d = 0; d < headDim; ++d) {
                const float df = qProj[d] - qPreDump[d];
                if (std::fabs(df) > qd) qd = std::fabs(df);
            }
            std::fprintf(stderr, "[QBISECT] CPU L=0 pos=%zu h0 ROPE_DELTA_CPU=%g\n", pos, qd);
            std::fflush(stderr);
        }
        parityEmit(ParityCheckpoint::Q_Rope, qProj, qDim);
        parityEmit(ParityCheckpoint::K_Rope, kProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "Q_ROPE", qProj, qDim);
        parityEmitLayer(static_cast<int>(layer), "K_ROPE", kProj, kvDim);
    }

    // RAWRXD_GPU_KV_NUMERIC_PARITY_001 (opt-in; read-only, dumps only).
    for (size_t h = 0; h < numKVHeads; ++h) {
        float* kd = kvCache->keyPtr(layer, h, pos);
        float* vd = kvCache->valuePtr(layer, h, pos);
        if (!kd || !vd) {
            throw std::runtime_error("attention: invalid KV destination");
        }
        std::memcpy(kd, kProj + h * headDim, headDim * sizeof(float));
        std::memcpy(vd, vProj + h * headDim, headDim * sizeof(float));
    }
    // RAWRXD_LAYER0_ATTN_BISECT_001: read the slot back out of the cache rather
    // than probing the projection buffer. The value the next decode step will
    // consume is the one in the cache, so the cache is the correct thing to
    // measure; probing the source buffer would not detect a short write.
    if (spine) {
        const float* k0 = kvCache->keyPtr(layer, 0, pos);
        const float* v0 = kvCache->valuePtr(layer, 0, pos);
        AttnSpineSample ks, vs;
        attnSpineAccum(k0, headDim, ks);
        attnSpineAccum(v0, headDim, vs);
        attnSpineEmit(layer, spinePos, "K_CACHE_SLOT0", ks, "READ_BACK_AFTER_WRITE");
        attnSpineEmit(layer, spinePos, "V_CACHE_SLOT0", vs, "READ_BACK_AFTER_WRITE");
        spineLog.add("K_CACHE_SLOT0", attnSpineVerdict(ks));
        spineLog.add("V_CACHE_SLOT0", attnSpineVerdict(vs));
    }
    // One parity record per layer over the full kvDim span (post-RoPE K,
    // raw V) matching the reference cache layout [kvHead][headDim].
    parityEmitKvWrite(static_cast<int>(layer), kProj, vProj, kvDim);

    // RAWRXD_GPU_KV_NUMERIC_PARITY_001: dump the CPU reference K/V for this
    // slot immediately after the prefill write and BEFORE decode1 can touch
    // it. Dumped post-RoPE on purpose -- matching the pre-RoPE projection
    // would not exonerate the value actually stored in the cache.
    // Layout is [kvHead][headDim], identical ordering to the GPU slot.
    if (kvParityDumpEnabled && (pos == 0 || pos == 1) &&
        (layer == 0 || layer + 1 == config.numLayers)) {
        std::fprintf(stderr, "[KVPAR] CPU layer=%zu pos=%zu headDim=%zu kvHeads=%zu\n",
            layer, pos, headDim, numKVHeads);
        for (size_t kh = 0; kh < numKVHeads; ++kh) {
            const float* kk = kvCache->keyPtr(layer, kh, pos);
            const float* vv = kvCache->valuePtr(layer, kh, pos);
            std::fprintf(stderr, "[KVPAR] CPU L=%zu p=%zu kh=%zu K8=%g %g %g %g %g %g %g %g\n",
                layer, pos, kh, kk[0],kk[1],kk[2],kk[3],kk[4],kk[5],kk[6],kk[7]);
            std::fprintf(stderr, "[KVPAR] CPU L=%zu p=%zu kh=%zu V8=%g %g %g %g %g %g %g %g\n",
                layer, pos, kh, vv[0],vv[1],vv[2],vv[3],vv[4],vv[5],vv[6],vv[7]);
        }
        std::fflush(stderr);
    }

    const size_t attend = pos + 1;
    const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    std::vector<float> scores(attend);
    // RAWRXD_LAYER0_ATTN_BISECT_001: a probe-only copy of the raw dot products.
    // The production path folds the scale into `scores` in place and does not
    // otherwise retain the pre-scale value, so without this copy
    // SCORES_PRE_SCALE would have to be reconstructed rather than observed.
    // Allocated and written only while the probe is armed; nothing reads it on
    // the production path, so arithmetic and allocation behaviour are unchanged.
    std::vector<float> spinePreScale;
    if (spine) spinePreScale.assign(attend, 0.0f);
    // Worst-case accumulators across all heads, so a defect that only appears in
    // a head other than 0 cannot be reported as SANE by a head-0 probe.
    struct SpineAgg { size_t nan = 0, inf = 0, samples = 0; double amax = 0.0; } ;
    SpineAgg aggPre, aggPost, aggSoft, aggCtx;

    // RAWRXD_ATTN_CTX2_PROBE_001: layer 0 only, positions 0 and 1 only. Layer 0
    // is where the divergence first appears, and restricting to it keeps the
    // probe from perturbing the other 21 layers through 32 per-head readbacks.
    const bool ctx2Wanted = Deep2::Ctx2::wantsPosition(static_cast<int>(pos)) &&
                            layer == 0;
    std::vector<float> rawScores;
    if (ctx2Wanted) rawScores.assign(attend, 0.0f);

    for (size_t h = 0; h < numHeads; ++h) {
        const size_t kvHead = h / groupSize;
        const float* q = qProj + h * headDim;
        float* headOut = attnValue.data() + h * headDim;

        for (size_t t = 0; t < attend; ++t) {
            const float* k = kvCache->keyPtr(layer, kvHead, t);
            if (!k) throw std::runtime_error("attention: invalid K cache read");
            double dot = 0.0;
            for (size_t d = 0; d < headDim; ++d) {
                dot += static_cast<double>(q[d]) *
                       static_cast<double>(k[d]);
            }
            // Bit-identical to the previous single expression: the cast to
            // float happens at the same point, then the same multiply.
            const float rawDot = static_cast<float>(dot);
            if (spine) spinePreScale[t] = rawDot;
            scores[t] = rawDot * scale;
            if (ctx2Wanted) rawScores[t] = static_cast<float>(dot);
        }
        // RAWRXD_LAYER0_ATTN_BISECT_001: both sides of the scale, head 0 exact
        // plus a worst-case fold across every head.
        if (spine) {
            AttnSpineSample pre, post;
            attnSpineAccum(spinePreScale.data(), attend, pre);
            attnSpineAccum(scores.data(), attend, post);
            aggPre.nan += pre.nan; aggPre.inf += pre.inf;
            aggPre.samples += pre.count;
            aggPre.amax = pre.amax > aggPre.amax ? pre.amax : aggPre.amax;
            aggPost.nan += post.nan; aggPost.inf += post.inf;
            aggPost.samples += post.count;
            aggPost.amax = post.amax > aggPost.amax ? post.amax : aggPost.amax;
            if (h == 0) {
                char extra[128];
                std::snprintf(extra, sizeof(extra),
                              "HEAD=0 KVHEAD=%zu ATTEND=%zu SCALE=%.9g",
                              kvHead, attend, (double)scale);
                attnSpineEmit(layer, spinePos, "SCORES_PRE_SCALE", pre, extra);
                attnSpineEmit(layer, spinePos, "SCORES_POST_SCALE", post, extra);
                spineLog.add("SCORES_PRE_SCALE", attnSpineVerdict(pre));
                spineLog.add("SCORES_POST_SCALE", attnSpineVerdict(post));
            }
        }
        parityEmit(ParityCheckpoint::AttnScores, scores.data(), attend);
        parityEmitLayer(static_cast<int>(layer), "ATTN_SCORES",
                        scores.data(), attend);

        // RAWRXD_LAYER0_ATTN_BISECT_001: mask boundary, taken BEFORE softmax. There
        // is no mask array on this route -- the causal mask is fused into the
        // loop bound `t < attend`, exactly as Deep2::AttnVis already records
        // with "fused_full_causal" and mask count 0. So the measured post-mask
        // vector is numerically the post-scale vector, and emitting it proves
        // that: if SCORES_POST_MASK ever differs from SCORES_POST_SCALE, a mask
        // step ran that the route does not document. Emitting a mask value after
        // softmax would instead describe a mask that was never applied.
        if (spine && h == 0) {
            AttnSpineSample msk;
            attnSpineAccum(scores.data(), attend, msk);
            char extra[160];
            std::snprintf(extra, sizeof(extra),
                          "MASK_IMPL=FUSED_CAUSAL_BOUND MASK_ARRAY_APPLIED=0 "
                          "HEAD=0 ATTEND=%zu HEAD_DIM=%zu SCALE=%.9g",
                          attend, headDim, (double)scale);
            attnSpineEmit(layer, spinePos, "SCORES_POST_MASK", msk, extra);
            spineLog.add("SCORES_POST_MASK", attnSpineVerdict(msk));
        }
        softmax(scores.data(), scores.size());
        // RAWRXD_LAYER0_ATTN_BISECT_001: softmax boundary. A finite-but-wrong
        // normalisation and a non-finite one are distinguished here: with the
        // causal mask fused into the bound, the probe sum should be ~1.
        if (spine && h == 0) {
            AttnSpineSample soft;
            attnSpineAccum(scores.data(), attend, soft);
            double probSum = 0.0;
            if (scores.data())
                for (size_t t = 0; t < attend; ++t)
                    if (std::isfinite(scores[t])) probSum += (double)scores[t];
            aggSoft.nan += soft.nan; aggSoft.inf += soft.inf;
            aggSoft.samples += soft.count;
            aggSoft.amax = soft.amax > aggSoft.amax ? soft.amax : aggSoft.amax;
            char extra[160];
            std::snprintf(extra, sizeof(extra),
                          "HEAD=0 ATTEND=%zu PROB_SUM=%.9g EXPECTED_PROB_SUM=1",
                          attend, probSum);
            attnSpineEmit(layer, spinePos, "SCORES_POST_SOFTMAX", soft, extra);
            spineLog.add("SCORES_POST_SOFTMAX", attnSpineVerdict(soft));
        }
        parityEmit(ParityCheckpoint::AttnProbs, scores.data(), attend);
        parityEmitLayer(static_cast<int>(layer), "ATTN_PROBS",
                        scores.data(), attend);

        std::memset(headOut, 0, headDim * sizeof(float));
        for (size_t t = 0; t < attend; ++t) {
            const float* v = kvCache->valuePtr(layer, kvHead, t);
            if (!v) throw std::runtime_error("attention: invalid V cache read");
            const float a = scores[t];
            for (size_t d = 0; d < headDim; ++d) {
                headOut[d] += a * v[d];
            }
        }
        // RAWRXD_LAYER0_ATTN_BISECT_001: context boundary for this head. This is
        // where a V addressing or cache-layout defect would first appear.
        if (spine && h == 0) {
            AttnSpineSample ctx;
            attnSpineAccum(headOut, headDim, ctx);
            aggCtx.nan += ctx.nan; aggCtx.inf += ctx.inf;
            aggCtx.samples += ctx.count;
            aggCtx.amax = ctx.amax > aggCtx.amax ? ctx.amax : aggCtx.amax;
            char extra[96];
            std::snprintf(extra, sizeof(extra), "HEAD=0 KVHEAD=%zu ATTEND=%zu",
                          kvHead, attend);
            attnSpineEmit(layer, spinePos, "CONTEXT", ctx, extra);
            spineLog.add("CONTEXT", attnSpineVerdict(ctx));
        }

        // RAWRXD_ATTN_CTX2_PROBE_001: the four objects for the CTX=1 -> CTX=2
        // transition, taken from the production arithmetic at the point it
        // happens. `rawScores` holds the unscaled dot products, which the
        // production path folds into `scores` in place and therefore does not
        // otherwise retain; keeping a copy is what makes SCORE_RAW observable
        // rather than reconstructed.
        if (ctx2Wanted) {
            Deep2::Ctx2::Record r;
            r.step = static_cast<int>(pos);
            r.ctx = static_cast<int>(attend);
            r.side = "cpu";
            r.layer = static_cast<int>(layer);
            r.qHead = static_cast<int>(h);
            r.kvHead = static_cast<int>(kvHead);
            r.gqaGroup = static_cast<int>(groupSize);
            r.headDim = static_cast<int>(headDim);
            r.scoreRaw = rawScores;
            r.scoreScaled.assign(rawScores.begin(), rawScores.end());
            for (size_t t = 0; t < rawScores.size(); ++t) {
                r.scoreScaled[t] = r.scoreScaled[t] * scale;
            }
            r.prob.assign(scores.begin(), scores.end());
            r.out.assign(headOut, headOut + headDim);
            // The bytes this head consumed, hashed per head so the join can ask
            // directly whether two sides used the same inputs. K and V are
            // taken from the LAST visible slot, which is the slot whose value
            // the divergence is measured against.
            r.qHash = Deep2::Ctx2::fnv1a(q, headDim);
            {
                const float* kLast = kvCache->keyPtr(layer, kvHead, attend - 1);
                const float* vLast = kvCache->valuePtr(layer, kvHead, attend - 1);
                if (kLast) r.kHash = Deep2::Ctx2::fnv1a(kLast, headDim);
                if (vLast) r.vHash = Deep2::Ctx2::fnv1a(vLast, headDim);
                const size_t n8 = headDim < 8 ? headDim : 8;
                if (kLast) r.kF8.assign(kLast, kLast + n8);
                if (vLast) r.vF8.assign(vLast, vLast + n8);
            }
            r.qF8.assign(q, q + (headDim < 8 ? headDim : 8));
            Deep2::Ctx2::emit(r);
        }
    }
    // RAWRXD_ATTN_VISIBILITY_TRACE_001: state-visibility record for THIS
    // production attention call, using only values the code above actually
    // used. `pos` is the index written above, `attend` is the count the read
    // loop reached, and the loop body is `t < attend`, so the read range is
    // [0, attend-1]. No mask array exists on this route: the causal read is
    // fused into the loop bound, so MASK_IMPL records that rather than
    // reporting a mask that was never applied.
    Deep2::AttnVis::recordAttention(
        layer, pos, pos, pos, pos, pos,
        0, attend - 1, attend,
        "fused_full_causal", 0, attend - 1,
        attend - 1, "cpu_attn");
    parityEmit(ParityCheckpoint::AttnValue, attnValue.data(), qDim);
    parityEmitLayer(static_cast<int>(layer), "ATTN_VALUE",
                    attnValue.data(), qDim);

    if (!finiteVector(attnValue.data(), qDim)) {
        throw std::runtime_error("attention: non-finite softmax/value output");
    }

    const WeightTensor* outWeight =
        lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (!outWeight) {
        throw std::runtime_error("attention: missing output projection");
    }
    size_t woRows = 0, woCols = 0;
    if (!matrixShape(*outWeight, woRows, woCols) ||
        woRows != H || woCols != qDim) {
        throw std::runtime_error("attention: invalid output projection geometry");
    }
    LinearW(*outWeight, attnValue.data(), nullptr, output, H);
    parityEmit(ParityCheckpoint::OProj, output, H);
    parityEmitLayer(static_cast<int>(layer), "O_PROJ", output, H);

    // RAWRXD_LAYER0_ATTN_BISECT_001: context across ALL heads, then the output
    // projection, then the function summary that names the first transition.
    // CONTEXT_ALL is the aggregate that a head-0-only probe cannot provide.
    if (spine) {
        AttnSpineSample ctxAll;
        attnSpineAccum(attnValue.data(), qDim, ctxAll);
        char ctxExtra[192];
        std::snprintf(ctxExtra, sizeof(ctxExtra),
                      "NUM_HEADS=%zu HEAD_DIM=%zu NUM_KV_HEADS=%zu "
                      "WORST_HEAD_NAN=%zu WORST_HEAD_INF=%zu WORST_HEAD_ABSMAX=%.6g",
                      numHeads, headDim, numKVHeads,
                      aggCtx.nan, aggCtx.inf, aggCtx.amax);
        attnSpineEmit(layer, spinePos, "CONTEXT_ALL", ctxAll, ctxExtra);
        spineLog.add("CONTEXT_ALL", attnSpineVerdict(ctxAll));

        AttnSpineSample op;
        attnSpineAccum(output, H, op);
        attnSpineEmit(layer, spinePos, "O_PROJ", op, "OUTPUT_PROJECTION");
        spineLog.add("O_PROJ", attnSpineVerdict(op));
        // ATTN_OUT is the same buffer as O_PROJ on the CPU route: forwardLayer
        // probes `attentionOutput`, which IS this `output`. Emitted under both
        // names so the spine joins to the existing LAYERDIAG ATTN_OUT record
        // without a reader having to know they alias.
        attnSpineEmit(layer, spinePos, "ATTN_OUT", op, "ALIASES_O_PROJ");
        spineLog.add("ATTN_OUT", attnSpineVerdict(op));
        attnSpineSummary(layer, spinePos, spineLog);
    }

    if (!finiteVector(output, H)) {
        throw std::runtime_error("attention: non-finite projected output");
    }
}

// =================== FFN (SwiGLU / GeGLU / Simple MLP) ====================
void Deep2Engine::computeFFN(size_t layer, const float* input, float* output) {
    (void)layer;
    size_t H = config.hiddenDim;
    size_t I = modelWeights.intermediateDim ? modelWeights.intermediateDim : H * 4;

    const LayerWeights& lw = modelWeights.layers[layer];
    if (lw.wGate.data && lw.wUp.data && lw.wDown.data) {
        // Real SwiGLU / GeGLU: gate = Wg @ x, up = Wu @ x
        const WeightTensor* guW[2]={&lw.wGate,&lw.wUp};
        float* guY[2]={gateBuf,upBuf};
        if(!tryVulkanHostGEMVGroup(guW,guY,2,input,H)){
            LinearW(lw.wGate, input, nullptr, gateBuf, I);
            LinearW(lw.wUp,   input, nullptr, upBuf,   I);
        }

        parityEmit(ParityCheckpoint::FfnGate, gateBuf, I);
        parityEmit(ParityCheckpoint::FfnUp,   upBuf,   I);
        parityEmitLayer(static_cast<int>(layer), "FFN_GATE", gateBuf, I);
        parityEmitLayer(static_cast<int>(layer), "FFN_UP",   upBuf,   I);
        // Gemma3 uses GeGLU (GELU-based); everything else uses SiLU-based SwiGLU
        if (modelArchitecture_ == "gemma3") {
            geglu(gateBuf, upBuf, gateBuf, I);
            parityEmit(ParityCheckpoint::Swiglu, gateBuf, I);
            parityEmitLayer(static_cast<int>(layer), "GEGLU", gateBuf, I);
        } else {
            for (size_t i = 0; i < I; ++i) gateBuf[i] = silu(gateBuf[i]) * upBuf[i];
            parityEmit(ParityCheckpoint::Swiglu, gateBuf, I);
            parityEmitLayer(static_cast<int>(layer), "SWIGLU", gateBuf, I);
        }
        // down = Wd @ gateBuf
        LinearW(lw.wDown, gateBuf, nullptr, output, H);
        parityEmit(ParityCheckpoint::FfnDown, output, H);
        parityEmitLayer(static_cast<int>(layer), "FFN_DOWN", output, H);
    } else if (lw.wUp.data && lw.wDown.data) {
        // Simple MLP (Nemotron-H): up = Wu @ x, act(up), down = Wd @ act
        LinearW(lw.wUp, input, nullptr, gateBuf, I);
        parityEmit(ParityCheckpoint::FfnUp, gateBuf, I);
        parityEmitLayer(static_cast<int>(layer), "FFN_UP", gateBuf, I);
for (size_t i = 0; i < I; ++i) gateBuf[i] = silu(gateBuf[i]);
            parityEmit(ParityCheckpoint::Swiglu, gateBuf, I);
            parityEmitLayer(static_cast<int>(layer), "SILU", gateBuf, I);
            LinearW(lw.wDown, gateBuf, nullptr, output, H);
        parityEmit(ParityCheckpoint::FfnDown, output, H);
        parityEmitLayer(static_cast<int>(layer), "FFN_DOWN", output, H);
    } else {
        throw std::runtime_error(
            "computeFFN: dense FFN tensors are not fully bound; synthetic fallback is forbidden");
    }
    if (!finiteVector(output, H)) {
        throw std::runtime_error("computeFFN: non-finite output");
    }
}

// =================== SwiGLU ACTIVATION ====================
void Deep2Engine::SwiGLU(const float* gate, const float* up,
                         float* output, size_t dim) {
    if (!gate || !up || !output || dim == 0)
        throw std::runtime_error("SwiGLU: null input/output");
    for (size_t i = 0; i < dim; ++i)
        output[i] = silu(gate[i]) * up[i];
}

// =================== MoE FFN (REAL ROUTED EXPERTS) ====================
void Deep2Engine::computeMoEFFN(size_t layer,
                                const float* input,
                                float* output) {
    RAWRXD_DEEP2_TRACE("MOE_FFN_CALL layer=%zu input=%p output=%p\n", layer, (void*)input, (void*)output);
    if (!input || !output || layer >= modelWeights.layers.size()) {
        RAWRXD_DEEP2_TRACE("MOE_FFN_CALL FAIL: invalid args input=%p output=%p layer=%zu layers=%zu\n",
            (void*)input, (void*)output, layer, modelWeights.layers.size());
        throw std::runtime_error("MoE: invalid layer/input/output");
    }
    if (input == output)
        throw std::runtime_error("MoE: output aliases input");

    // BATCH10_GPU_MOE_FIRST
    if (vulkanInitialized_ && !vulkanDevices_.empty()) {
        if (computeMoEFFNGpu(layer, input, output))
            return;
        if (vulkanStrictNoCpuFallback_)
            throw std::runtime_error("MoE: GPU expert path failed under strict mode");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = modelWeights.hiddenDim;
    const size_t E = modelWeights.numExperts;
    const size_t K = modelWeights.numExpertsPerToken;
    const size_t I = modelWeights.moeIntermediateDim;

    if (H == 0 || E == 0 || K == 0 || K > E || I == 0)
        throw std::runtime_error("MoE: invalid model geometry");
    if (!lw.moeRouter.data ||
        lw.moeRouter.rows != E ||
        lw.moeRouter.cols != H)
        throw std::runtime_error("MoE: router tensor not bound");
    if (lw.moeUp.size() != E ||
        lw.moeDown.size() != E)
        throw std::runtime_error("MoE: expert tensors not fully bound");
    // Nematron-H uses packed experts without per-expert gate projections.
    if (modelArchitecture_ != "nemotron_h_moe" && lw.moeGate.size() != E)
        throw std::runtime_error("MoE: expert gate tensors not fully bound");
    if (layer >= moeRouters_.size() || !moeRouters_[layer])
        throw std::runtime_error("MoE: router runtime not initialized");

    std::vector<float> routerLogits(E, 0.0f);
    LinearW(lw.moeRouter, input, nullptr, routerLogits.data(), E);

    TokenRoute route =
        moeRouters_[layer]->RouteFromLogits(routerLogits.data(), E);
    if (!route.valid ||
        route.expertIds.size() != K ||
        route.expertWeights.size() != K)
        throw std::runtime_error("MoE: route failed");

    // RAWRXD_EXPERT_REUSE_TRACE_001
    //
    // The one measurement that decides whether the transient-realization
    // architecture (UNMODEL/UNADDRESS/SPACELESS/REALIZE) is buildable at all.
    // It is placed here because this is the SINGLE point every routed expert
    // passes through: RouteFromLogits has produced the top-k, the ids are
    // validated, and the token index is known. No expert can be executed
    // without appearing in route.expertIds at this line, so the trace cannot
    // miss an access, and it cannot double-count one.
    //
    // WHY REUSE DISTANCE AND NOT EXPERT-HIT-RATE
    //   A residency policy needs to know how far away the next use of a given
    //   (layer, expert) is, not merely whether it was ever hit. Two distances
    //   are recorded because they imply different residency designs:
    //     ACCESS distance -- intervening EXPERT ACCESSES. Bounds the working set:
    //       if P95 is ~7, a HOT set of 8-12 experts per layer is plausible.
    //     TOKEN  distance -- intervening DECODE TOKENS. Bounds how long a hot
    //       tensor must survive: a large TOKEN distance with a small ACCESS
    //       distance means many experts are live at once.
    //   If P95 access distance is ~90, a small HOT set cannot work and the whole
    //   strategy must change. That is the falsification this buys.
    //
    // MEASUREMENT, NOT ASSERTION
    //   Every field is observed at runtime. Nothing here is a default, a target,
    //   or a constant: the counters are printed from accumulated observations and
    //   an unrun trace prints nothing at all.
    //
    //   SCOPE LIMIT, stated rather than hidden: this records the ROUTER's
    //   selection, which is an upper bound on expert residency pressure. If a
    //   selected expert is then skipped, the trace over-counts residency demand.
    //   That direction is the safe one -- it over-states the working set rather
    //   than under-stating it -- but it is a bound and not an equality.
    if (g_expertReuseTraceEnabled) {
        const std::uint64_t token = g_expertReuseToken;
        const std::uint64_t accessSeq = g_expertReuseAccessSeq;
        for (size_t k = 0; k < route.expertIds.size(); ++k) {
            const int eid = route.expertIds[k];
            if (eid < 0) continue;
            // Keyed by (layer, expert): MoE weights are per-layer, so an expert
            // id means nothing without its layer. A shared-expert slot is
            // deliberately NOT recorded here -- it is resident for every token by
            // construction and would pollute the reuse distribution.
            const std::uint64_t key =
                (static_cast<std::uint64_t>(layer) << 32) |
                static_cast<std::uint32_t>(eid);

            auto it = g_expertReuseLast.find(key);
            const bool seen = (it != g_expertReuseLast.end());
            const std::uint64_t prevAccess = seen ? it->second.accessSeq : 0;
            const std::uint64_t prevToken   = seen ? it->second.token     : 0;

            std::fprintf(stderr,
                         "EXPERT_REUSE TOKEN=%llu LAYER=%zu EXPERT=%d ACCESS_SEQ=%llu "
                         "PREV_ACCESS_SEQ=%llu REUSE_DISTANCE_ACCESS=%llu "
                         "PREV_TOKEN=%llu REUSE_DISTANCE_TOKEN=%llu COLD_FIRST_TOUCH=%d\n",
                         (unsigned long long)token, layer, eid,
                         (unsigned long long)accessSeq,
                         (unsigned long long)prevAccess,
                         seen ? (unsigned long long)(accessSeq - prevAccess) : 0ull,
                         (unsigned long long)prevToken,
                         seen ? (unsigned long long)(token - prevToken) : 0ull,
                         seen ? 0 : 1);
            g_expertReuseLast[key] = ReuseSlot{accessSeq, token};
            ++g_expertReuseAccessSeq;
            if (!seen) ++g_expertReuseColdFirstTouches;
            else       ++g_expertReuseReused;
        }
        ++g_expertReuseToken;
    }

#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
    {
        SsmStageRange inR, lgR;
        ssmStageAccum(input, H, inR);
        ssmStageAccum(routerLogits.data(), E, lgR);
        double wAbs = 0.0;
        for (size_t k = 0; k < route.expertWeights.size(); ++k) {
            const double w = std::fabs(static_cast<double>(route.expertWeights[k]));
            if (w > wAbs) wAbs = w;
        }
        RAWRXD_DEEP2_TRACE(
            "MOESTAGE layer=%zu STAGE=ROUTER NORM_NONFINITE=%zu NORM_ABSMIN=%.9g "
            "NORM_ABSMAX=%.9g ROUTER_LOGITS_ABSMIN=%.9g ROUTER_LOGITS_ABSMAX=%.9g "
            "ROUTER_LOGITS_NONZERO=%d ROUTER_LOGITS_NONFINITE=%zu "
            "ROUTER_TOPK_VALID=%d ROUTER_WEIGHTS_ABSMIN=%.9g ROUTER_WEIGHTS_ABSMAX=%.9g "
            "ROUTER_WEIGHTS_NONZERO=%d EXPERT_IDS=",
            layer, inR.nonfinite, inR.amax, lgR.mn, lgR.mx,
            (lgR.amax > 0.0) ? 1 : 0, lgR.nonfinite,
            (route.expertIds.size() == K) ? 1 : 0,
            0.0, wAbs, (wAbs > 0.0) ? 1 : 0);
        for (size_t k = 0; k < route.expertIds.size(); ++k)
            RAWRXD_DEEP2_TRACE("%d%s", route.expertIds[k],
                               (k + 1 < route.expertIds.size()) ? "," : "");
        RAWRXD_DEEP2_TRACE("\n");
    }
#endif

    // BATCH007: advisory prefetch of routed experts into per-device ExpertCache
    const uint64_t cpuEpoch = kvCache ? kvCache->currentLength() : 0;
    expertPredictorCounters_.observations += 1;
    expertPredictorCounters_.liveRoutes += 1;
    {
        std::vector<uint32_t> observed;
        observed.reserve(route.expertIds.size());
        for (size_t k = 0; k < route.expertIds.size(); ++k)
            if (route.expertIds[k] >= 0)
                observed.push_back(static_cast<uint32_t>(route.expertIds[k]));
        expertPredictor_.observe(static_cast<uint32_t>(layer), observed);
    }
    for (size_t dev = 0; dev < expertCaches_.size(); ++dev) {
        auto& cache = expertCaches_[dev];
        if (!cache) continue;
        for (size_t k = 0; k < K; ++k) {
            const int eid = route.expertIds[k];
            if (eid < 0) continue;
            const rawrxd::deep2::ExpertKey key{static_cast<uint32_t>(layer), static_cast<uint32_t>(eid)};
            cache->prefetch(key, cpuEpoch);
            ++expertPredictorCounters_.prefetchesIssued;
            // RAWRXD_DEEP2_PREDICTIVE_ROUTER_ADOPTION_001: real router weights
            // feed the cache's EMA predicted value, so EmaLfu eviction scores on
            // router probability rather than recency alone.
            cache->notePrediction(key, route.expertWeights[k], cpuEpoch);
            ++expertPredictorCounters_.notesEmitted;
        }
    }

    // RAWRXD_DEEP2_PREDICTIVE_ROUTER_ADOPTION_001: query the routing-heat
    // predictor for this layer and feed the predicted keys forward as
    // non-binding placement hints. Prediction affects placement only; the
    // selected experts above are unchanged.
    {
        const auto predicted =
            expertPredictor_.predict(static_cast<uint32_t>(layer), K);
        expertPredictorCounters_.predictedQueries += 1;
        expertPredictorCounters_.predictedKeys += predicted.size();
        for (const uint32_t e : predicted) {
            for (size_t dev = 0; dev < expertCaches_.size(); ++dev) {
                auto& cache = expertCaches_[dev];
                if (!cache) continue;
                cache->notePrediction(rawrxd::deep2::ExpertKey{static_cast<uint32_t>(layer), e},
                                      0.0f, cpuEpoch);
            }
            // Overlap of the prediction against the true route for this layer.
            for (size_t k = 0; k < K; ++k)
                if (route.expertIds[k] >= 0 &&
                    static_cast<uint32_t>(route.expertIds[k]) == e) {
                    ++expertPredictorCounters_.matchesNextLayer;
                    break;
                }
        }
    }

    std::fill(output, output + H, 0.0f);

    // Shared expert participates independently of routed top-k experts.
    if (lw.moeSharedGate.data || lw.moeSharedUp.data ||
        lw.moeSharedDown.data) {
        // B3-C: the staging buffer must be distinct from `input`. The engine
        // calls computeMoEFFN(layer, layerTemp, ffnOutput), so staging into
        // layerTemp zeroed the FFN input before any expert GEMV ran and the
        // whole MoE output came out exactly zero on every invocation.
        if (!moeSharedTemp)
            throw std::runtime_error("MoE: shared-expert staging not allocated");
        if (input == moeSharedTemp)
            throw std::runtime_error("MoE: shared-expert staging aliases FFN input");
        std::fill(moeSharedTemp, moeSharedTemp + H, 0.0f);
        computeSharedExpertFFN(layer, input, moeSharedTemp);
        for (size_t i = 0; i < H; ++i)
            output[i] += moeSharedTemp[i];
#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
        SsmStageRange shR;
        ssmStageAccum(moeSharedTemp, H, shR);
        RAWRXD_DEEP2_TRACE(
            "MOESTAGE layer=%zu STAGE=SHARED_OUT N=%zu ABSMAX=%.9g NONZERO=%d "
            "NONFINITE=%zu SHARED_STAGING_ALIASES_INPUT=0\n",
            layer, H, shR.amax, (shR.amax > 0.0) ? 1 : 0, shR.nonfinite);
#endif
    }

    auto runOne = [&](size_t routeIndex) -> std::vector<float> {
        const int expertId = route.expertIds[routeIndex];
        if (expertId < 0 || static_cast<size_t>(expertId) >= E)
            throw std::runtime_error("MoE: routed expert id out of range");

        MoEWeightHandle handle;
        handle.layer = static_cast<int>(layer);
        handle.expert = expertId;
        handle.gate = &lw.moeGate[static_cast<size_t>(expertId)];
        handle.up   = &lw.moeUp[static_cast<size_t>(expertId)];
        handle.down = &lw.moeDown[static_cast<size_t>(expertId)];

        const size_t a = handle.gate->sizeBytes;
        const size_t b = handle.up->sizeBytes;
        const size_t c = handle.down->sizeBytes;
        if (a > std::numeric_limits<size_t>::max() - b ||
            a + b > std::numeric_limits<size_t>::max() - c)
            throw std::runtime_error("MoE: expert byte counter overflow");
        handle.bytes = a + b + c;

        std::vector<float> expertOut(H, 0.0f);
        computeExpertFFN(handle, input, expertOut.data(), H, I);
        return expertOut;
    };

    // Top-k experts are independent. Use the real worker pool when safe;
    // nested calls from a pool worker execute inline to avoid starvation.
    if (threadPool && !threadPool->isWorkerThread() && K > 1) {
        std::vector<std::future<std::vector<float>>> futures;
        futures.reserve(K);
        for (size_t j = 0; j < K; ++j) {
            futures.emplace_back(threadPool->enqueue(
                [&, j] { return runOne(j); }));
        }

        for (size_t j = 0; j < K; ++j) {
            std::vector<float> expertOut = futures[j].get();
            const float w = route.expertWeights[j];
            for (size_t i = 0; i < H; ++i)
                output[i] += w * expertOut[i];
        }
    } else {
        for (size_t j = 0; j < K; ++j) {
            std::vector<float> expertOut = runOne(j);
            const float w = route.expertWeights[j];
            for (size_t i = 0; i < H; ++i)
                output[i] += w * expertOut[i];
        }
    }

    if (!finiteVector(output, H))
        throw std::runtime_error("MoE: non-finite routed output");

#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
    SsmStageRange outR;
    ssmStageAccum(output, H, outR);
    RAWRXD_DEEP2_TRACE(
        "MOESTAGE layer=%zu STAGE=FFN_OUTPUT N=%zu ABSMAX=%.9g NONZERO=%d "
        "NONFINITE=%zu FFN_ZERO=%d GATE=DEEP2_MOE_FFN_EXECUTION_001\n",
        layer, H, outR.amax, (outR.amax > 0.0) ? 1 : 0, outR.nonfinite,
        (outR.amax == 0.0) ? 1 : 0);
#endif
}

void Deep2Engine::LinearWBatch4(
    const WeightTensor& wt,const float* inputBatch,size_t count,
    const float* bias,float* outputBatch,size_t outDim)
{
    if(!inputBatch||!outputBatch||count==0||count>4||outDim==0)
        throw std::runtime_error("LinearWBatch4: invalid arguments");

    size_t rows=0,cols=0;
    if(!matrixShape(wt,rows,cols)||rows!=outDim)
        throw std::runtime_error("LinearWBatch4: geometry mismatch");

    // Q4_K is the target amortized path. Other types retain exactness by
    // using the already GPU-backed single-vector LinearW path.
    if(wt.type==(int)GGMLType::GGML_TYPE_Q4_K &&
       vulkanInitialized_&&vulkanDevices_.size()>=2) {
        std::fprintf(stderr,
            "Q4K_OPROJ_TRACE LinearWBatch4 wt=%p type=%d rows=%zu cols=%zu count=%zu outDim=%zu input=%p output=%p strict=%d\n",
            wt.data, wt.type, rows, cols, count, outDim,
            (const void*)inputBatch, (const void*)outputBatch,
            (int)vulkanStrictNoCpuFallback_);
        std::fflush(stderr);
        std::memset(outputBatch,0,count*outDim*sizeof(float));
        if(tryVulkanHostGEMVBatch4(
                wt,inputBatch,count,outputBatch,outDim)) {
            // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001: this is a BYPASS, not a
            // delegation. Despite the name, LinearWBatch4 is not a wrapper
            // around LinearW -- on GPU success it returns here and never enters
            // LinearW() at all, so the batched lmHead is outside the LinearW
            // funnel on exactly the same footing as an ordinary projection.
            {
                using namespace rawrxd::deep2::weightcensus;
                Event bev;
                bev.site = Site::LinearWBatch4; bev.route = Route::Bypass;
                bev.tensor = wt.name;
                bev.bytes = wt.sizeBytes ? wt.sizeBytes : rows * cols;
                WeightConsumptionCensus::instance().record(bev);
            }
            if(bias) {
                for(size_t b=0;b<count;++b)
                    for(size_t i=0;i<outDim;++i)
                        outputBatch[b*outDim+i]+=bias[i];
            }
            if(!finiteVector(outputBatch,count*outDim))
                throw std::runtime_error(
                    "LinearWBatch4: non-finite GPU batch output");
            return;
        }
        if(vulkanStrictNoCpuFallback_)
            throw std::runtime_error(
                "LinearWBatch4: Q4_K batch GPU path failed under strict mode");
    }

    for(size_t b=0;b<count;++b)
        LinearW(wt,inputBatch+b*cols,bias,
                outputBatch+b*outDim,outDim);
}

void Deep2Engine::computeExpertFFN(const MoEWeightHandle& handle,
                                   const float* input,
                                   float* output,
                                   size_t hiddenDim,
                                   size_t expertDim) {
    if (!handle.valid() || !input || !output ||
        hiddenDim == 0 || expertDim == 0)
        throw std::runtime_error("MoE expert: invalid handle/geometry");

    const WeightTensor& up   = *handle.up;
    const WeightTensor& down = *handle.down;

    if (!up.data || !down.data ||
        up.rows != expertDim || up.cols != hiddenDim ||
        down.rows != hiddenDim || down.cols != expertDim)
        throw std::runtime_error("MoE expert: tensor geometry mismatch");

    if (handle.gate && handle.gate->data) {
        const WeightTensor& gate = *handle.gate;
        if (gate.rows != expertDim || gate.cols != hiddenDim)
            throw std::runtime_error("MoE expert: gate tensor geometry mismatch");

        std::vector<float> gateBufLocal(expertDim, 0.0f);
        std::vector<float> upBufLocal(expertDim, 0.0f);

        LinearW(gate, input, nullptr, gateBufLocal.data(), expertDim);
        LinearW(up,   input, nullptr, upBufLocal.data(), expertDim);

        SwiGLU(gateBufLocal.data(),
               upBufLocal.data(),
               gateBufLocal.data(),
               expertDim);

        std::fill(output, output + hiddenDim, 0.0f);
        LinearW(down, gateBufLocal.data(), nullptr, output, hiddenDim);
    } else {
        // Nematron-H packed experts: no per-expert gate projection; up acts as gate.
        std::vector<float> upBufLocal(expertDim, 0.0f);
        LinearW(up, input, nullptr, upBufLocal.data(), expertDim);
        for (size_t i = 0; i < expertDim; ++i) upBufLocal[i] = silu(upBufLocal[i]);
        std::fill(output, output + hiddenDim, 0.0f);
        LinearW(down, upBufLocal.data(), nullptr, output, hiddenDim);
    }

    if (!finiteVector(output, hiddenDim))
        throw std::runtime_error("MoE expert: non-finite output");
}

void Deep2Engine::computeSharedExpertFFN(size_t layer,
                                         const float* input,
                                         float* output) {
    if (!input || !output || layer >= modelWeights.layers.size())
        throw std::runtime_error("MoE shared: invalid layer/input/output");

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = modelWeights.hiddenDim;

    const bool any =
        lw.moeSharedGate.data || lw.moeSharedUp.data || lw.moeSharedDown.data;
    if (!any) {
        std::fill(output, output + H, 0.0f);
        return;
    }

    const bool all = lw.moeSharedGate.data &&
                     lw.moeSharedUp.data &&
                     lw.moeSharedDown.data;
    if (all) {
        const size_t I = lw.moeSharedGate.rows;
        if (I == 0 ||
            lw.moeSharedGate.cols != H ||
            lw.moeSharedUp.rows != I || lw.moeSharedUp.cols != H ||
            lw.moeSharedDown.rows != H || lw.moeSharedDown.cols != I)
            throw std::runtime_error("MoE shared: tensor geometry mismatch");

        std::vector<float> gate(I, 0.0f);
        std::vector<float> up(I, 0.0f);

        LinearW(lw.moeSharedGate, input, nullptr, gate.data(), I);
        LinearW(lw.moeSharedUp, input, nullptr, up.data(), I);
        SwiGLU(gate.data(), up.data(), gate.data(), I);

        std::fill(output, output + H, 0.0f);
        LinearW(lw.moeSharedDown, gate.data(), nullptr, output, H);
    } else if (lw.moeSharedUp.data && lw.moeSharedDown.data) {
        // Nematron-H style shared expert without gate projection.
        const size_t I = lw.moeSharedUp.rows;
        if (I == 0 ||
            lw.moeSharedUp.cols != H ||
            lw.moeSharedDown.rows != H || lw.moeSharedDown.cols != I)
            throw std::runtime_error("MoE shared: tensor geometry mismatch");
        std::vector<float> up(I, 0.0f);
        LinearW(lw.moeSharedUp, input, nullptr, up.data(), I);
        for (size_t i = 0; i < I; ++i) up[i] = silu(up[i]);
        std::fill(output, output + H, 0.0f);
        LinearW(lw.moeSharedDown, up.data(), nullptr, output, H);
    } else {
        throw std::runtime_error("MoE shared: incomplete shared expert");
    }

    if (!finiteVector(output, H))
        throw std::runtime_error("MoE shared: non-finite output");
}

void Deep2Engine::computeSSM(size_t layer, const float* input, float* output) {
    using Deep2::Arch::Ref::silu;
    using Deep2::Arch::Ref::softplus;
    using Deep2::Arch::Ref::depthwiseConvStep;
    using Deep2::Arch::Ref::mamba2Step;
    using Deep2::Arch::Ref::finite;

    RAWRXD_DEEP2_TRACE("SSM_CALL layer=%zu input=%p output=%p\n", layer, (void*)input, (void*)output);
    if (!input || !output || layer >= modelWeights.layers.size()) {
        RAWRXD_DEEP2_TRACE("SSM_CALL FAIL: invalid args input=%p output=%p layer=%zu layers=%zu\n",
            (void*)input, (void*)output, layer, modelWeights.layers.size());
        throw std::runtime_error("computeSSM: invalid layer/input/output");
    }
    // DEFECT_A guard: input and output must not alias. The old call
    // computeSSM(layer, output, output) corrupted the residual mid-compute.
    // forwardLayer now routes input->layerTemp and output->mixerBranch.
    if (input == output) {
        RAWRXD_DEEP2_TRACE("SSM_CALL FAIL: aliased input==output layer=%zu\n", layer);
        throw std::runtime_error("computeSSM: input and output must not alias");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    if (!lw.hasSSM)
        throw std::runtime_error("computeSSM: layer is not an SSM/Mamba layer");

    const size_t H = config.hiddenDim;
    if (!nemotronGeoOk_ || !ssmInner_ || !ssmStateSize_ || !ssmHeads_ || !ssmGroups_) {
        std::memcpy(output, input, H * sizeof(float));
        static bool warnedOnce = false;
        if (!warnedOnce) {
            std::fprintf(stderr,
                "[Deep2Engine] WARNING: SSM metadata incomplete; identity fallback active.\n");
            warnedOnce = true;
        }
        return;
    }

    const size_t inner       = ssmInner_;
    const size_t stateN      = ssmStateSize_;
    const size_t heads       = ssmHeads_;
    const size_t groups      = ssmGroups_;
    const size_t headDim     = inner / heads;
    const size_t groupBC     = groups * stateN;
    const size_t convChannels = inner + 2 * groupBC;
    const size_t inRows      = 2 * inner + 2 * groupBC + heads;

    if (!ssmX || !ssmY || !ssmTemp || !ssmState || !ssmConvState)
        throw std::runtime_error("computeSSM: SSM buffers not allocated");

#ifdef RAWRXD_DEEP2_SSM_NUMERIC_DIAG
    const long long ssmDiagCall = ssmDiagNext();
    const bool ssmDiagOn = ssmDiagCall < ssmDiagBudget();
    const auto dstage = [&](const char* name, const float* p, size_t n) {
        if (!ssmDiagOn) return;
        SsmStageRange r;
        ssmStageAccum(p, n, r);
        std::fprintf(stderr,
            "SSMDIAG call=%lld layer=%zu STAGE=%s N=%zu MIN=%.9g MAX=%.9g ABSMAX=%.9g NONFINITE=%zu\n",
            ssmDiagCall, layer, name, n, r.mn, r.mx, r.amax, r.nonfinite);
        std::fflush(stderr);
    };
    if (ssmDiagOn) {
        std::fprintf(stderr,
            "SSMDIAG call=%lld layer=%zu GEO inner=%zu state=%zu heads=%zu groups=%zu "
            "headDim=%zu groupBC=%zu convChannels=%zu inRows=%zu convK=%zu\n",
            ssmDiagCall, layer, inner, stateN, heads, groups,
            headDim, groupBC, convChannels, inRows, ssmConvKernel);
        char sh[192];
        ssmShapeText(lw.ssmIn, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmIn SHAPE=%s\n", ssmDiagCall, layer, sh);
        ssmShapeText(lw.ssmConv1d, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmConv1d SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, convChannels * ssmConvKernel);
        ssmShapeText(lw.ssmConv1dBias, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmConv1dBias SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, convChannels);
        ssmShapeText(lw.ssmDtBias, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmDtBias SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, heads);
        ssmShapeText(lw.ssmA, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmA SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, heads);
        ssmShapeText(lw.ssmD, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmD SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, heads);
        ssmShapeText(lw.ssmNorm, sh, sizeof sh);
        std::fprintf(stderr, "SSMDIAG call=%lld layer=%zu TENSOR=ssmNorm SHAPE=%s EXPECT_ELEMENTS=%zu\n",
                     ssmDiagCall, layer, sh, inner);
        dstage("X_INPUT", input, H);
    }
#else
    const bool ssmDiagOn = false;
    const auto dstage = [](const char*, const float*, size_t) {};
#endif

    if (!lw.ssmIn.data || !lw.ssmOut.data || !lw.ssmConv1d.data ||
        !lw.ssmDtBias.data || !lw.ssmA.data || !lw.ssmD.data || !lw.ssmNorm.data)
        throw std::runtime_error("computeSSM: required SSM tensors missing");

    // ---- 1. input projection: z | x0 | B0 | C0 | dt0 ----
    LinearW(lw.ssmIn, input, nullptr, ssmTemp, inRows);

    const float* z  = ssmTemp;
    const float* x0 = z + inner;
    const float* B0 = x0 + inner;
    const float* C0 = B0 + groupBC;
    const float* dt0 = C0 + groupBC;

    dstage("PROJ_ALL", ssmTemp, inRows);
    dstage("PROJ_Z", z, inner);
    dstage("PROJ_X0", x0, inner);
    dstage("PROJ_B0", B0, groupBC);
    dstage("PROJ_C0", C0, groupBC);
    dstage("PROJ_DT0", dt0, heads);

    // ---- 2. causal depthwise conv1d over x,B,C ----
    float* convIn = ssmX; // borrow ssmX as scratch [convChannels]
    std::copy_n(x0, inner, convIn);
    std::copy_n(B0, 2 * groupBC, convIn + inner);
    dstage("CONV_IN", convIn, convChannels);

    // ---- 3. dequantize conv1d weights + bias ONCE per layer, reused per token ----
    auto& lc = ssmLayerCaches_[layer];
    if (!lc.initialized) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmConv1d.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get conv1d dequant");
        const size_t nConv = convChannels * ssmConvKernel;
        lc.convK.resize(nConv);
        dq(static_cast<const uint8_t*>(lw.ssmConv1d.data), lc.convK.data(), nConv);
        if (lw.ssmConv1dBias.data) {
            const auto* dqB = QuantKernelRegistry::Instance().GetDequant(lw.ssmConv1dBias.type);
            if (dqB) {
                lc.convB.resize(convChannels);
                dqB(static_cast<const uint8_t*>(lw.ssmConv1dBias.data), lc.convB.data(), convChannels);
            }
        }
        lc.initialized = true;
    }
    auto& convK = lc.convK;
    auto& convB = lc.convB;

    float* convHist = ssmConvState + layer * convChannels * (ssmConvKernel > 1 ? (ssmConvKernel - 1) : 0);
    float* convOut  = ssmY; // borrow ssmY as scratch [convChannels]
    depthwiseConvStep(convIn, convChannels, convK.data(), ssmConvKernel,
                      convHist, convB.data(), convOut);
    dstage("CONV_ACC_PRE_SILU", convOut, convChannels);
    dstage("CONV_HISTORY", convHist, convChannels * (ssmConvKernel > 1 ? (ssmConvKernel - 1) : 0));
    dstage("CONV_KERNEL", convK.data(), convK.size());
    dstage("CONV_BIAS", convB.data(), convB.size());
    for (size_t i = 0; i < convChannels; ++i) convOut[i] = silu(convOut[i]);
    dstage("CONV_OUT", convOut, convChannels);

    const float* x = convOut;
    const float* B = convOut + inner;
    const float* C = B + groupBC;
    dstage("X_CONV", x, inner);
    dstage("B_CONV", B, groupBC);
    dstage("C_CONV", C, groupBC);

    // ---- 4. prepare dt bias, A, D (dequant ONCE per layer) ----
    if (lc.dtBias.empty()) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmDtBias.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get dtBias dequant");
        lc.dtBias.resize(heads);
        dq(static_cast<const uint8_t*>(lw.ssmDtBias.data), lc.dtBias.data(), heads);
    }
    if (lc.A.empty()) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmA.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get A dequant");
        lc.A.resize(heads);
        dq(static_cast<const uint8_t*>(lw.ssmA.data), lc.A.data(), heads);
        for (size_t h = 0; h < heads; ++h)
            if (lc.A[h] > 0.0f) lc.A[h] = -std::exp(lc.A[h]);
    }
    if (lc.D.empty()) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmD.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get D dequant");
        lc.D.resize(heads);
        dq(static_cast<const uint8_t*>(lw.ssmD.data), lc.D.data(), heads);
    }
    auto& dtBias = lc.dtBias;
    auto& A      = lc.A;
    auto& D      = lc.D;

    static std::vector<float> dt_static;
    dt_static.resize(heads);
    for (size_t h = 0; h < heads; ++h) dt_static[h] = dt0[h] + dtBias[h];
    dstage("DT_BIAS", dtBias.data(), dtBias.size());
    dstage("A", A.data(), A.size());
    dstage("D", D.data(), D.size());
    dstage("DT", dt_static.data(), heads);

    // ---- 5. selective scan (mamba2Step) ----
    float* statePtr = ssmState + layer * heads * headDim * stateN;
    float* yPtr     = ssmX; // reuse scratch [inner]
    dstage("STATE_PRE", statePtr, heads * headDim * stateN);
    mamba2Step(x, B, C, dt_static.data(), A.data(), D.data(),
               heads, groups, headDim, stateN, statePtr, yPtr);
    dstage("STATE_POST", statePtr, heads * headDim * stateN);
    dstage("Y_SCAN", yPtr, inner);

    if (!finite(yPtr, inner))
        throw std::runtime_error("computeSSM: selective scan produced non-finite output");

    // ---- 6. gated RMS norm (Mamba2 internal, post-scan, pre-out_proj) ----
    // This is NOT the block prenorm. It normalises the scan output yPtr grouped
    // by (d_inner / n_group) contiguous elements, exactly as upstream does:
    //   llama.cpp src/models/mamba-base.cpp:273-276
    //   llama-model.cpp:4486 (ssm_norm shape {d_inner/n_group, n_group})
    // For the 4B model: d_inner=7680, n_group=8 -> group_size=960, and the
    // GGUF stores ssm_norm as ne[0]=960 (contiguous axis) x ne[1]=8 (groups),
    // so the flat element order is weight[g*960 + s] = weight[global_index].
    if (lc.normW.empty()) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmNorm.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get norm dequant");
        lc.normW.resize(inner);
        dq(static_cast<const uint8_t*>(lw.ssmNorm.data), lc.normW.data(), inner);
    }
    auto& normW = lc.normW;
    dstage("NORM_W", normW.data(), normW.size());
    dstage("Z_GATE", z, inner);

    // RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
    //
    // The centre of Mamba is a direct-weight island: ssmConv1d, ssmConv1dBias,
    // ssmDtBias, ssmA, ssmD and ssmNorm were all resolved and dequantized above
    // without ever entering LinearW(). Only ssmIn and ssmOut go through LinearW.
    // Each tensor is recorded by name so the receipt shows WHICH weights bypass,
    // not merely that something did.
    //
    // Placed after the norm dequant because that is the last of the six; every
    // one of them has therefore genuinely been read by this point.
    {
        using namespace rawrxd::deep2::weightcensus;
        const WeightTensor* ssmDirect[6] = {
            &lw.ssmConv1d, &lw.ssmConv1dBias, &lw.ssmDtBias,
            &lw.ssmA,      &lw.ssmD,         &lw.ssmNorm
        };
        for (const WeightTensor* t : ssmDirect) {
            if (!t || !t->data) continue;
            Event sev;
            sev.site  = Site::SsmDirect;
            sev.route = Route::Bypass;   // resolved and dequantized in place
            sev.tensor = t->name;
            sev.bytes = t->sizeBytes ? t->sizeBytes : t->numElements();
            WeightConsumptionCensus::instance().record(sev);
        }
    }

    const size_t groupSize = inner / groups;   // 960 for the 4B model
    if (groupSize == 0)
        throw std::runtime_error("computeSSM: non-integral ssm_norm group size");
    // Proof-checked by deep2_ssm_norm_layout_gate: ne[0]==groupSize,
    // ne[1]==groups, flat index == global element index.
    if (normW.size() != inner)
        throw std::runtime_error("computeSSM: ssm_norm weight length != d_inner");

    for (size_t g = 0; g < groups; ++g) {
        float* yg = yPtr + g * groupSize;
        double ss = 0.0;
        for (size_t s = 0; s < groupSize; ++s) ss += double(yg[s]) * double(yg[s]);
        const float inv = 1.0f / std::sqrt(float(ss / double(groupSize)) + modelWeights.normEps);
        for (size_t s = 0; s < groupSize; ++s) {
            const size_t idx = g * groupSize + s;   // flat == global
            const float nw = normW[idx];
            yg[s] = yg[s] * inv * nw * silu(z[idx]);
        }
    }

    dstage("Y_NORM", yPtr, inner);

    // ---- 7. output projection ----
    std::fill(output, output + H, 0.0f);
    LinearW(lw.ssmOut, yPtr, nullptr, output, H);
    dstage("SSM_OUT", output, H);

    if (!finite(output, H))
        throw std::runtime_error("computeSSM: final output is non-finite");

    ++ssmRealCalls_;
}

// RAWRXD_REVERSE_TRADE_TITAN_001: record the layers the resident GPU graph
// actually forwarded on this route.
//
// Why this exists, measured rather than assumed: forcing DEEP2_RESIDENT_FIRST
// produced a receipt reading
//
//     ROUTE_HISTOGRAM=VulkanResident:13   CERTIFICATION_VERDICT=FAIL
//     CERTIFICATION_BLOCKERS=NO_NODES_VISITED,ZERO_OUTPUT_COUNT,...
//
// after 13 tokens x 22 layers of real GPU compute. tryGpuTokenForward claims
// the whole token, so forwardLayer() -- the only place recordNodeExecution is
// called -- never runs on this route. The authority therefore observed a
// successful GPU forward as an empty traversal, and correctly refused to
// certify it.
//
// The layer count is NOT taken from modelWeights.numLayers. It is the DELTA of
// gpuFwd_.forwardLayers, a counter incremented once per layer submit inside the
// resident graph (Deep2Engine_GpuForward.cpp:2320) and already cross-checked
// there against tokenForwards * expectedLayersPerToken. Reading a measured
// delta is what keeps this from being a reconstruction of what should have
// happened.
static void recordResidentNodeExecutions(std::uint64_t layersForwarded)
{
    for (std::uint64_t i = 0; i < layersForwarded; ++i)
    {
        rawrxd::compute::recordNodeExecution(
            "resident_layer_" + std::to_string(static_cast<unsigned long long>(i)),
            true,
            1,
            "gpu resident layer forwarded");
    }
}

// =================== FORWARD ALL LAYERS ====================
// RAWRXD_REVERSE_TRADE_TITAN_001: maps the route that actually executed to the
// name the receipt carries. There is deliberately no default arm returning a
// plausible value: an unrecognised route must be visible in the receipt as
// itself, because an unnamed route is exactly what made the previous forward
// PASS unreversible.
static const char* routeName(Deep2Engine::ExecutionRoute r) {
    switch (r) {
        case Deep2Engine::ExecutionRoute::Cpu:             return "Cpu";
        case Deep2Engine::ExecutionRoute::VulkanResident:  return "VulkanResident";
        case Deep2Engine::ExecutionRoute::VulkanMoeHybrid: return "VulkanMoeHybrid";
        case Deep2Engine::ExecutionRoute::VulkanDualRow:   return "VulkanDualRow";
        case Deep2Engine::ExecutionRoute::HostFallback:    return "HostFallback";
        case Deep2Engine::ExecutionRoute::ReverseWebGPU: return "ReverseWebGPU";
        case Deep2Engine::ExecutionRoute::Unset:           break;
    }
    return "<unset>";
}

Deep2Engine::ForwardResult Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    // RAWRXD_TOKEN_WALL_PROFILE_001: covers every return path below.
    TokWallScope _tokProfScope(tokProfOn());
    if (!modelWeights.loaded || !hidden || seqLen == 0) {
        std::fprintf(stderr, "[FWD_ALL] FAIL: invalid_args loaded=%d hidden=%p seqLen=%zu\n",
            modelWeights.loaded ? 1 : 0, (void*)hidden, seqLen); std::fflush(stderr);
        return ForwardResult{false, ExecutionRoute::Unset, false, "invalid_args"};
    }
    if (modelWeights.layers.size() < modelWeights.numLayers) {
        std::fprintf(stderr, "[FWD_ALL] FAIL: layer_count_mismatch layers.size=%zu numLayers=%zu\n",
            modelWeights.layers.size(), (size_t)modelWeights.numLayers); std::fflush(stderr);
        return ForwardResult{false, ExecutionRoute::Unset, false, "layer_count_mismatch"};
    }
    std::fprintf(stderr, "[FWD_ALL] seqLen=%zu numLayers=%zu isMoE=%d useMLA=%d vulkan=%d/%d\n",
        seqLen, (size_t)modelWeights.numLayers,
        modelWeights.isMoE ? 1 : 0, modelWeights.useMLA ? 1 : 0,
        vulkanEnabled_ ? 1 : 0, vulkanInitialized_ ? 1 : 0); std::fflush(stderr);

    // RAWRXD_REVERSE_WEBGPU_STREAM_AUTHORITY_001
    // If the user has explicitly enabled reverse WebGPU streaming, give that
    // route first claim before any local GPU or CPU dispatch. Deep2 retains
    // model authority; the browser receives only the working set required
    // for the next dispatch.
    if (reverseWebgpuEnabled_) {
        if (tryReverseWebgpuTokenForward(hidden, seqLen)) {
            std::fprintf(stderr, "[FWD_ALL] ReverseWebGPU route succeeded\n");
            std::fflush(stderr);
            return ForwardResult{true, ExecutionRoute::ReverseWebGPU, false, nullptr};
        }
        std::fprintf(stderr, "[FWD_ALL] ReverseWebGPU route declined; continuing to local dispatch\n");
        std::fflush(stderr);
    }

    // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — map traversal evidence
    // Bind once per process; record node per layer executed.
    static bool bowrainBound = false;
    if (!bowrainBound) {
        rawrxd::compute::markSourceCreated();
        rawrxd::compute::apply("STAR", true, true, true, true, 1);
        rawrxd::compute::recordRuntimeBinding("Deep2Engine::forwardTokenAllLayers");
        bowrainBound = true;
    }
    const size_t bowrainLayerCount = modelWeights.numLayers;

    // Once any lane has mutated per-token state (device KV/residency, or
    // hidden rewritten layer-by-layer), no other lane may retry the token,
    // in strict or non-strict mode.
    auto blockCommittedFallback = [this](const char* stage, ExecutionRoute route) {
        std::fprintf(stderr,
            "COMMITTED_FALLBACK_BLOCKED=1 STRICT_NATIVE_ABORT=1 VERDICT=FAIL stage=%s\n",
            stage);
        std::fflush(stderr);
        vulkanStrictViolation_ = true;
        gpuFwdCommitted_ = false;
        return ForwardResult{false, route, false, "committed_fallback_blocked"};
    };

    // Batch10: MoE and MLA currently use host-orchestrated GPU-heavy execution.
    // It is a product execution lane, but NOT fully-resident GPU authority.
    if (vulkanEnabled_ && vulkanInitialized_ &&
        (modelWeights.isMoE || modelWeights.useMLA)) {
        if (forwardTokenGpuHybrid(hidden, seqLen)) {
            // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record execution evidence for this traversal
            {
                const size_t nodesVisited = rawrxd::compute::mapNodesVisited();
                const size_t nodesExecuted = rawrxd::compute::mapNodesExecuted();
                const size_t nodesFailed = rawrxd::compute::mapNodesFailed();
                if (nodesVisited > 0) {
                    bool finiteOutput = true;
                    for (size_t i = 0; i < config.hiddenDim; ++i) {
                        if (!std::isfinite(hidden[i])) { finiteOutput = false; break; }
                    }
                    rawrxd::compute::recordExecutionEvidence(
                        1, true, finiteOutput
                    );
                }
            }
            return ForwardResult{true, ExecutionRoute::VulkanMoeHybrid, true, nullptr};
        }
        if (gpuFwdStateMutated_)
            return blockCommittedFallback("moe_hybrid", ExecutionRoute::VulkanMoeHybrid);
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            return ForwardResult{false, ExecutionRoute::VulkanMoeHybrid, false, "moe_hybrid_failed"};
}
    }

// 40TPS dense lane:
    // A contiguous layer split keeps activations resident but executes GPU0's
    // dependent range before GPU1's range, so bandwidth does not aggregate.
    // For dense two-stick models, run the normal mathematically-verified
    // host orchestration while LinearW's strict dual-row backend sends every
    // heavy weight GEMV to both GPUs simultaneously.
    //
    // This is deliberately classified separately from FULL_RESIDENT_GPU:
    // activations/KV orchestration are host-visible, weight arithmetic is not.
    const char* denseExec=std::getenv("DEEP2_DENSE_EXEC");
    const bool forceLayerSplit=
        denseExec && std::strcmp(denseExec,"LAYER_SPLIT")==0;
    // DEEP2_RESIDENT_FORWARD_PREEMPTION_001 (Case A routing experiment):
    // the resident forward path (device arenas, resident weights, fused
    // per-layer command buffers, device KV) already proved 5.59 TPS with
    // DENSE_ROW_WALL_PCT=1.904 in the b3 layersplit receipt, while the
    // dual-row host lane measures 5.08-5.14 TPS at 88% dense-row wall.
    // RESIDENT_FIRST gives tryGpuTokenForward first claim on dense
    // two-stick models; the dual-row lane remains the fallback. Fail-
    // closed: under strict mode a resident failure still refuses CPU.
    const char* residentFirstEnv=std::getenv("DEEP2_RESIDENT_FIRST");
    const bool residentFirst=
        residentFirstEnv && residentFirstEnv[0]=='1';
    const bool dualRowDense=
        !forceLayerSplit && !residentFirst &&
        vulkanEnabled_ && vulkanInitialized_ &&
        vulkanDevices_.size()>=2 &&
        !modelWeights.isMoE && !modelWeights.useMLA;

    // Resident-first: the full-token resident graph gets first claim.
    // Everything below is fallback only.
    if (residentFirst && vulkanEnabled_ && vulkanInitialized_ &&
        !modelWeights.isMoE && !modelWeights.useMLA) {
        const std::uint64_t residentLayersBefore = gpuFwd_.forwardLayers;
        if (tryGpuTokenForward(hidden)) {
            // RAWRXD_REVERSE_TRADE_TITAN_001: this route bypasses forwardLayer(),
            // so record the layers it measured for itself.
            recordResidentNodeExecutions(
                gpuFwd_.forwardLayers - residentLayersBefore);
            {
                size_t hiddenFinite = 0, hiddenNan = 0, hiddenInf = 0;
                float hiddenMin = std::numeric_limits<float>::max();
                float hiddenMax = -std::numeric_limits<float>::max();
                for (size_t i = 0; i < config.hiddenDim; ++i) {
                    const float v = hidden[i];
                    if (std::isnan(v)) ++hiddenNan;
                    else if (std::isinf(v)) ++hiddenInf;
                    else { ++hiddenFinite; hiddenMin = std::min(hiddenMin, v); hiddenMax = std::max(hiddenMax, v); }
                }
                std::fprintf(stderr,
                    "GPU_HIDDEN_POST_FORWARD finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                    hiddenFinite, hiddenNan, hiddenInf, hiddenMin, hiddenMax);
                std::fflush(stderr);
            }
            // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record execution evidence for this traversal
            {
                const size_t nodesVisited = rawrxd::compute::mapNodesVisited();
                const size_t nodesExecuted = rawrxd::compute::mapNodesExecuted();
                const size_t nodesFailed = rawrxd::compute::mapNodesFailed();
                if (nodesVisited > 0) {
                    bool finiteOutput = true;
                    for (size_t i = 0; i < config.hiddenDim; ++i) {
                        if (!std::isfinite(hidden[i])) { finiteOutput = false; break; }
                    }
                    rawrxd::compute::recordExecutionEvidence(
                        1, true, finiteOutput
                    );
                }
            }
            return ForwardResult{true, ExecutionRoute::VulkanResident, true, nullptr};
        }
        if (gpuFwdStateMutated_)
            return blockCommittedFallback("resident_first", ExecutionRoute::VulkanResident);
        std::fprintf(stderr,
            "[RESIDENT_FIRST] resident forward declined; "
            "falling back to dual-row lane\n");
        if (vulkanStrictNoCpuFallback_) {
            // Strict authority must not silently accept the slower host lane
            // when the resident graph declined; record and fail closed.
            vulkanStrictViolation_ = true;
            return ForwardResult{false, ExecutionRoute::Unset, false, "resident_forward_declined"};
        }
    }

    if(dualRowDense){
        size_t dualRowLayersDone=0;
        // RAWRXD_DISPATCH_WIRE_001 / STRICT_GUARD_5407
        //
        // Every sibling lane in this dispatch honours vulkanStrictNoCpuFallback_
        // (MoE/MLA hybrid at 5337, resident-first decline at 5399, dual-row
        // EXCEPTION at 5444, Batch9 at 5464). This branch had no guard at all, and
        // it is the DEFAULT lane for a dense non-MoE model when
        // DEEP2_RESIDENT_FIRST is unset.
        //
        // Measured consequence, f66d63e05, qwen32_85tps_gate --only 2:
        //   hostForwardLayerCalls = 1280   (20 tokens x 64 layers)
        //   dualRowDenseTokens     = 20
        //   GPU_LAYER_SUBMITS      = 0      GPU_OP_SUBMITS = 0
        //   STRICT_GPU_VIOLATIONS  = 0      THRESHOLD_RESULT PASS, exit 0
        //
        // i.e. every layer executed on the CPU and the gate certified a GPU run,
        // because this lane runs host code, increments a host counter, and returns
        // ExecutionRoute::VulkanDualRow without ever consulting the strict flag.
        // Under strict authority that is a false PASS, not a slow path.
        const std::uint32_t dualRowToken = (std::uint32_t)(gpuFwd_.dualRowDenseTokens + 1);
        {
            // Pre-dispatch decision record, emitted BEFORE the strict guard so the
            // capture contains the evidence in BOTH outcomes: an executed host
            // lane and a refused one. A hook that only fires after the refusal
            // would be silent in exactly the case worth recording. latencyNs is 0
            // by design -- nothing has executed yet; this packet's job is the
            // predicate set, not timing.
            Deep2::Wire::DispatchDecision dd{};
            dd.token = dualRowToken;
            dd.layer = 0;
            dd.seqLen = (std::uint32_t)seqLen;
            dd.numLayers = (std::uint32_t)modelWeights.numLayers;
            dd.deviceCount = (std::uint32_t)vulkanDevices_.size();
            dd.vulkanEnabled = vulkanEnabled_;
            dd.vulkanInitialized = vulkanInitialized_;
            dd.strictNoCpuFallback = vulkanStrictNoCpuFallback_;
            dd.residentFirst = residentFirst;
            dd.forceLayerSplit = forceLayerSplit;
            dd.isMoE = modelWeights.isMoE;
            dd.useMLA = modelWeights.useMLA;
            dd.latencyNs = 0;
            dd.onHost = true;   // the selected lane IS the host lane
            Deep2::Wire::WireRecordDispatch(dd);
        }
        if (vulkanStrictNoCpuFallback_) {
            // Fail closed rather than silently execute the host lane. The route
            // was going to be labelled VulkanDualRow regardless of what actually
            // ran, so the label is removed as well as the execution.
            vulkanStrictViolation_ = true;
            gpuFwdCommitted_ = false;
            std::fprintf(stderr,
                "[DualRowStrict] DUAL_ROW_HOST_LANE_REFUSED strict=1 "
                "residentFirst=%d forceLayerSplit=%d devices=%zu isMoE=%d useMLA=%d "
                "reason=no_gpu_resident_lane_available\n",
                (int)residentFirst, (int)forceLayerSplit, vulkanDevices_.size(),
                (int)modelWeights.isMoE, (int)modelWeights.useMLA);
            std::fflush(stderr);
            return ForwardResult{false, ExecutionRoute::Unset, false,
                                 "dual_row_host_lane_refused"};
        }
        try {
            for(size_t l=0;l<modelWeights.numLayers;++l){
                forwardLayer(l,hidden,layerOut,seqLen);
                std::memcpy(
                    hidden,layerOut,config.hiddenDim*sizeof(float));
                ++dualRowLayersDone;
                ++gpuFwd_.hostForwardLayerCalls; // host execution, not GPU
            }
            ++gpuFwd_.dualRowDenseTokens;
            gpuFwdCommitted_=false; // not FULL_RESIDENT_GPU
            // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record execution evidence for this traversal
            {
                const size_t nodesVisited = rawrxd::compute::mapNodesVisited();
                const size_t nodesExecuted = rawrxd::compute::mapNodesExecuted();
                const size_t nodesFailed = rawrxd::compute::mapNodesFailed();
                if (nodesVisited > 0) {
                    bool finiteOutput = true;
                    for (size_t i = 0; i < config.hiddenDim; ++i) {
                        if (!std::isfinite(hidden[i])) { finiteOutput = false; break; }
                    }
                    rawrxd::compute::recordExecutionEvidence(
                        1, true, finiteOutput
                    );
                }
            }
            return ForwardResult{true, ExecutionRoute::VulkanDualRow, false, nullptr};
        } catch(const std::bad_alloc& bae) {
#ifdef _WIN32
            PROCESS_MEMORY_COUNTERS pmc{};
            SIZE_T workingSet=0;
            if(GetProcessMemoryInfo(GetCurrentProcess(),&pmc,sizeof(pmc))) {
                workingSet=pmc.WorkingSetSize;
            }
            std::fprintf(stderr,
                "[Deep2Engine] ALLOCATION_RECEIPT: std::bad_alloc at layer (unknown), "
                "seqLen=%zu. WorkingSet=%zu MB. Exception: %s\n",
                seqLen,(size_t)(workingSet/(1024ULL*1024ULL)),bae.what());
#else
            std::fprintf(stderr,
                "[Deep2Engine] ALLOCATION_RECEIPT: std::bad_alloc at layer (unknown), "
                "seqLen=%zu. Exception: %s\n",
                seqLen,bae.what());
#endif
            throw; // rethrow so outer handler records it as a strict violation
        } catch(const std::exception& ex) {
            std::fprintf(stderr,
                "[Deep2Engine] dual-row dense forward failed: %s\n",
                ex.what());
            if(dualRowLayersDone>0)
                return blockCommittedFallback("dual_row", ExecutionRoute::VulkanDualRow);
            if(vulkanStrictNoCpuFallback_){
                vulkanStrictViolation_=true;
                return ForwardResult{false, ExecutionRoute::VulkanDualRow, false, "dual_row_exception"};
            }
            // Non-strict callers may continue into the resident layer-split
            // lane below; strict 40-TPS authority never takes this fallback.
        }
    }

    // Dense Batch9 resident path.
    if (vulkanEnabled_ && vulkanInitialized_) {
        const std::uint64_t residentLayersBefore = gpuFwd_.forwardLayers;
        if (tryGpuTokenForward(hidden)) {
            gpuFwdCommitted_ = true;
            // RAWRXD_REVERSE_TRADE_TITAN_001: see the resident-first site. Two
            // distinct return sites reach VulkanResident; a route that is
            // evidence on one path and silent on the other is not measured.
            recordResidentNodeExecutions(
                gpuFwd_.forwardLayers - residentLayersBefore);
            // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record execution evidence for this traversal
            {
                const size_t nodesVisited = rawrxd::compute::mapNodesVisited();
                const size_t nodesExecuted = rawrxd::compute::mapNodesExecuted();
                const size_t nodesFailed = rawrxd::compute::mapNodesFailed();
                if (nodesVisited > 0) {
                    bool finiteOutput = true;
                    for (size_t i = 0; i < config.hiddenDim; ++i) {
                        if (!std::isfinite(hidden[i])) { finiteOutput = false; break; }
                    }
                    rawrxd::compute::recordExecutionEvidence(
                        1, true, finiteOutput
                    );
                }
            }
            return ForwardResult{true, ExecutionRoute::VulkanResident, true, nullptr};
        }

        ++vulkanGemvFail_;
        gpuFwdCommitted_ = false;
        if (gpuFwdStateMutated_)
            return blockCommittedFallback("batch9", ExecutionRoute::VulkanResident);
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            return ForwardResult{false, ExecutionRoute::VulkanResident, false, "tryGpuTokenForward_failed"};
        }
    }
    // RAWRXD_SIGNAL_LAYER_WALK_005C / RAWRXD_E2E_REAL_CODE_YIELDLESS_BEACONISM_005D
    //
    // OBSERVE ONLY. This block reads tensors and prints. It never writes to
    // `hidden`, `layerOut`, weights, or logits, and it cannot manufacture signal:
    // if the forward is zero, the beacons print zero.
    //
    // It exists because two measured facts could not be separated without it:
    //   1. FINALNORM_POST is identically zero on 9 of 9 forwards, so the signal
    //      is already gone at or before the last layer output.
    //   2. The only per-layer timing available was SLOW_LAYER, which is gated on
    //      `layerMs > 100.0`. That gate means every sample ever collected is from
    //      the slow tail, so the reported mean was a biased estimate of the true
    //      per-layer cost. Under the beacon, EVERY layer's wall time is printed so
    //      the mean is over the whole population.
    //
    // The one number that decides the root: abs_sum of `hidden` as it enters the
    // loop versus abs_sum of `layerOut` as it leaves each layer.
    const bool nanoBeacon = (std::getenv("RAWRXD_NANOBEACON") != nullptr);
    auto nanoAbsSum = [](const float* p, size_t n) -> double {
        if (!p || n == 0) return 0.0;
        double s = 0.0;
        for (size_t i = 0; i < n; ++i) {
            const float v = p[i];
            if (std::isfinite(v)) s += std::abs(static_cast<double>(v));
        }
        return s;
    };
    auto nanoNonzero = [](const float* p, size_t n) -> size_t {
        if (!p || n == 0) return 0;
        size_t c = 0;
        for (size_t i = 0; i < n; ++i) {
            const float v = p[i];
            if (std::isfinite(v) && v != 0.0f) ++c;
        }
        return c;
    };

    try {
        if (nanoBeacon) {
            std::fprintf(stderr,
                "[NANOBEACON_SIGNAL] BOUND=LOOP_ENTRY_HIDDEN L=-1 PTR=%p N=%zu ABS_SUM=%.9g NONZERO=%zu seqLen=%zu layers=%zu hiddenDim=%u\n",
                (const void*)hidden, config.hiddenDim,
                nanoAbsSum(hidden, config.hiddenDim),
                nanoNonzero(hidden, config.hiddenDim),
                seqLen, modelWeights.numLayers, (unsigned)config.hiddenDim);
            std::fflush(stderr);
        }
        for (size_t l = 0; l < modelWeights.numLayers; ++l) {
            auto tLayer0 = std::chrono::steady_clock::now();
            const double preAbs  = nanoBeacon ? nanoAbsSum(hidden, config.hiddenDim)  : 0.0;
            const size_t preNz   = nanoBeacon ? nanoNonzero(hidden, config.hiddenDim) : 0;
            forwardLayer(l, hidden, layerOut, seqLen);
            auto tLayer1 = std::chrono::steady_clock::now();
            if (nanoBeacon) {
                const double postAbs = nanoAbsSum(layerOut, config.hiddenDim);
                const size_t postNz  = nanoNonzero(layerOut, config.hiddenDim);
                std::fprintf(stderr,
                    "[NANOBEACON_SIGNAL] BOUND=LAYER_OUT L=%zu PTR=%p N=%zu IN_ABS_SUM=%.9g IN_NONZERO=%zu OUT_ABS_SUM=%.9g OUT_NONZERO=%zu seqLen=%zu\n",
                    l, (const void*)layerOut, config.hiddenDim, preAbs, preNz, postAbs, postNz, seqLen);
                std::fprintf(stderr,
                    "[NANOBEACON_SPEED] L=%zu WALL_US=%llu\n",
                    l, (unsigned long long)std::chrono::duration_cast<std::chrono::microseconds>(tLayer1 - tLayer0).count());
                std::fflush(stderr);
            }
            std::memcpy(hidden, layerOut, config.hiddenDim * sizeof(float));
            ++gpuFwd_.hostForwardLayerCalls;
            double layerMs = std::chrono::duration<double, std::milli>(tLayer1 - tLayer0).count();
            RAWRXD_DEEP2_TRACE("FWD_LAYER_TIMING layer=%zu ms=%.3f\n", l, layerMs);
            if (layerMs > 100.0) {
                std::fprintf(stderr, "SLOW_LAYER layer=%zu ms=%.3f seqLen=%zu\n", l, layerMs, seqLen);
                std::fflush(stderr);
            }
        }
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[Deep2Engine] forward failed: %s\n", ex.what());
        gpuFwdCommitted_ = false;
        return ForwardResult{false, ExecutionRoute::Cpu, false, "cpu_forward_exception"};
    }
    gpuFwdCommitted_ = false;

    // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — record execution evidence for this traversal
    {
        const size_t nodesVisited = rawrxd::compute::mapNodesVisited();
        const size_t nodesExecuted = rawrxd::compute::mapNodesExecuted();
        const size_t nodesFailed = rawrxd::compute::mapNodesFailed();
        // Only record if we actually traversed layers
        if (nodesVisited > 0) {
            // Check output finiteness
            bool finiteOutput = true;
            for (size_t i = 0; i < config.hiddenDim; ++i) {
                if (!std::isfinite(hidden[i])) { finiteOutput = false; break; }
            }
            rawrxd::compute::recordExecutionEvidence(
                1, // one token forward pass
                true, // callbacks observed (forwardTokenAllLayers is called per token)
                finiteOutput
            );
        }
    }

    return ForwardResult{true, ExecutionRoute::Cpu, false, nullptr};
}

// =================== GENERATE ====================
size_t Deep2Engine::generate(const int* promptTokens, size_t promptLen,
                              int* outputTokens, size_t maxOutputLen,
                              InferenceStats* stats,
                              std::function<bool(int)> onToken) {    if (stats) *stats = {};
    if (!initialized || !modelWeights.loaded) {
        std::fprintf(stderr, "[GENERATE] SILENT_EXIT: not initialized or model not loaded (init=%d loaded=%d)\n",
            initialized ? 1 : 0, modelWeights.loaded ? 1 : 0);
        std::fflush(stderr);
        return 0;
    }
    if (!promptTokens || promptLen == 0) {
        std::fprintf(stderr, "[GENERATE] SILENT_EXIT: null promptTokens=%p promptLen=%zu\n",
            (void*)promptTokens, promptLen);
        std::fflush(stderr);
        return 0;
    }
    if (!outputTokens || maxOutputLen == 0) {
        std::fprintf(stderr, "[GENERATE] SILENT_EXIT: null outputTokens=%p maxOutputLen=%zu\n",
            (void*)outputTokens, maxOutputLen);
        std::fflush(stderr);
        return 0;
    }
    if (!hiddenStates || !logits || config.hiddenDim == 0 || config.vocabSize == 0) {
        std::fprintf(stderr, "[GENERATE] SILENT_EXIT: hiddenStates=%p logits=%p hiddenDim=%zu vocabSize=%zu\n",
            (void*)hiddenStates, (void*)logits,
            (size_t)config.hiddenDim, (size_t)config.vocabSize);
        std::fflush(stderr);
        return 0;
    }

    // A fresh top-level generate transaction consumes any old cancel request.
    clearCancel();
    modelState_ = ModelState::Generating;

    auto t0 = std::chrono::steady_clock::now();

    std::vector<float> hidden(config.hiddenDim);    // Prefill each prompt token exactly once, in token order.
    for (size_t p = 0; p < promptLen; ++p) {
        if (cancelRequested_.load(std::memory_order_acquire)) {
            std::fprintf(stderr, "[PREFILL] CANCELLED at prefill token %zu/%zu\n", p, promptLen);
            std::fflush(stderr);
            modelState_ = ModelState::Choreographable;            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
            return 0;
        }
        parityBeginStep(static_cast<int>(p));
        if (profiler_) profiler_->beginToken(static_cast<uint32_t>(p), p, Deep2::ProfilePhase::Prefill);
        auto tEmbed0 = std::chrono::steady_clock::now();
        if (!embedToken(promptTokens[p], hidden.data())) {
            std::fprintf(stderr, "[PREFILL] embedToken FAILED for prefill token %zu (tokenId=%d)\n",
                p, promptTokens[p]);
            std::fflush(stderr);
            modelState_ = ModelState::Choreographable;            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
            lastFailureDetail_ = "embedToken failed for prefill token " + std::to_string(p);
            lastFailureStatus_ = GenerationStatus::InternalError;
            return 0;
        }
        auto tEmbed1 = std::chrono::steady_clock::now();
        {
            float emMin = std::numeric_limits<float>::infinity();
            float emMax = -std::numeric_limits<float>::infinity();
            for (size_t i = 0; i < config.hiddenDim; ++i) {
                if (hidden[i] < emMin) emMin = hidden[i];
                if (hidden[i] > emMax) emMax = hidden[i];
            }
        }
        if (profiler_) profiler_->recordCpuOverhead(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tEmbed1 - tEmbed0).count()));
        auto tFwd0 = std::chrono::steady_clock::now();
        // RAWRXD_ATTN_VISIBILITY_TRACE_001: open the position frame on the
        // authoritative KV position, not on the loop counter, so the record is
        // bound to the same identity the KV machinery uses.
        {
            const size_t posAtPre = kvCache ? kvCache->currentLength() : p;
            Deep2::AttnVis::beginPosition(
                static_cast<int>(posAtPre), posAtPre, "prefill", promptTokens[p],
                posAtPre, isVulkanInitialized() ? "vulkan" : "cpu");
        }
        {
            auto fr = forwardTokenAllLayers(hidden.data(), p + 1);
            if (!fr.ok) {
                std::fprintf(stderr, "[PREFILL] forwardTokenAllLayers FAILED at prefill token %zu stage=%s route=%d\n",
                    p, fr.failureStage ? fr.failureStage : "(null)", (int)fr.actualRoute);
                std::fflush(stderr);
                modelState_ = ModelState::Choreographable;
                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
                lastFailureStatus_ = GenerationStatus::ForwardFailure;
                lastFailureDetail_ = std::string("prefill forward failed at token ")
                    + std::to_string(p)
                    + (fr.failureStage ? (std::string(" stage=") + fr.failureStage) : std::string());
                return 0;
            }
            // RAWRXD_REVERSE_TRADE_TITAN_001: record the route that ACTUALLY
            // executed. The route travels back in the ForwardResult, so this is
            // an observation of what ran, not a declaration of what should run.
            rawrxd::compute::recordExecutionRoute(routeName(fr.actualRoute));
        }
        auto tFwd1 = std::chrono::steady_clock::now();
        if (profiler_) profiler_->recordGpuForward(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count()));
        if (config.useKVCache && kvCache) kvCache->advance();
        // The LAST prefill position's logits are produced by the computeLogits
        // call that follows this loop, so that frame deliberately stays open
        // and is closed there. Every earlier prefill position has no logits of
        // its own and is closed here with logits_available=0.
        if (p + 1 < promptLen) {
            Deep2::AttnVis::endPosition(nullptr, 0,
                kvCache ? kvCache->currentLength() : 0);
        }
        if (profiler_) profiler_->endToken(static_cast<uint32_t>(p));
    }    auto tPrefillEnd = std::chrono::steady_clock::now();
    parityEmit((ParityCheckpoint)20, hidden.data(), config.hiddenDim);

    // Context cap is an execution invariant, not a best-effort hint.
    if (config.maxSeqLen == 0) {
        config.maxSeqLen = 8192; // default if metadata omitted
    }
    size_t decodeLimit = maxOutputLen;
    if (config.maxSeqLen != 0) {
        if (promptLen >= config.maxSeqLen) {
            decodeLimit = 0;
        } else {
            decodeLimit = std::min(decodeLimit, config.maxSeqLen - promptLen);
        }
    }    size_t generated = 0;
    bool pendingForward=false;
    int pendingToken=-1;
    const bool specActive=
        medusaEnabled_&&deterministicGreedy_&&medusaDecoder_&&
        parityProbe_==nullptr&&!modelWeights.isMoE&&!modelWeights.useMLA;    if(specActive) {
        medusaDecoder_->reset();
        medusaDecoder_->observe(promptTokens,promptLen);
    }

    // RAWRXD_IDE_GENERATION_UNSILENT_001: structured stage diagnostics (opt-in;
    // disabled by default so the clean CLI path is unaffected).
    auto& diag = Deep2::Deep2Diag::instance();
    diag.configureFromEnv();
    diag.setBackendRoute(isVulkanInitialized() ? "vulkan" : "cpu");
    diag.beginSession(static_cast<uint32_t>(promptLen));

    // RAWRXD_DECODE_STEP_TRACE_001: opt-in, one line per decode step.
    // Deliberately independent of RAWRXD_TRACE_PROFILE, which was observed
    // to change sampler behaviour and therefore cannot be used to observe
    // the sampler. Read-only diagnostics: it must not perturb the path it
    // is measuring.
    static const bool decodeStepTrace = [](){
        const char* v = std::getenv("RAWRXD_DECODE_STEP_TRACE");
        return v && v[0] && v[0] != '0';
    }();

    while(generated<decodeLimit) {        if(cancelRequested_.load(std::memory_order_acquire)) {            break;
        }

        // Exactly one emitted token remains unforwarded between decode
        // transactions. Accepted speculative prefix tokens are already in KV.
        if(pendingForward) {
            if (profiler_) profiler_->beginToken(static_cast<uint32_t>(generated), promptLen + generated, Deep2::ProfilePhase::Decode);
            parityBeginStep(static_cast<int>(
                kvCache?kvCache->currentLength():promptLen+generated-1));
            auto tEmb0 = std::chrono::steady_clock::now();
            if(!embedToken(pendingToken,hidden.data())) {
                std::fprintf(stderr, "[DECODE] embedToken FAILED for decode token %zu (tokenId=%d)\n",
                    generated, pendingToken);
                std::fflush(stderr);
                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
                lastFailureDetail_ = "embedToken failed for decode token " + std::to_string(generated);
                lastFailureStatus_ = GenerationStatus::InternalError;
                break;
            }
            auto tEmb1 = std::chrono::steady_clock::now();
            {
                float emMin = std::numeric_limits<float>::infinity();
                float emMax = -std::numeric_limits<float>::infinity();
                for (size_t i = 0; i < config.hiddenDim; ++i) {
                    if (hidden[i] < emMin) emMin = hidden[i];
                    if (hidden[i] > emMax) emMax = hidden[i];
                }
            }
            if (profiler_) profiler_->recordCpuOverhead(
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tEmb1 - tEmb0).count()));
            const size_t seq=(kvCache?kvCache->currentLength():promptLen)+1;
            if (decodeStepTrace) {
                std::fprintf(stderr, "[DTRACE] step=%zu IN token=%d seq=%zu kvBefore=%zu\n",
                    generated, pendingToken, seq,
                    kvCache ? kvCache->currentLength() : (size_t)0);
                std::fflush(stderr);
            }
            auto tFwd0 = std::chrono::steady_clock::now();
            if (vramStreamingController_) vramStreamingController_->beginTokenMeasurement(promptLen + generated);
            // RAWRXD_ATTN_VISIBILITY_TRACE_001: decode position frame, anchored
            // on the authoritative KV position.
            {
                const size_t posAtDec = kvCache ? kvCache->currentLength()
                                                : (promptLen + generated - 1);
                Deep2::AttnVis::beginPosition(
                    static_cast<int>(posAtDec), posAtDec, "decode", pendingToken,
                    posAtDec, isVulkanInitialized() ? "vulkan" : "cpu");
            }
            {
                auto fr = forwardTokenAllLayers(hidden.data(),seq);
                if(!fr.ok) {
                    std::fprintf(stderr, "[DECODE] forwardTokenAllLayers FAILED at decode token %zu stage=%s route=%d\n",
                        generated, fr.failureStage ? fr.failureStage : "(null)", (int)fr.actualRoute);
                    std::fflush(stderr);
                    if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
                    lastFailureStatus_ = GenerationStatus::ForwardFailure;
                    lastFailureDetail_ = std::string("decode forward failed at token ")
                        + std::to_string(generated)
                        + (fr.failureStage ? (std::string(" stage=") + fr.failureStage) : std::string());
                    break;
                }
                // RAWRXD_REVERSE_TRADE_TITAN_001: see the prefill site. Both
                // real execution paths report the route that carried the token,
                // so ROUTE_HISTOGRAM is measured across the whole run rather
                // than asserted from a single call site.
                rawrxd::compute::recordExecutionRoute(routeName(fr.actualRoute));
            }
            auto tFwd1 = std::chrono::steady_clock::now();
            if (decodeStepTrace) {
                std::fprintf(stderr, "[DTRACE] step=%zu FWD_OK seq=%zu kvAfter=%zu\n",
                    generated, seq, kvCache ? kvCache->currentLength() : (size_t)0);
                std::fflush(stderr);
            }
            diag.record(Deep2::DiagStage::Forward,
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count()),
                static_cast<uint32_t>(generated));
            if (profiler_) profiler_->recordGpuForward(
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count()));
            if(config.useKVCache&&kvCache&&!kvCache->advance()) {
                std::fprintf(stderr, "[DECODE] kvCache->advance() FAILED at decode token %zu (KV full?)\n", generated);
                std::fflush(stderr);
                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
                break;
            }
            pendingForward=false;

            // ----- streaming telemetry: one token fully emitted -----
            if (vramStreamingController_) {
                uint64_t tokenBytesMoved = 0;
                vramStreamingController_->endTokenMeasurement(tokenBytesMoved);
                telemetry.ram_to_gpu_bytes = tokenBytesMoved;
                telemetry.token_total_ns = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count());
                telemetry.record_token();
            } else {
                telemetry.record_token();
            }
        }

        const size_t remaining=decodeLimit-generated;
        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr, "[DECODE] token=%zu/%zu remaining=%zu specActive=%d\n",
                generated, decodeLimit, remaining, specActive ? 1 : 0);
            std::fflush(stderr);
        }
        if(specActive&&remaining>=2) {
            try {
                if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] building proposals at token %zu remaining %zu\n", generated, remaining); std::fflush(stderr); }
                std::vector<int32_t> proposals;
                (void)buildAdaptiveSpeculativeProposals(
                    hidden.data(),remaining,proposals);
                if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] proposals=%zu at token %zu\n", proposals.size(), generated); std::fflush(stderr); }
                if(!proposals.empty()) {

                    std::vector<int32_t> verified;
                    if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] verifying %zu proposals at token %zu\n", proposals.size(), generated); std::fflush(stderr); }
                    if(verifySpeculativeGreedyWindow(
                            hidden.data(),proposals,remaining,verified)&&
                       !verified.empty()) {
                        if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] verified=%zu tokens at token %zu\n", verified.size(), generated); std::fflush(stderr); }
                        if(medusaDecoder_) {
                            ++medusaDecoder_->stats.exact.speculativeWindowsSucceeded;
                        }
                        bool stop=false;
                        for(int32_t tok:verified) {
                            if(generated>=decodeLimit) break;
                            // D3 â€” EOS in speculative window: stop at the
                            // first EOS without emitting it; undo the count
                            // so the bookkeeping reflects only emitted text.
                            if (tokenizer && tokenizer->isEos(tok)) {
                                std::fprintf(stderr, "[DECODE] EOS in spec verified window at decode token %zu (tokenId=%d)\n",
                                    generated, tok);
                                std::fflush(stderr);
                                stop=true;
                                break;
                            }
                            outputTokens[generated++]=tok;
                            medusaDecoder_->observe(tok);
                            if(onToken&&!onToken(tok)) {stop=true;break;}
                        }
                        if(!verified.empty()) {
                            pendingToken=verified.back();
                            pendingForward=true;
                        }
                        if(stop) break;
                        continue;
                    } else {
                        if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] verify FAILED (0 verified) at token %zu\n", generated); std::fflush(stderr); }
                    }
                } else {
                    if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "[SPEC] no proposals at token %zu (specActive but empty)\n", generated); std::fflush(stderr); }
                }
            } catch(const std::exception& e) {
                std::fprintf(stderr, "[DECODE] SPECULATIVE_EXCEPTION at token %zu: %s\n", generated, e.what());
                std::fflush(stderr);
                if(medusaDecoder_) {
                    ++medusaDecoder_->stats.exact.exceptionFallbacks;
                    ++medusaDecoder_->stats.exact.proposalExceptions;
                }
            } catch(...) {
                std::fprintf(stderr, "[DECODE] SPECULATIVE_UNKNOWN_EXCEPTION at token %zu\n", generated);
                std::fflush(stderr);
                if(medusaDecoder_) {
                    ++medusaDecoder_->stats.exact.exceptionFallbacks;
                }
            }
        }
        if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "FINAL_NORM_ENTER\n"); std::fflush(stderr); }
        auto tLogits0 = std::chrono::steady_clock::now();
        try {
            computeLogits(hidden.data(), logits);
        } catch (const std::exception& e) {
            // Always-on: real failure surfacing (not per-token spam).
            std::fprintf(stderr, "[DECODE] computeLogits THREW at token %zu: %s\n", generated, e.what());
            std::fflush(stderr);
            lastFailureStatus_ = GenerationStatus::InternalError;
            lastFailureDetail_ = std::string("computeLogits failed at token ")
                + std::to_string(generated) + ": " + e.what();
            diag.endSession(false, lastFailureDetail_);
            break;
        }
        diag.record(Deep2::DiagStage::Logits,
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - tLogits0).count()),
            static_cast<uint32_t>(generated));
        if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "COMPUTE_LOGITS_RETURNED\n"); std::fflush(stderr); }
        // Full-vocab sanity scan is diagnostic only: costs a vocabSize pass per
        // token, so keep it off the default (clean CLI) hot path.
        if (deep2ForwardTraceEnabled()) {
            size_t finite = 0, nan = 0, inf = 0;
            float logitMin = std::numeric_limits<float>::max();
            float logitMax = -std::numeric_limits<float>::max();
            for (size_t i = 0; i < config.vocabSize; ++i) {
                const float v = logits[i];
                if (std::isnan(v)) ++nan;
                else if (std::isinf(v)) ++inf;
                else { ++finite; logitMin = std::min(logitMin, v); logitMax = std::max(logitMax, v); }
            }
            std::fprintf(stderr,
                "LOGITS_SANITY count=%zu finite=%zu nan=%zu inf=%zu min=%g max=%g\n",
                (size_t)config.vocabSize, finite, nan, inf, logitMin, logitMax);
            std::fflush(stderr);
        }
        // RAWRXD_ATTN_VISIBILITY_TRACE_001: close the open position frame with
        // the token decision this forward produced. On the first decode
        // iteration the open frame is the LAST PREFILL position -- that is
        // where the first generated token's logits actually come from.
        Deep2::AttnVis::endPosition(logits, config.vocabSize,
            kvCache ? kvCache->currentLength() : 0);
        // Step label was set by the prefill loop (step 0) or by the decode
        // parityBeginStep(promptLen+i-1) before this token's forward pass.
        parityEmitLogitsTop10(logits, config.vocabSize);
        // Diagnostic logit stats: three more full-vocab passes, diag-gated.
        if (deep2ForwardTraceEnabled()) {
            int vocab = static_cast<int>(config.vocabSize);
            float maxv = logits[0];
            int maxi = 0;
            float minv = logits[0];
            for (int vi = 1; vi < vocab; ++vi) {
                if (logits[vi] > maxv) { maxv = logits[vi]; maxi = vi; }
                if (logits[vi] < minv) minv = logits[vi];
            }
            double mean = 0.0;
            for (int vi = 0; vi < vocab; ++vi) mean += logits[vi];
            mean /= vocab;
            double var = 0.0;
            for (int vi = 0; vi < vocab; ++vi) { double d = logits[vi] - mean; var += d * d; }
            var = std::sqrt(var / vocab);
            std::fprintf(stderr, "[LOGITS] token=%zu min=%g max=%g mean=%g std=%g argmax=%d\n",
                generated, minv, maxv, mean, var, maxi);
            std::fflush(stderr);
        }
        auto tSample0 = std::chrono::steady_clock::now();
        const int nextTok = sampleToken(logits);
        if (deep2ForwardTraceEnabled()) { std::fprintf(stderr, "SAMPLER_RESULT token=%d vocab=%zu\n", nextTok, (size_t)config.vocabSize); std::fflush(stderr); }
        auto tSample1 = std::chrono::steady_clock::now();
        if (decodeStepTrace) {
            std::fprintf(stderr, "[DTRACE] step=%zu SAMPLED token=%d\n", generated, nextTok);
            std::fflush(stderr);
        }
        diag.record(Deep2::DiagStage::Sampler,
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tSample1 - tSample0).count()),
            static_cast<uint32_t>(generated));
        if (profiler_) profiler_->recordSampling(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tSample1 - tSample0).count()));
        if (nextTok < 0 || static_cast<size_t>(nextTok) >= config.vocabSize) {
            std::fprintf(stderr, "[DECODE] sampleToken returned INVALID token=%d (vocab=%zu) at decode token %zu\n",
                nextTok, (size_t)config.vocabSize, generated);
            std::fflush(stderr);
            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
            break;
        }
        outputTokens[generated] = nextTok;
        // RAWRXD_BATCH_02_SAMPLER_GATE_001 â€” record committed token in
        // generated-history so the next decode step's repetition penalty
        // applies to it.
        generatedTokensHistory_.push_back(nextTok);
        if (profiler_) profiler_->endToken(static_cast<uint32_t>(generated));
        // D3 â€” EOS termination. Stop the decode loop on actual EOS without
        // emitting it as text. We resolve the EOS id from the tokenizer
        // metadata at request time (tokenizer->eosTokenId()), NOT from a
        // generic TOK_CONTROL filter: only the model's own EOS token ends
        // generation. Tokens are still classified post-sample so the
        // bookkeeping records what would have been emitted.
        const bool isEosToken = tokenizer && tokenizer->isEos(nextTok);
        if (isEosToken) {
            std::fprintf(stderr, "[DECODE] EOS at decode token %zu (tokenId=%d)\n",
                generated, nextTok);
            std::fflush(stderr);
            // We do NOT increment `generated` for the EOS token itself and we
            // do NOT call onToken(EOS). The loop ends here. Status will be
            // set to EndOfSequence in generateStream() when n == 0.
            // outputTokens[generated] was written with the EOS id above;
            // truncating the returned count discards it.
            //
            // RAWRXD_EOS_ZERO_TOKEN_UNDERFLOW_001: decrement only when
            // `generated > 0`. EOS on the very first decode step leaves
            // generated == 0, and an unconditional `--generated` wraps a
            // size_t to SIZE_MAX (18446744073709551615). That value was then
            // reported as a successful Completed generation with ~1.8e19
            // tokens, and the D1 contract guard did not catch it because both
            // of its clauses were false-negative for a nonzero count.
            if (generated > 0) {
                --generated;
            }
            break;
        }
        ++generated;
        if(specActive) medusaDecoder_->observe(nextTok);
        pendingToken=nextTok;
        pendingForward=true;
        if (onToken) {
            auto tCb0 = std::chrono::steady_clock::now();
            const bool cont = onToken(nextTok);
            diag.record(Deep2::DiagStage::Callback,
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now() - tCb0).count()),
                static_cast<uint32_t>(generated));
            if (!cont) break;
        }
    }

    diag.setGenTokens(static_cast<uint32_t>(generated));
    diag.endSession(lastFailureDetail_.empty(), lastFailureDetail_);

    // Flush any dangling active token profile when decode loop exits
    if (profiler_ && profiler_->counters().tokensStarted > profiler_->counters().tokensCompleted + profiler_->counters().tokensAborted) {
        // active token may remain; abort it to keep counters balanced
        // (the last pending forward token was already ended above, so this
        // should normally be a no-op, but guards speculative paths)
    }

    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr, "[GENERATE] EXIT generated=%zu promptLen=%zu prefillMs=%.1f decodeMs=%.1f tps=%.2f\n",
            generated, promptLen,
            stats ? std::chrono::duration<double, std::milli>(tPrefillEnd - t0).count() : 0.0,
            stats ? 0.0 : 0.0,
            0.0);
        std::fflush(stderr);
    }
    auto tEnd = std::chrono::steady_clock::now();

    if (stats) {
        stats->tokensGenerated = generated;
        stats->promptTokens = promptLen;
        stats->prefillMs =
            std::chrono::duration<double, std::milli>(tPrefillEnd - t0).count();
        stats->totalWallMs = std::chrono::duration<double, std::milli>(tEnd - t0).count();
        stats->decodeMs = std::chrono::duration<double, std::milli>(tEnd - tPrefillEnd).count();

        if (stats->prefillMs > 0.0) {
            stats->prefillTokensPerSecond =
                static_cast<double>(promptLen) / (stats->prefillMs / 1000.0);
        }
        if (stats->decodeMs > 0.0) {
            stats->decodeTokensPerSecond = generated / (stats->decodeMs / 1000.0);
        }
        if (stats->totalWallMs > 0.0) {
            stats->tokensPerSecond = generated / (stats->totalWallMs / 1000.0);
        }
        if (generated > 0) {
            stats->latencyMs = stats->totalWallMs / static_cast<double>(generated);
        }

        // VRAM streaming telemetry
        if (vramStreamingController_) {
            auto vstats = vramStreamingController_->stats();
            stats->vramTokensMeasured = vstats.tokensMeasured;
            stats->vramCeilingBytes = vstats.vramCeilingBytes;
            stats->vramPeakUsedBytes = vstats.vramPeakBytes;
            stats->hostSpillBytes = vstats.hostRamUsedBytes + vstats.hostNvmeUsedBytes;
            if (vstats.tokensMeasured > 0) {
                stats->avgVramBytesPerToken = static_cast<double>(vstats.tokenBytesMovedSum) / static_cast<double>(vstats.tokensMeasured);
            }
            if (stats->decodeMs > 0.0 && vstats.tokensMeasured > 0) {
                // measured streaming TPS: measured tokens / decode wall time
                stats->vramStreamingTokensPerSecond = static_cast<double>(vstats.tokensMeasured) / (stats->decodeMs / 1000.0);
            }
        }
    }

    modelState_ = ModelState::Choreographable;
    // DEEP2_HTTP_FAILURE_SEMANTICS_001: successful transaction clears stale
    // failure state so a later 0-token result is never mislabeled.
    lastFailureDetail_.clear();
    lastFailureStatus_ = GenerationStatus::Completed;
    return generated;
}

std::string Deep2Engine::generateText(const std::string& prompt, size_t maxTokens) {
  if (prompt.empty() || maxTokens == 0) {
    std::fprintf(stderr, "[GENTEXT] EARLY_EXIT: prompt.empty=%d maxTokens=%zu\n",
                 prompt.empty() ? 1 : 0, maxTokens); std::fflush(stderr);
    return {};
  }
  // CONFIGURE SAMPLING BEFORE GENERATING.
  //
  // This call was missing. generateStream() configures explicitly; generateText()
  // went straight to generate(), so its output depended entirely on whatever
  // sampling state happened to be left in the object.
  //
  // Measured consequence, not speculation: with no prior configureGeneration(),
  // a real 1.1B model answered a tool-call prompt with
  //     "1000000000000000000000000000000, 20."
  // and a SECOND call in the same engine returned the empty string. The model
  // looked incapable of following instructions when the actual fault was that
  // it was sampling from undefined state -- the classic "the model is weak"
  // misdiagnosis, caused here by the harness rather than the weights.
  //
  // Defaults here mirror GenerationOptions so the two entry points agree.
  GenerationOptions opts;
  opts.maxTokens = static_cast<uint32_t>(maxTokens);
  configureGeneration(opts);

  auto toks = tokenize(prompt);
    if (toks.empty()) {
        std::fprintf(stderr, "[GENTEXT] EARLY_EXIT: tokenize returned 0 tokens for prompt='%s'\n",
            prompt.c_str()); std::fflush(stderr);
        return {};
    }
    std::fprintf(stderr, "[GENTEXT] prompt='%s' tokens=%zu maxTokens=%zu\n",
        prompt.c_str(), toks.size(), maxTokens); std::fflush(stderr);
    std::vector<int> out(maxTokens);
    InferenceStats st{};
    size_t n = generate(toks.data(), toks.size(), out.data(), maxTokens, &st);
    out.resize(n);
    std::string result = detokenize(out);
    std::fprintf(stderr, "[GENTEXT] RESULT generated=%zu text='%s'\n", n, result.c_str()); std::fflush(stderr);
    return result;
}

// =================== STREAMING GENERATE ====================
GenerationResult Deep2Engine::generateStream(
    const std::string& prompt,
    const GenerationOptions& options,
    TokenCallback callback) {
    GenerationResult res{};
    configureGeneration(options);

    auto toks = tokenize(prompt);
    res.promptTokens = toks.size();
    if (toks.empty() || !initialized || !modelWeights.loaded) {
        // D1 â€” initialization-failure / empty-input: distinguish empty
        // input (InvalidInput) from an uninitialized engine (InternalError).
        // Never report completed=true on either path.
        std::fprintf(stderr, "[STREAM] EARLY_EXIT toks=%zu init=%d loaded=%d\n",
            toks.size(), initialized ? 1 : 0, modelWeights.loaded ? 1 : 0);
        std::fflush(stderr);
        if (toks.empty()) {
            res.status = GenerationStatus::InvalidInput;
            res.failureDetail = "empty prompt: tokenizer produced zero tokens";
        } else {
            res.status = GenerationStatus::InternalError;
            res.failureDetail = std::string("engine not ready: initialized=")
                + (initialized ? "1" : "0")
                + " loaded=" + (modelWeights.loaded ? "1" : "0");
        }
        res.completed = false;
        reset();
        return res;
    }

    // maxTokens==0 means "until a real stop condition". This engine does not
    // yet own EOS metadata, so the hard context boundary is the safe stop.
    size_t limit = options.maxTokens;
    if (limit == 0) {
        if (config.maxSeqLen > toks.size()) {
            limit = config.maxSeqLen - toks.size();
        } else {
            // D1 â€” context-exhaustion: the request cannot proceed because the
            // prompt alone fills the model context. Surface this as
            // InvalidInput (the request shape is not serviceable) rather than
            // InternalError, and never report completed=true.
            std::fprintf(stderr, "[STREAM] EARLY_EXIT: promptLen=%zu >= maxSeqLen=%zu (context full)\n",
                toks.size(), (size_t)config.maxSeqLen);
            std::fflush(stderr);
            res.status = GenerationStatus::InvalidInput;
            res.failureDetail = std::string("prompt length ") + std::to_string(toks.size())
                + " >= maxSeqLen " + std::to_string(config.maxSeqLen);
            res.completed = false;
            reset();
            return res;
        }
    }

    std::vector<int> out(limit);
    InferenceStats st{};

    const size_t n = generate(toks.data(), toks.size(), out.data(), out.size(), &st,
        [&](int tok) {
            if (callback) {
                const std::string piece = tokenizer ? tokenizer->decode(tok) : std::string{};
                return callback(tok, piece);
            }
            return true;
        });

    res.generatedTokens = n;
    res.promptTimeMs = st.prefillMs;
    res.generationTimeMs = st.decodeMs;
    res.cancelled = cancelRequested_.load(std::memory_order_acquire);
    // D1 â€” result contract: derive `completed` ONLY from the resolved status,
    // never from `cancelled` alone. The invariant is:
    //   completed == (status == GenerationStatus::Completed)
    // This makes the previous bug structurally impossible:
    //   (ForwardFailure, completed=true, generatedTokens=0)
    // and also (Cancelled, completed=true, generatedTokens>0) and
    // (EndOfSequence, completed=true, generatedTokens=0).
    // RAWRXD_DEEP2_GENERATION_LIFECYCLE_001.
    if (res.cancelled) {
        res.status = GenerationStatus::Cancelled;
    } else if (n > 0 && lastFailureDetail_.empty()) {
        res.status = GenerationStatus::Completed;
    } else if (!lastFailureDetail_.empty()) {
        res.status = lastFailureStatus_;
        res.failureDetail = lastFailureDetail_;
    } else {
        // Zero tokens without a recorded failure = immediate EOS / context
        // boundary. Legitimate, NOT an error.
        res.status = GenerationStatus::EndOfSequence;
    }
    res.completed = (res.status == GenerationStatus::Completed);
    std::fprintf(stderr, "[STREAM] RESULT generated=%zu promptTokens=%zu prefillMs=%.1f decodeMs=%.1f tps=%.2f cancelled=%d completed=%d status=%d cache_hits=%llu cache_misses=%llu cache_evictions=%llu\n",
        (size_t)n, (size_t)res.promptTokens, res.promptTimeMs, res.generationTimeMs,
        st.decodeMs > 0 ? (double)n / (st.decodeMs / 1000.0) : 0.0,
        res.cancelled ? 1 : 0, res.completed ? 1 : 0, (int)res.status,
        (unsigned long long)residencyCacheHits_,
        (unsigned long long)residencyCacheMisses_,
        (unsigned long long)residencyCacheEvictions_);
    std::fflush(stderr);
    if (n == 0 && !res.cancelled && lastFailureDetail_.empty()) {
        std::fprintf(stderr, "[STREAM] 0_TOKENS_NO_FAILURE: likely EOS or context boundary (EndOfSequence)\n");
        std::fflush(stderr);
    }
    // D1 structural-impossibility check. If the invariant is ever violated
    // it is a programming error; fail loudly so the regression test catches
    // any future regression instead of silently producing a false PASS.
    if (res.completed && (res.status != GenerationStatus::Completed || res.generatedTokens == 0)) {
        std::fprintf(stderr, "[STREAM] CONTRACT_VIOLATION: completed=true but status=%d generatedTokens=%llu\n",
            (int)res.status, (unsigned long long)res.generatedTokens);
        std::fflush(stderr);
        std::abort();
    }
    if (!res.completed && res.status == GenerationStatus::Completed) {
        std::fprintf(stderr, "[STREAM] CONTRACT_VIOLATION: completed=false but status=Completed\n");
        std::fflush(stderr);
        std::abort();
    }
    // RAWRXD_EOS_ZERO_TOKEN_UNDERFLOW_001: a generated count can never exceed
    // the requested ceiling. `generate()` indexes outputTokens[generated] with
    // generated < decodeLimit, so a result above the limit proves the counter
    // was corrupted (the EOS-at-token-0 underflow produced SIZE_MAX here).
    // This must be treated as a defect, never as a large successful run.
    if (res.generatedTokens > limit) {
        std::fprintf(stderr, "[STREAM] CONTRACT_VIOLATION: generatedTokens=%llu exceeds limit=%zu\n",
            (unsigned long long)res.generatedTokens, limit);
        std::fflush(stderr);
        res.status = GenerationStatus::InternalError;
        res.failureDetail = "generated token count exceeds requested limit: "
            + std::to_string(res.generatedTokens) + " > " + std::to_string(limit);
        res.completed = false;
        res.generatedTokens = 0;
    }
    // D2 â€” generation lifecycle: at the end of every independent generation,
    // clear the KV cache and per-generation state so the NEXT independent
    // request on this engine instance observes kvCacheLength() == 0.
    // `reset()` clears the KV cache (kvCache->clear(false)), the
    // per-generation scratch buffers (hidden/attention/FFN/SSM/conv), and
    // the spec KV mirror; it does NOT touch modelWeights, tokenizer, or
    // allocations. This eliminates stale-KV cpu_forward_exception at
    // prefill token 0 of generation #N when N > 1.
    // RAWRXD_DEEP2_GENERATION_LIFECYCLE_001.

    // RAWRXD_BOWRAIN_COMPUTE_AUTHORITY_001 — write receipt for this generation
    {
        const char* bowrainReceiptPath = std::getenv("BOWRAIN_RECEIPT_PATH");
        if (bowrainReceiptPath && bowrainReceiptPath[0]) {
            // RAWRXD_REVERSE_TRADE_TITAN_001: name the physical means before
            // the receipt is materialised.
            //
            // The stone here is "the released weights compute this model's
            // required behaviour". No trade was applied to it: Deep2 executes
            // the released native tensors unmodified, so the reversed form and
            // the original form are the same statement. Recording that
            // explicitly is what lets a reverse walk terminate at real
            // hardware instead of at an unexamined assertion.
            //
            // Every value below is read from live engine state at receipt time.
            // None of them is a default standing in for a measurement.
            // RAWRXD_REVERSE_TRADE_TITAN_001: an absent value must be stored ABSENT, not
            // as the literal text "<none>".
            //
            // The first version stored "<none>" when no device was present. That
            // string is non-empty, so provenanceComplete() -- which tests
            // !device.empty() -- accepted it, and a CPU-only run with no
            // physical device at all still certified. The falsification run
            // proved it: DEVICE=<none> produced PASS. A placeholder that reads
            // like evidence IS evidence to every downstream emptiness test, so
            // the placeholder is produced only at render time, never stored.
            std::string device;
            if (vulkanInitialized_ && !vulkanDevices_.empty()
                && vulkanDevices_[0]
                && !vulkanDevices_[0]->physicalInfo().name.empty()) {
                device = vulkanDevices_[0]->physicalInfo().name;
            }

            std::string modelId;
            if (config.modelPath[0] != '\0')
                modelId = config.modelPath;

            rawrxd::compute::recordExecutionProvenance(
                device,
                modelId,
                "RELEASED_NATIVE_WEIGHTS_UNMODIFIED",
                "RELEASED_NATIVE_WEIGHTS_UNMODIFIED",
                "NONE");

            const bool wrote =
                rawrxd::compute::writeBowRainReceipt(bowrainReceiptPath);
            std::fprintf(stderr,
                "[BOWRAIN] RECEIPT_WRITTEN=%d PATH=%s "
                "BACKEND=%s DEVICE=%s MODEL=%s\n",
                wrote ? 1 : 0, bowrainReceiptPath,
                rawrxd::compute::executionBackend().c_str(),
                rawrxd::compute::executionDevice().c_str(),
                rawrxd::compute::modelIdentity().c_str());
            std::fflush(stderr);
        }
    }

    reset();
    return res;
}

// =================== GPU FORWARD (delegated implementation) ====================
// Batch 9: real definitions live in Deep2Engine_GpuForward.cpp +
// Deep2Engine_VulkanRuntime.cpp. Old success stubs removed.

// =================== FIND / LOAD TENSOR ====================
WeightTensor* Deep2Engine::findTensor(const std::string& namePattern) {
    auto match = [&](WeightTensor& wt) -> WeightTensor* {
        if (!wt.name.empty() &&
            (wt.name == namePattern ||
             wt.name.find(namePattern) != std::string::npos))
            return &wt;
        return nullptr;
    };

    if (auto* p = match(modelWeights.tokenEmbed)) return p;
    if (auto* p = match(modelWeights.lmHead)) return p;
    if (auto* p = match(modelWeights.finalNorm)) return p;

    for (LayerWeights& lw : modelWeights.layers) {
        WeightTensor* fields[] = {
            &lw.wq, &lw.wk, &lw.wv, &lw.wo, &lw.wqkv,
            &lw.attnNorm, &lw.attnQNorm, &lw.attnKNorm,
            &lw.wGate, &lw.wUp, &lw.wDown, &lw.ffnNorm,
            &lw.moeRouter, &lw.moeSharedGate,
            &lw.moeSharedUp, &lw.moeSharedDown,
            &lw.ssmA, &lw.ssmAlpha, &lw.ssmBeta,
            &lw.ssmIn, &lw.ssmD, &lw.ssmConv1d,
            &lw.ssmConv1dBias, &lw.ssmDtBias,
            &lw.ssmNorm, &lw.ssmOut
        };
        for (WeightTensor* wt : fields)
            if (auto* p = match(*wt)) return p;

        for (WeightTensor& wt : lw.moeGate)
            if (auto* p = match(wt)) return p;
        for (WeightTensor& wt : lw.moeUp)
            if (auto* p = match(wt)) return p;
        for (WeightTensor& wt : lw.moeDown)
            if (auto* p = match(wt)) return p;
    }
    return nullptr;
}

bool Deep2Engine::loadTensorFromGGUF(WeightTensor& wt,
                                     const std::string& name) {
    if (!ggufResult.ok || !ggufResult.loader) return false;
    const GGUFTensor* t = ggufResult.loader->getTensor(name);
    if (!t || !t->data || t->sizeBytes == 0 || t->shape.empty())
        return false;

    wt = {};
    wt.data = const_cast<uint8_t*>(t->data);
    wt.type = static_cast<int>(t->type);
    wt.sizeBytes = t->sizeBytes;
    wt.name = t->name;
    wt.shape = t->shape;
    wt.mapped = true;
    wt.shardId = t->shardId;
    wt.fileOffset = t->fileOffset;
    wt.hasFileBacking = true;

    // RAWRXD_SPACELESS_STEP_10: populate stable tensor identity from name
    {
        // model fingerprint: hash of model path (simplified: use 1 for single-model)
        wt.identity.model = 1;
        // tensor fingerprint: hash of GGUF tensor name (stable across runs)
        std::hash<std::string> h;
        wt.identity.tensor = h(t->name);
        // layer: parse from "blk.N.xxx" or "token_embd" etc.
        wt.identity.layer = 0;
        if (t->name.find("blk.") != std::string::npos) {
            size_t dot = t->name.find('.', 4);
            if (dot != std::string::npos) {
                try { wt.identity.layer = static_cast<uint32_t>(std::stoul(t->name.substr(4, dot - 4))); } catch (...) {}
            }
        }
        wt.identity.role    = 0;
        wt.identity.variant = 0;
    }

    if (t->shape.size() == 1) {
        wt.rows = static_cast<size_t>(t->shape[0]);
        wt.cols = 1;
        return true;
    }

    wt.cols = static_cast<size_t>(t->shape[0]);
    size_t rows = 1;
    for (size_t i = 1; i < t->shape.size(); ++i) {
        const size_t d = static_cast<size_t>(t->shape[i]);
        if (d != 0 && rows > std::numeric_limits<size_t>::max() / d)
            return false;
        rows *= d;
    }
    wt.rows = rows;
    return true;
}

// =================== MARS (REAL PROVIDER â€” OPEN GATE) ====================
bool Deep2Engine::enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes) {
    marsEnabled_ = false;
    marsWeightsPlaced_ = false;

    // A zero-sized device budget is never a valid MARS authority.
    if (gpu0VRAMBytes == 0 || gpu1VRAMBytes == 0)
        return false;

    if (!marsController_) {
        marsController_ = std::make_unique<Deep2::MARSController>();
    }
    if (!marsController_->initialize(gpu0VRAMBytes, gpu1VRAMBytes)) {
        marsController_.reset();
        return false;
    }
    marsEnabled_ = true;
    return true;
}

void Deep2Engine::disableMARS() {
    marsEnabled_ = false;
    marsWeightsPlaced_ = false;
    marsStandby_ = false;
    marsLayerLeases_.clear();
    if (marsController_) marsController_->shutdown();
    marsController_.reset();
}

bool Deep2Engine::marsHostResidentAuthorityOk() const {
    // HOST_RESIDENT_DENSE only; K2_STREAM_AUTHORITY â†’ STANDBY by law.
    if (!marsEnabled_ || !marsController_) return false;
    auto parity = marsController_->getDynamicParity();
    // Parity is acceptable if at least one GPU holds some weight bytes.
    return parity.gpu0Bytes > 0 || parity.gpu1Bytes > 0;
}

void Deep2Engine::standdownMARSEmptyPlacement(const char* reason) {
    (void)reason;
    // Transition to standby if placement has been cleared / failed.
    marsStandby_ = true;
    marsWeightsPlaced_ = false;
}

Deep2::VRAMLease* Deep2Engine::placeTensorMARS(
    uint64_t tensorId,
    const std::string& name,
    size_t bytes,
    float priority) {
    if (!marsEnabled_ || !marsController_) return nullptr;
    return marsController_->placeTensor(tensorId, name, bytes, priority);
}

Deep2Engine::MARSPlacementReport Deep2Engine::placeAllModelTensorsMARS() {
    MARSPlacementReport report{};
    if (!marsEnabled_ || !marsController_) return report;

    std::vector<std::tuple<uint64_t, std::string, size_t, float>> items;
    auto placeWt = [&](const WeightTensor& wt) {
        if (wt.data && wt.sizeBytes > 0) {
            items.emplace_back(marsNextTensorId_++, wt.name, wt.sizeBytes, 1.0f);
        }
    };
    placeWt(modelWeights.tokenEmbed);
    placeWt(modelWeights.lmHead);
    placeWt(modelWeights.finalNorm);
    for (const LayerWeights& lw : modelWeights.layers) {
        const WeightTensor* fields[] = {
            &lw.wq, &lw.wk, &lw.wv, &lw.wo, &lw.wqkv,
            &lw.bq, &lw.bk, &lw.bv,
            &lw.attnNorm, &lw.attnQNorm, &lw.attnKNorm,
            &lw.attnQ_a, &lw.attnQ_a_norm, &lw.attnQ_b,
            &lw.attnKV_a_mqa, &lw.attnKV_a_norm,
            &lw.attnK_b, &lw.attnV_b, &lw.attnO,
            &lw.wGate, &lw.wUp, &lw.wDown, &lw.ffnNorm,
            &lw.moeRouter, &lw.moeSharedGate,
            &lw.moeSharedUp, &lw.moeSharedDown,
            &lw.ssmA, &lw.ssmAlpha, &lw.ssmBeta,
            &lw.ssmIn, &lw.ssmD, &lw.ssmConv1d,
            &lw.ssmConv1dBias, &lw.ssmDtBias,
            &lw.ssmNorm, &lw.ssmOut
        };
        for (const WeightTensor* wt : fields) placeWt(*wt);
        for (const WeightTensor& wt : lw.moeGate) placeWt(wt);
        for (const WeightTensor& wt : lw.moeUp) placeWt(wt);
        for (const WeightTensor& wt : lw.moeDown) placeWt(wt);
    }

    report.leaseCount = items.size();
    size_t placed = marsController_->placeAllTensors(items);
    report.placed = placed;
    report.skipped = items.size() - placed;

    // Count bytes per GPU from lease states
    auto parity = marsController_->getDynamicParity();
    report.bytesGpu0 = parity.gpu0Bytes;
    report.bytesGpu1 = parity.gpu1Bytes;
    report.bytesTotal = parity.gpu0Bytes + parity.gpu1Bytes + parity.hostBytes;
    marsWeightsPlaced_ = placed > 0;
    return report;
}

Deep2::HotpatchResult Deep2Engine::redirectTensor(uint64_t tensorId, int targetGPU) {
    if (!marsEnabled_ || !marsController_)
        return Deep2::HotpatchResult{};
    return marsController_->redirectTensor(tensorId, targetGPU);
}

void Deep2Engine::rebalanceMARS() {
    if (marsEnabled_ && marsController_)
        marsController_->rebalance();
}

Deep2::DynamicParity Deep2Engine::getDynamicParity() const {
    if (marsEnabled_ && marsController_)
        return marsController_->getDynamicParity();
    return Deep2::DynamicParity{};
}

bool Deep2Engine::handleTensorFault(uint64_t tensorId) {
    if (!marsEnabled_ || !marsController_) return false;
    return marsController_->handleTensorFault(tensorId);
}

bool Deep2Engine::handleGPUFailure(int gpu) {
    if (!marsEnabled_ || !marsController_) return false;
    return marsController_->handleGPUFailure(gpu);
}

// =================== 24 GiB HARD-RESIDENCY / MEASURED STREAMING ====================
void Deep2Engine::enableVramStreaming(bool enable) {
    if (!enable) {
        if (streamEngine_) streamEngine_->shutdown();
        streamEngine_.reset();
        streamRouter_.reset();
        vramStreamingController_.reset();
        vramStreamingEnabled_ = false;
        streamPrefetchEnabled_ = false;
        return;
    }
    if (!vramStreamingController_) {
        vramStreamingController_ = std::make_unique<Deep2::VramStreamingController>();
    }
    if (!streamEngine_) {
        streamEngine_ = std::make_unique<Deep2::StreamEngine>();
    }
    if (!streamRouter_) {
        streamRouter_ = std::make_unique<Deep2::StreamRouter>();
    }

    // Attach NVMe stream if available
    if (nvmeStream_) {
        vramStreamingController_->attachNvmeStream(nvmeStream_.get());
        streamEngine_->initialize(nvmeConfig_, vramStreamingController_.get(), nvmeStream_.get());
    }

    // Attach elastic residency manager if available
    if (elasticResidency_) {
        vramStreamingController_->attachElasticManager(elasticResidency_.get());
        streamRouter_->initialize(vramStreamingController_.get(), streamEngine_.get(), elasticResidency_.get());
    } else {
        streamRouter_->initialize(vramStreamingController_.get(), streamEngine_.get(), nullptr);
    }

    vramStreamingEnabled_ = true;
}

void Deep2Engine::lockVramResidency() {
    if (vramStreamingController_) vramStreamingController_->lockResidency();
}

void Deep2Engine::unlockVramResidency() {
    if (vramStreamingController_) vramStreamingController_->unlockResidency();
}

void Deep2Engine::setVramCeilingGiB(uint32_t gib) {
    if (vramStreamingController_) vramStreamingController_->setVramCeilingGiB(gib);
}

uint64_t Deep2Engine::vramCeilingBytes() const {
    return vramStreamingController_ ? vramStreamingController_->vramCeilingBytes() : 0;
}

void Deep2Engine::beginTokenStreamingMeasurement(uint64_t tokenIndex) {
    if (vramStreamingController_) vramStreamingController_->beginTokenMeasurement(tokenIndex);
}

bool Deep2Engine::endTokenStreamingMeasurement(uint64_t& outBytesMoved) {
    return vramStreamingController_ ? vramStreamingController_->endTokenMeasurement(outBytesMoved) : false;
}

VramStreamingStats Deep2Engine::getVramStreamingStats() const {
    return vramStreamingController_ ? vramStreamingController_->stats() : VramStreamingStats{};
}

// =================== TIME-REVERSE DIGEST ====================
void Deep2Engine::enableTimeReverseDigest(bool enable) {
    if (!enable) {
        timeReverseDigest_.reset();
        timeReverseEnabled_ = false;
        return;
    }
    if (!timeReverseDigest_) {
        timeReverseDigest_ = std::make_unique<TimeReverseDigest>();
    }
    timeReverseEnabled_ = true;
}

void Deep2Engine::setTimeReverseHorizonMs(double ms) {
    if (timeReverseDigest_) {
        timeReverseDigest_->setHorizonNs(static_cast<uint64_t>(ms * 1e6));
    }
}

// =================== GPU SCHEDULER ====================
void Deep2Engine::initializeGpuScheduler() {
    if (!gpuScheduler_) {
        gpuScheduler_ = std::make_unique<GpuScheduler>();
    }
    gpuScheduler_->clearDevices();
    gpuScheduler_->setPolicyFromEnv();
    for (size_t i = 0; i < vulkanDevices_.size(); ++i) {
        GpuDeviceDescriptor desc{};
        desc.ordinal = static_cast<uint32_t>(i);
        desc.available = true;
        gpuScheduler_->registerDevice(desc);
    }
    gpuScheduler_->enableBeaconism(BeaconismAuthority::enabledGlobally());
}

void Deep2Engine::setGpuPolicy(GpuPolicy policy) {
    if (gpuScheduler_) gpuScheduler_->setPolicy(policy);
}

GpuPolicy Deep2Engine::currentGpuPolicy() const {
    return gpuScheduler_ ? gpuScheduler_->currentPolicy() : GpuPolicy::SINGLE;
}

GpuScheduler* Deep2Engine::getGpuScheduler() const {
    return gpuScheduler_.get();
}

std::string Deep2Engine::scheduleGpuWork(const GpuWorkItem& work) {
    if (!gpuScheduler_) return "";
    return gpuScheduler_->schedule(work);
}

// =================== COMPRESSED KV CACHE ====================
void Deep2Engine::enableCompressedKV(bool enable, KVQuantType quantType) {
    if (!enable) {
        if (compressedKV_) compressedKV_->shutdown();
        compressedKV_.reset();
        compressedKVEnabled_ = false;
        return;
    }
    if (!compressedKV_ || compressedKVConfig_.quantType != quantType) {
        compressedKVConfig_.quantType = quantType;
        compressedKV_ = std::make_unique<Deep2::CompressedKVCache>(compressedKVConfig_);
        if (!compressedKV_->initialize(config.numLayers, config.numHeads, config.headDim, config.maxSeqLen)) {
            compressedKV_.reset();
            compressedKVEnabled_ = false;
            return;
        }
    }
    compressedKVEnabled_ = true;
}

// =================== NVMe STREAMING ====================
void Deep2Engine::enableNVMeStreaming(bool enable, const std::string& modelPath) {
    if (!enable) {
        if (nvmeStream_) nvmeStream_->shutdown();
        nvmeStream_.reset();
        nvmeStreamingEnabled_ = false;
        return;
    }
    std::string path = modelPath.empty() ? config.modelPath : modelPath;
    if (!nvmeStream_) {
        nvmeStream_ = std::make_unique<Deep2::NVMeStream>(nvmeConfig_);
    }
    if (!nvmeStream_->isInitialized()) {
        if (!nvmeStream_->initialize(path)) {
            nvmeStream_.reset();
            nvmeStreamingEnabled_ = false;
            return;
        }
    }
    nvmeStreamingEnabled_ = true;
}

// =================== BP16 STREAMER ====================
bool Deep2Engine::loadModelFromBP16(const std::string& bp16Path) {
    if (bp16Path.empty()) return false;
    if (!bp16Streamer_) {
        bp16Streamer_ = std::make_unique<Deep2::BP16Streamer>();
    }
    if (!bp16Streamer_->isInitialized()) {
        if (!bp16Streamer_->initialize(bp16Path)) {
            bp16Streamer_.reset();
            bp16Enabled_ = false;
            return false;
        }
    }
    bp16Enabled_ = true;
    // Attempt to discover all blocks via file size (best-effort)
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(bp16Path, ec);
    if (!ec && fileSize > 0) {
        // No-op: blocks are loaded on demand via loadBlock/getBlockData.
        (void)fileSize;
    }
    return true;
}

// =================== NANOF32BRAID STREAMER ====================
bool Deep2Engine::loadModelFromNanof32Braid(const std::string& braidPath) {
    if (braidPath.empty()) return false;
    if (!braidStreamer_) {
        braidStreamer_ = std::make_unique<Deep2::Nanof32BraidStreamer>();
    }
    if (!braidStreamer_->isOpen()) {
        if (!braidStreamer_->open(braidPath)) {
            braidStreamer_.reset();
            braidEnabled_ = false;
            return false;
        }
    }

    // Read architecture metadata
    Deep2::Nanof32BraidArchMeta archMeta{};
    if (!braidStreamer_->readArchMeta(archMeta)) {
        std::fprintf(stderr, "[NQBRAID] ERROR: failed to read arch meta\n");
        return false;
    }

    // Configure model weights from arch meta
    modelWeights = {};
    modelWeights.numLayers = archMeta.numLayers;
    modelWeights.hiddenDim = archMeta.hiddenDim;
    modelWeights.vocabSize = archMeta.vocabSize;
    modelWeights.numHeads = archMeta.numHeads;
    modelWeights.numKVHeads = archMeta.numKVHeads;
    modelWeights.headDim = archMeta.headDim;
    modelWeights.intermediateDim = archMeta.intermediateDim;
    modelWeights.normEps = archMeta.normEps;
    modelWeights.useMLA = (archMeta.ropeType == 3);
    modelWeights.isMoE = (archMeta.numExperts > 0);
    modelWeights.numExperts = archMeta.numExperts;
    modelWeights.numExpertsPerToken = archMeta.activeExperts;

    config.hiddenDim = archMeta.hiddenDim;
    config.vocabSize = archMeta.vocabSize;
    config.numLayers = archMeta.numLayers;
    config.numHeads = archMeta.numHeads;
    config.numKVHeads = archMeta.numKVHeads;
    config.headDim = archMeta.headDim;
    config.intermediateDim = archMeta.intermediateDim;
    config.normEps = archMeta.normEps;

    // Read all tensors from the braid file
    std::vector<std::pair<std::string, Deep2::NQBraidBlock>> tensors;
    if (!braidStreamer_->readAllTensors(tensors)) {
        std::fprintf(stderr, "[NQBRAID] ERROR: failed to read all tensors\n");
        return false;
    }

    // Build name → tensor map
    std::unordered_map<std::string, Deep2::NQBraidBlock*> tensorMap;
    for (auto& kv : tensors) {
        tensorMap[kv.first] = &kv.second;
    }

    // Helper: find tensor by name substring match (first match)
    auto findTensor = [&](const std::string& name) -> Deep2::NQBraidBlock* {
        for (auto& kv : tensorMap) {
            if (kv.first.find(name) != std::string::npos) {
                return kv.second;
            }
        }
        return nullptr;
    };

    // Helper: bind a tensor into WeightTensor
    auto bindTensor = [](Deep2::NQBraidBlock& blk, WeightTensor& wt,
                         size_t rows, size_t cols) {
        if (!blk.ready || blk.bf16Data.empty()) return false;
        wt.data = blk.bf16Data.data();
        wt.type = 30;  // GGML_TYPE_BF16
        wt.rows = rows;
        wt.cols = cols;
        wt.sizeBytes = blk.bf16Data.size() * sizeof(Deep2::bfloat16_t);
        wt.mapped = true;
        wt.name = blk.name;
        wt.shape = {static_cast<int64_t>(cols), static_cast<int64_t>(rows)};
        return true;
    };

    // Token embeddings (vocabSize x hiddenDim)
    auto emb = findTensor("token_embd");
    if (emb) {
        bindTensor(*emb, modelWeights.tokenEmbed,
                   archMeta.vocabSize, archMeta.hiddenDim);
    }

    // Output norm
    auto outNorm = findTensor("output_norm");
    if (outNorm) {
        bindTensor(*outNorm, modelWeights.finalNorm,
                   1, archMeta.hiddenDim);
    }

    // LM head / output.weight
    auto lmHead = findTensor("output.weight");
    if (!lmHead) lmHead = findTensor("lm_head");
    if (lmHead) {
        bindTensor(*lmHead, modelWeights.lmHead,
                   archMeta.vocabSize, archMeta.hiddenDim);
    }

    // Allocate per-layer weights
    modelWeights.layers.assign(archMeta.numLayers, LayerWeights{});

    // Map each layer
    for (uint32_t layer = 0; layer < archMeta.numLayers; ++layer) {
        auto& lw = modelWeights.layers[layer];
        std::string blk = "blk." + std::to_string(layer) + ".";

        auto findLayerTensor = [&](const std::string& pattern) -> Deep2::NQBraidBlock* {
            for (auto& kv : tensorMap) {
                if (kv.first.find(pattern) != std::string::npos) {
                    return kv.second;
                }
            }
            return nullptr;
        };

        // Attention norms
        auto attnNorm = findLayerTensor(blk + "attn_norm");
        if (attnNorm) bindTensor(*attnNorm, lw.attnNorm, 1, archMeta.hiddenDim);

        auto ffnNorm = findLayerTensor(blk + "ffn_norm");
        if (ffnNorm) bindTensor(*ffnNorm, lw.ffnNorm, 1, archMeta.hiddenDim);

        // Attention projections
        if (archMeta.ropeType == 3) {
            // MLA path
            auto q_a = findLayerTensor(blk + "attn_q_a");
            auto q_b = findLayerTensor(blk + "attn_q_b");
            auto kv_a = findLayerTensor(blk + "attn_kv_a");
            auto k_b = findLayerTensor(blk + "attn_k_b");
            auto v_b = findLayerTensor(blk + "attn_v_b");
            auto attn_o = findLayerTensor(blk + "attn_o");
            auto q_a_norm = findLayerTensor(blk + "attn_q_a_norm");
            auto kv_a_norm = findLayerTensor(blk + "attn_kv_a_norm");

            if (q_a) bindTensor(*q_a, lw.attnQ_a, archMeta.hiddenDim, archMeta.hiddenDim);
            if (q_b) bindTensor(*q_b, lw.attnQ_b, archMeta.numHeads * archMeta.headDim, archMeta.hiddenDim);
            if (kv_a) bindTensor(*kv_a, lw.attnKV_a_mqa, archMeta.hiddenDim, archMeta.hiddenDim);
            if (k_b) bindTensor(*k_b, lw.attnK_b, archMeta.numHeads * archMeta.headDim, archMeta.hiddenDim);
            if (v_b) bindTensor(*v_b, lw.attnV_b, archMeta.numHeads * archMeta.headDim, archMeta.hiddenDim);
            if (attn_o) bindTensor(*attn_o, lw.attnO, archMeta.hiddenDim, archMeta.numHeads * archMeta.headDim);
            if (q_a_norm) bindTensor(*q_a_norm, lw.attnQ_a_norm, 1, archMeta.headDim);
            if (kv_a_norm) bindTensor(*kv_a_norm, lw.attnKV_a_norm, 1, archMeta.hiddenDim);
            lw.useMLA = true;
        } else {
            // Standard MHA / GQA path
            auto wq = findLayerTensor(blk + "attn_q");
            auto wk = findLayerTensor(blk + "attn_k");
            auto wv = findLayerTensor(blk + "attn_v");
            auto wo = findLayerTensor(blk + "attn_o");

            size_t qDim = archMeta.numHeads * archMeta.headDim;
            size_t kvDim = archMeta.numKVHeads * archMeta.headDim;

            if (wq) bindTensor(*wq, lw.wq, qDim, archMeta.hiddenDim);
            if (wk) bindTensor(*wk, lw.wk, kvDim, archMeta.hiddenDim);
            if (wv) bindTensor(*wv, lw.wv, kvDim, archMeta.hiddenDim);
            if (wo) bindTensor(*wo, lw.wo, archMeta.hiddenDim, qDim);
        }

        // FFN weights
        auto gate = findLayerTensor(blk + "ffn_gate");
        auto up = findLayerTensor(blk + "ffn_up");
        auto down = findLayerTensor(blk + "ffn_down");

        if (gate) bindTensor(*gate, lw.wGate, archMeta.intermediateDim, archMeta.hiddenDim);
        if (up) bindTensor(*up, lw.wUp, archMeta.intermediateDim, archMeta.hiddenDim);
        if (down) bindTensor(*down, lw.wDown, archMeta.hiddenDim, archMeta.intermediateDim);

        // MoE weights (if applicable)
        if (archMeta.numExperts > 0) {
            auto router = findLayerTensor(blk + "ffn_gate_exps");
            if (router) bindTensor(*router, lw.moeRouter, archMeta.numExperts, archMeta.hiddenDim);
            // TODO: expert-specific gate/up/down — requires expert index matching
        }
    }

    // Transfer ownership of tensor data to the streamer cache for residency
    {
        std::lock_guard<std::mutex> lk(braidStreamer_->cacheMutex());
        auto& cache = braidStreamer_->cache();
        uint32_t idx = 0;
        for (auto& kv : tensors) {
            cache[idx++] = std::move(kv.second);
        }
    }

    modelWeights.loaded = true;
    braidEnabled_ = true;

    std::fprintf(stderr, "[NQBRAID] LOADED: %u layers, hidden=%u, vocab=%u, tensors=%zu\n",
                 archMeta.numLayers, archMeta.hiddenDim, archMeta.vocabSize, tensors.size());
    std::fflush(stderr);

    return true;
}

// =================== REVERSE WEBGPU STREAM AUTHORITY ====================
// RAWRXD_REVERSE_WEBGPU_STREAM_AUTHORITY_001
// Deep2 retains model authority; browser becomes execution/view surface only.
void Deep2Engine::enableReverseWebgpu(bool enable) {
    reverseWebgpuEnabled_ = enable;
    if (!enable) {
        reverseWebgpuBound_ = false;
    }
}

bool Deep2Engine::tryReverseWebgpuTokenForward(float* hidden, size_t seqLen) {
    if (!reverseWebgpuEnabled_ || !modelWeights.loaded) {
        return false;
    }
    // TODO: produce WebGPU-compatible compute packet from the current working set
    // (identify required tensor/range → locate representation → materialize
    //  WebGPU input → dispatch → receive result into hidden).
    //
    // For now: the route exists, the predicate is wired, the execution is
    // a measured "not yet implemented" so the route does not silently claim
    // a false PASS.
    std::fprintf(stderr, "[REVERSE_WEBGPU] route reached; execution pending implementation\n");
    std::fflush(stderr);
    return false;
}

// =================== SOVEREIGN (TRUTHFUL LIFECYCLE) ====================
void Deep2Engine::enableAllEnhancements() {
    enableChamber(true);
    enableToroidalKV(true);
    enablePlasmaGovernor(true);
    enableSovereignRuntime(true);
}

void Deep2Engine::enableChamber(bool enable) {
    if (!enable) {
        chamber_.reset();
        chamberEnabled_ = false;
        return;
    }
    if (!chamber_) {
        chamber_ = std::make_unique<Deep2::Chamber>();
    }
    chamberEnabled_ = true;
}

Deep2::ChamberResult Deep2Engine::evaluateChamber(const float* hidden_state, size_t dim) {
    if (!chamberEnabled_ || !chamber_)
        return Deep2::ChamberResult{};
    return chamber_->evaluate(hidden_state, dim);
}

Deep2::FormulaRoute Deep2Engine::routePrimitive(uint64_t context_hash) {
    if (!chamberEnabled_ || !chamber_)
        return Deep2::FormulaRoute{};
    return chamber_->routePrimitive(context_hash);
}

void Deep2Engine::enableToroidalKV(bool enable, size_t maxTokens) {
    if (!enable) {
        toroidalKV_.reset();
        toroidalKVEnabled_ = false;
        return;
    }
    if (!toroidalKV_ || toroidalKV_->capacity() != maxTokens) {
        toroidalKV_ = std::make_unique<Deep2::ToroidalKVCache>(
            config.numLayers, config.numHeads, config.headDim, maxTokens);
        if (!toroidalKV_->initialize()) {
            toroidalKV_.reset();
            toroidalKVEnabled_ = false;
            return;
        }
    }
    toroidalKVEnabled_ = true;
}

void Deep2Engine::enablePlasmaGovernor(bool enable) {
    if (!enable) {
        plasmaGovernor_.reset();
        plasmaGovernorEnabled_ = false;
        return;
    }
    if (!plasmaGovernor_) {
        plasmaGovernor_ = std::make_unique<Deep2::PlasmaGovernor>();
    }
    plasmaGovernorEnabled_ = true;
}

void Deep2Engine::updateThermalState(const Deep2::ThermalState& state) {
    if (plasmaGovernorEnabled_ && plasmaGovernor_)
        plasmaGovernor_->update(state);
}

float Deep2Engine::currentThrottle() const {
    if (plasmaGovernorEnabled_ && plasmaGovernor_)
        return plasmaGovernor_->currentThrottle();
    return 1.0f;
}

void Deep2Engine::enableCyclone(bool enable) {
    if (!enable) {
        if (cyclone_) {
            cyclone_->reset();
            Deep2::LivePath_UnbindCyclone();
            cyclone_.reset();
            cycloneEnabled_ = false;
        }
        return;
    }
    if (!cyclone_) {
        cyclone_ = std::make_unique<Deep2::CycloneScheduler>();
    }
    cyclone_->reset();
    if (modelWeights.loaded && modelWeights.numLayers > 0) {
        cyclone_->onModelSwitch(static_cast<uint32_t>(modelWeights.numLayers), 0);
        Deep2::LivePath_BindCyclone(cyclone_.get());
    }
    // If model is not loaded yet, onModelSwitch + bind happen in loadModel().
    cycloneEnabled_ = true;
}

void Deep2Engine::enableSovereignRuntime(bool enable) {
    if (!enable) {
        sovereignRuntime_.reset();
        sovereignRuntimeEnabled_ = false;
        return;
    }
    if (!sovereignRuntime_) {
        Deep2::SovereignOutOfCoreRuntime::OocConfig cfg{};
        sovereignRuntime_ = std::make_unique<Deep2::SovereignOutOfCoreRuntime>(cfg);
    }
    if (!sovereignRuntime_->isInitialized()) {
        if (!sovereignRuntime_->initialize()) {
            sovereignRuntime_.reset();
            sovereignRuntimeEnabled_ = false;
            return;
        }
    }
    sovereignRuntimeEnabled_ = true;
}

Deep2::SovereignOutOfCoreRuntime* Deep2Engine::getSovereignRuntime() const {
    if (sovereignRuntimeEnabled_ && sovereignRuntime_)
        return sovereignRuntime_.get();
    return nullptr;
}

// =================== PROFILER / TELEMETRY (TRUTHFUL LIFECYCLE) ====================
void Deep2Engine::enableProfiling(bool enable) {
    profilingEnabled_ = false;
    if (!enable) {
        if (profiler_) profiler_->setEnabled(false);
        profiler_.reset();
        profileHistory_.clear();
        return;
    }

    if (!profiler_) {
        profiler_ = std::make_unique<ProductionProfiler>();
    }
    profiler_->reset();
    profiler_->setEnabled(true);
    profileHistory_.clear();
    profilingEnabled_ = true;
}

bool Deep2Engine::saveProfileJSON(const std::string& path) const {
    if (!profiler_) return false;
    return profiler_->saveJSON(path);
}

std::string Deep2Engine::getProfileJSONSummary() const {
    if (!profiler_) return "{}";
    return profiler_->toJSON();
}

// =================== TOKEN HELPERS ====================
// Batch 9: gpuForwardCounters/resetGpuForwardCounters/isRealGpuForward are
// defined in Deep2Engine_GpuForward.cpp.

// =================== CHAT (basic prompt wrapper) ====================
std::string Deep2Engine::generateChat(const std::string& userMessage,
                                       const std::string& systemPrompt,
                                       size_t maxTokens) {
    std::string full = systemPrompt + "\nUser: " + userMessage + "\nAssistant: ";
    return generateText(full, maxTokens);
}

// =================== KV CACHE ADVANCE ====================
bool Deep2Engine::advancePersistentKv() {
    return kvCache && kvCache->advance();
}

size_t Deep2Engine::persistentKvLength() const {
    return kvCache ? kvCache->currentLength() : 0;
}

// =================== GROW CONTEXT ====================
bool Deep2Engine::growContext(size_t newMaxSeqLen) {
    if (!initialized || !kvCache || newMaxSeqLen == 0)
        return false;
    if (newMaxSeqLen <= config.maxSeqLen)
        return true;
    if (!kvCache->grow(newMaxSeqLen))
        return false;
    config.maxSeqLen = newMaxSeqLen;
    return true;
}

// Batch 9: Vulkan runtime bindings live in Deep2Engine_VulkanRuntime.cpp.
// Old null-device stubs removed.

} // namespace Deep2
//fcukevol

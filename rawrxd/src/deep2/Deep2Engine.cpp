/* Deep2Engine.cpp â€” Real Implementation
 * Connects: tokenizer, sampler, KV cache, weights, forward pass
 */
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "Sampler.hpp"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include "Deep2DualGpuRowSplit.hpp"
#include "lavapath/GpuForwardChildLadder.hpp"
#include "Deep2ArchitectureRuntime.hpp"
#include "expert_cache/Deep2Batch005Integration.h"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <fstream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace Deep2 {

// ------------------------------------------------------------
// Token-path telemetry accumulator (C++20, zero-dependency beyond the standard lib).
// All fields are caller-fed from real execution points — no synthetic estimates.
// ------------------------------------------------------------
struct TokenTelemetryAccumulator {
    // One‑time initialization / open
    bool open(const char* csv_path = nullptr, const char* jsonl_path = nullptr);

    // Call once per generated token (ideally right after the token is fully emitted).
    void record_token();

    // ------------------------------------------------------------------
    // Counters filled from the real Deep2 execution points (see the per‑file wiring below).
    // ------------------------------------------------------------------
    // Token loop / timing
    uint64_t tokens_generated{};
    uint64_t token_total_ns{};          // TOKEN_TOTAL_NS wall‑clock per token

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

    // Expert‑cache
    uint32_t experts_total{};
    uint32_t experts_active{};
    uint64_t expert_cache_hits{};
    uint64_t expert_cache_misses{};

    // GPU timing (ns)
    uint64_t gpu_busy_ns{};
    uint64_t gpu_idle_ns{};
    uint64_t wait_ns{};
    uint64_t submit_ns{};

    // Hotpatch authority (populated by the address‑space layer)
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
// Global instance – one per engine process lifetime.
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
        else { std::fprintf(jsonl_fp, "{\"model_file_bytes\":%,}\n"); } // placeholder – real writer below
    }
    return ok;
}

void TokenTelemetryAccumulator::record_token() {
    ++tokens_generated;

    // Emit a CSV row if the file is open.
    if (csv_fp) {
        std::fprintf(csv_fp, "%llu,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
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
            tokens_generated, token_total_ns);
    }
    // JSONL row would be written similarly.
}

// ------------------------------------------------------------
// Early‑exit if telemetry not configured.
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
    int topIdx[10] = {};
    float topVal[10];
    std::fill(std::begin(topVal), std::end(topVal),
              -std::numeric_limits<float>::infinity());
    const size_t keep = std::min<size_t>(10, n);
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

// =================== CONSTRUCTOR / DESTRUCTOR ====================
namespace {
    rawrxd::Batch005Runtime s_expertCacheRuntime; // keeps expert_cache objects alive
}
Deep2Engine::Deep2Engine() {}
Deep2Engine::~Deep2Engine() { unloadModel(); }

// =================== INITIALIZE ====================
bool Deep2Engine::initialize(const EngineConfig& cfg) {
    // Core lifecycle owns runtime objects; model geometry may still be unknown
    // until the GGUF/model-loader batch binds real metadata.
    deallocateBuffers();
    config = cfg;

    clearCancel();
    gpuFwd_ = {};
    gpuFwdCommitted_ = false;
    modelState_ = ModelState::Closed;

    if (cfg.useThreadPool && cfg.numThreads > 0) {
        threadPool = std::make_unique<ThreadPool>(cfg.numThreads);
    } else {
        threadPool.reset();
    }

    kvCache = std::make_unique<KVCache>();
    tokenizer = std::make_unique<BPETokenizer>();
    sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
    deterministicGreedy_ = true;
    QuantKernelRegistry::Instance().Initialize();

    // Initialization means the runtime is ready. Scratch buffers are allocated
    // immediately only when geometry is already known; otherwise loadModel()
    // (or a later real loader) binds geometry and allocates them.
    initialized = true;
    if (cfg.hiddenDim != 0 && cfg.vocabSize != 0) {
        if (!allocateBuffers()) {
            initialized = false;
            return false;
        }
    }

    if (cfg.useKVCache && cfg.numLayers != 0 && cfg.maxSeqLen != 0 &&
        cfg.numHeads != 0) {
        KVCacheConfig kc{};
        kc.numLayers = cfg.numLayers;
        kc.numHeads = cfg.numKVHeads ? cfg.numKVHeads : cfg.numHeads;
        kc.headDim = cfg.headDim ? cfg.headDim : (cfg.hiddenDim / cfg.numHeads);
        kc.maxSeqLen = cfg.maxSeqLen;
        if (kc.headDim == 0 || !kvCache->allocate(kc)) {
            initialized = false;
            return false;
        }
    }
    return true;
}

// =================== ALLOCATE BUFFERS ====================
bool Deep2Engine::allocateBuffers() {
    const size_t H = modelWeights.hiddenDim ? modelWeights.hiddenDim : config.hiddenDim;
    const size_t V = modelWeights.vocabSize ? modelWeights.vocabSize : config.vocabSize;
    const size_t I = modelWeights.intermediateDim
        ? modelWeights.intermediateDim
        : (config.intermediateDim ? config.intermediateDim : (H ? H * 4 : 0));

    if (H == 0 || V == 0 || I == 0) return false;

    // Determine projection dimensions based on model metadata (supports rectangular attention like Gemma3)
    const size_t numHeads = modelWeights.numHeads ? modelWeights.numHeads : config.numHeads;
    const size_t headDim = modelWeights.headDim ? modelWeights.headDim : config.headDim;
    const size_t numKVHeads = modelWeights.numKVHeads ? modelWeights.numKVHeads : numHeads;

    const size_t qDim  = (numHeads && headDim) ? (numHeads * headDim) : H;
    const size_t kvDim = (numKVHeads && headDim) ? (numKVHeads * headDim) : H;

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

    // SSM / Mamba2 per-layer state buffers (Nemotron-H)
    const bool archIsNemotronH = (modelArchitecture_ == "nemotron_h" || modelArchitecture_ == "nemotron_h_moe");
    if (archIsNemotronH && ssmInner_ && ssmStateSize_ && ssmHeads_ && ssmGroups_ &&
        modelWeights.numLayers > 0) {
        const size_t groupBC = ssmGroups_ * ssmStateSize_;
        const size_t convChannels = ssmInner_ + 2 * groupBC;
        const size_t inRows = 2 * ssmInner_ + 2 * groupBC + ssmHeads_;
        ssmX      = new (std::nothrow) float[ssmInner_];
        ssmY      = new (std::nothrow) float[ssmInner_];
        ssmTemp   = new (std::nothrow) float[inRows];
        ssmState  = new (std::nothrow) float[modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_];
        ssmConvState = new (std::nothrow) float[modelWeights.numLayers * convChannels * (ssmConvKernel ? (ssmConvKernel - 1) : 0)];
        if (ssmState)  std::memset(ssmState,  0, modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_ * sizeof(float));
        if (ssmConvState && ssmConvKernel > 1) std::memset(ssmConvState, 0, modelWeights.numLayers * convChannels * (ssmConvKernel - 1) * sizeof(float));
        ssmLayerCaches_.resize(modelWeights.numLayers);
    }

    if (!hiddenStates || !attentionOutput || !ffnOutput || !logits ||
        !qProj || !kProj || !vProj || !gateBuf || !upBuf || !layerTemp ||
        !layerOut) {
        deallocateBuffers();
        return false;
    }

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

    // Reset SSM recurrent state for new conversation
    if (ssmState) {
        const size_t stateBytes = modelWeights.numLayers * ssmHeads_ * (ssmInner_ / ssmHeads_) * ssmStateSize_ * sizeof(float);
        std::memset(ssmState, 0, stateBytes);
    }
    if (ssmConvState) {
        const size_t groupBC = ssmGroups_ * ssmStateSize_;
        const size_t convChannels = ssmInner_ + 2 * groupBC;
        const size_t convHistBytes = modelWeights.numLayers * convChannels * (ssmConvKernel > 1 ? (ssmConvKernel - 1) : 0) * sizeof(float);
        std::memset(ssmConvState, 0, convHistBytes);
    }

    // BATCH10_RESET_MLA_CACHE
    for (auto& gpu : vulkanDevices_) {
        if (gpu) gpu->ResetMLACache();
    }
    specKvMirrorReset();

    gpuFwdCommitted_ = false;
    gpuFwd_ = {};
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
    if (keyLen != 0 && valueLen != 0 && keyLen != valueLen) {
        if (diag) {
            diag->stageCode = 6;
            diag->stageName = "ATTN_HEAD_DIM_MISMATCH";
            diag->message = "Deep2 currently requires equal attention.key_length and attention.value_length.";
        }
        return false;
    }
    if (keyLen != 0) {
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
    modelWeights.moeIntermediateDim =
        metaSize("expert_feed_forward_length", 0);
    modelWeights.numExperts =
        metaSize("expert_count", 0);
    modelWeights.numExpertsPerToken =
        metaSize("expert_used_count", 0);
    modelWeights.numSharedExperts =
        metaSize("expert_shared_count", 0);
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

    modelWeights.layers.assign(modelWeights.numLayers, LayerWeights{});

    for (size_t layer = 0; layer < modelWeights.numLayers; ++layer) {
        LayerWeights& lw = modelWeights.layers[layer];
        const std::string p = "blk." + std::to_string(layer) + ".";

        bindTensor(p + "attn_qkv.weight", lw.wqkv);
        bindTensor(p + "attn_q.weight", lw.wq);
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
            if (!lw.attnNorm.data) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing nemotron_h layer norm\n",
                    layer);
                if (diag) {
                    diag->stageCode = 14;
                    diag->stageName = "NEMOTRON_H_LAYER_NORM_MISSING";
                    diag->message = "Nemotron-H layer missing attn_norm.weight.";
                }
                return false;
            }
            // Nemotron-H hybrid layers do not require ffnNorm.
            // We determine block type from what tensors are present.
            const bool hasSSMBlock =
                lw.ssmIn.data || lw.ssmConv1d.data || lw.ssmDtBias.data ||
                lw.ssmA.data || lw.ssmD.data || lw.ssmNorm.data || lw.ssmOut.data;
            const bool hasAttnBlock =
                lw.wqkv.data || (lw.wq.data && lw.wk.data && lw.wv.data) || lw.wo.data;
            const bool hasFFNBlock = lw.wUp.data || lw.wDown.data || lw.wGate.data ||
                                    lw.moeUp.size() > 0 || lw.moeDown.size() > 0;
            if (!hasSSMBlock && !hasAttnBlock && !hasFFNBlock) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu nemotron_h block has neither SSM, attention, nor FFN tensors\n",
                    layer);
                if (diag) {
                    diag->stageCode = 15;
                    diag->stageName = "NEMOTRON_H_BLOCK_TYPE_UNKNOWN";
                    diag->message = "Nemotron-H layer has neither SSM, attention, nor FFN tensors bound.";
                }
                return false;
            }
            lw.hasSSM = hasSSMBlock;
            lw.hasAttn = hasAttnBlock;
            lw.hasFFN  = hasFFNBlock;
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

        const bool splitQkv =
            lw.wq.data && lw.wk.data && lw.wv.data;
        const bool fusedQkv = lw.wqkv.data != nullptr;
        if (!isNemotronH && !splitQkv && !fusedQkv) {
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
    specKvMirrorReset();
    kvCache = std::make_unique<KVCache>();
    clearCancel();
    gpuFwd_ = {};
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
    unloadModel();
    return loadModel(ggufPath);
}

// =================== TOKENIZE / DETOKENIZE ====================
std::vector<int> Deep2Engine::tokenize(const std::string& text) {
    if (!tokenizer) return {};
    return tokenizer->encode(text);
}

std::string Deep2Engine::detokenize(const std::vector<int>& tokens) {
    if (!tokenizer) return "";
    return tokenizer->decode(tokens);
}

// =================== EMBED TOKEN (REAL MAPPED WEIGHT ROW) ====================
bool Deep2Engine::embedToken(int tokenId, float* output) {
    if (!modelWeights.loaded || !output ||
        tokenId < 0 ||
        static_cast<size_t>(tokenId) >= modelWeights.vocabSize)
        return false;

    const WeightTensor& wt = modelWeights.tokenEmbed;
    const size_t H = modelWeights.hiddenDim;
    const size_t V = modelWeights.vocabSize;

    if (!wt.data || wt.rows != V || wt.cols != H || H == 0)
        return false;

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
    if (wt.sizeBytes != 0 &&
        (offset > wt.sizeBytes || rowBytes > wt.sizeBytes - offset))
        return false;

    auto dequant = QuantKernelRegistry::Instance().GetDequant(wt.type);
    if (!dequant) return false;

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
       modelWeights.hiddenDim==0)
        return false;
    const size_t H=modelWeights.hiddenDim;
    for(size_t b=0;b<count;++b) {
        if(!embedToken(tokenIds[b],outputBatch+b*H))
            return false;
    }
    return true;
}

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
        float fnMin = std::numeric_limits<float>::infinity();
        float fnMax = -std::numeric_limits<float>::infinity();
        for (size_t i = 0; i < H; ++i) {
            if (layerTemp[i] < fnMin) fnMin = layerTemp[i];
            if (layerTemp[i] > fnMax) fnMax = layerTemp[i];
        }
        std::fprintf(stderr, "FINALNORM_POST min=%g max=%g\n", fnMin, fnMax);
        std::fflush(stderr);
    }
    parityEmit(ParityCheckpoint::FinalNorm, layerTemp, H);
    LinearW(modelWeights.lmHead, layerTemp, nullptr, logitsOut, V);

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
    if (!sampler) return 0;
    return sampler->sample(logitsPtr, (int)config.vocabSize);
}

int Deep2Engine::sampleCommittedToken(const float* logitsPtr) {
    return sampleToken(logitsPtr);
}

// =================== CONFIGURE GENERATION ====================
void Deep2Engine::configureGeneration(const GenerationOptions& options) {
    if (options.temperature <= 0.0f || options.topK <= 1) {
        deterministicGreedy_ = true;
        sampler = std::make_unique<rawrxd::sampling::GreedySampler>();
    } else if (options.topK > 1) {
        deterministicGreedy_ = false;
        sampler = std::make_unique<rawrxd::sampling::TopKSampler>(
            (int)options.topK, options.temperature);
    } else {
        deterministicGreedy_ = false;
        sampler = std::make_unique<rawrxd::sampling::TemperatureSampler>(
            options.temperature);
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

// =================== FORWARD-LAYER TRACE GATE ====================
// Product path (rawr run) must stream only generated text to stdout and
// receipts to stderr. Per-op FWD_LAYER/LINEARW tracing is a batch-gate
// diagnostic: opt-in via DEEP2_TRACE_FORWARD=1 (checked once per process).
static bool deep2ForwardTraceEnabled() {
    static const bool enabled = [] {
        const char* v = std::getenv("DEEP2_TRACE_FORWARD");
        return v && v[0] == '1';
    }();
    return enabled;
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
    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr,"LINEARW name=%s rows=%zu cols=%zu type=%d\n",
                     wtn, wt.rows, wt.cols, wt.type); std::fflush(stderr);
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

    // BATCH10_ROW_SPLIT_LINEAR â€” real GPU arithmetic, host result contract.
    if (vulkanInitialized_ && !vulkanDevices_.empty()) {
        std::memset(output, 0, outDim * sizeof(float));
        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,"LINEARW_TRY_GPU name=%s\n",wtn); std::fflush(stderr);
        }

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
                    if (deep2ForwardTraceEnabled() || geometryChanged) {
                        std::fprintf(stderr,
                            "[B4_LMHEAD_PIN] slot0rows=%u slot1rows=%u "
                            "repin=%u\n",
                            w0v.rows, w1v.rows, lmHeadPinRePins_);
                    }
                }
            }
        }

        // Attempt 1: dual-GPU row split
        bool triedDual = false, dualOk = false;
        if (vulkanDevices_.size() >= 2 && wt.rows >= 2) {
            triedDual = true;
            if (tryVulkanHostGEMV(wt, input, output, outDim)) {
                dualOk = true;
            }
        }
        if (dualOk) {
            if (deep2ForwardTraceEnabled()) {
                std::fprintf(stderr,"LINEARW_RESULT=DUAL_GPU name=%s\n",wtn); std::fflush(stderr);
            }
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (!finiteVector(output, outDim))
                throw std::runtime_error("LinearW: non-finite GPU output");
            return;
        }
        if (triedDual) {
            if (deep2ForwardTraceEnabled()) {
                std::fprintf(stderr,"LINEARW_DUAL_ROW_FAIL name=%s\n",wtn); std::fflush(stderr);
            }
        }

        // Attempt 2: single-GPU fallback
        if (tryVulkanHostGEMV(wt, input, output, outDim)) {
            if (deep2ForwardTraceEnabled()) {
                std::fprintf(stderr,"LINEARW_RESULT=SINGLE_GPU name=%s\n",wtn); std::fflush(stderr);
            }
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (!finiteVector(output, outDim))
                throw std::runtime_error("LinearW: non-finite GPU output");
            return;
        }

        // GPU paths exhausted
        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,"LINEARW_RESULT=FAIL name=%s strict=%d\n",
                         wtn,(int)vulkanStrictNoCpuFallback_); std::fflush(stderr);
        }
        if (vulkanStrictNoCpuFallback_)
            throw std::runtime_error("LinearW: GPU path failed under strict mode");
    }

    // CPU fallback
    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr,"LINEARW_RESULT=CPU_FALLBACK name=%s\n",wtn); std::fflush(stderr);
    }
    auto kernel = QuantKernelRegistry::Instance().GetGEMV(wt.type);
    if (!kernel) {
        throw std::runtime_error("LinearW: no registered GEMV kernel");
    }

    // Diagnostic: log input statistics before GEMV
    float inMin =  std::numeric_limits<float>::infinity();
    float inMax = -std::numeric_limits<float>::infinity();
    size_t inBad = SIZE_MAX;
    for (size_t i = 0; i < cols; ++i) {
        if (!std::isfinite(input[i])) { inBad = i; break; }
        if (input[i] < inMin) inMin = input[i];
        if (input[i] > inMax) inMax = input[i];
    }
    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr,
            "LINEAR_CPU_BEGIN name=%s type=%d rows=%zu cols=%zu "
            "inputFinite=%d inputBad=%zu inputMin=%.9g inputMax=%.9g\n",
            wtn, wt.type, rows, cols,
            (inBad == SIZE_MAX) ? 1 : 0, inBad, inMin, inMax);
        std::fflush(stderr);
    }

    std::memset(output, 0, outDim * sizeof(float));
    kernel(static_cast<const uint8_t*>(wt.data), input, output, rows, cols);

    if (bias) {
        for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
    }

    size_t outBad = SIZE_MAX;
    float outMin =  std::numeric_limits<float>::infinity();
    float outMax = -std::numeric_limits<float>::infinity();
    for (size_t i = 0; i < outDim; ++i) {
        if (!std::isfinite(output[i])) { outBad = i; break; }
        if (output[i] < outMin) outMin = output[i];
        if (output[i] > outMax) outMax = output[i];
    }
    if (outBad != SIZE_MAX) {
        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,
                "LINEAR_CPU_NONFINITE name=%s type=%d firstBadIdx=%zu value=%.9g\n",
                wtn, wt.type, outBad,
                outBad < outDim ? output[outBad] : 0.0f);
            std::fflush(stderr);
        }
        throw std::runtime_error("LinearW: non-finite output");
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
    } else {
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
    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr,"FWD_LAYER layer=%zu seqLen=%zu\n",layer,seqLen); std::fflush(stderr);
    }
    if (!input || !output || config.hiddenDim == 0) {
        throw std::runtime_error("forwardLayer: invalid buffers/geometry");
    }
    if (layer >= modelWeights.layers.size()) {
        throw std::runtime_error("forwardLayer: layer weights not bound");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = config.hiddenDim;

    // Nemotron-H hybrid: each layer may have any subset of attention, SSM, and FFN.
    // Layers without attention skip the attention residual; layers without FFN skip the FFN residual.
    const bool doAttn = lw.hasAttn;
    const bool doSSM  = lw.hasSSM;
    const bool doFFN  = lw.hasFFN;

    // ---- Attention branch ----
    if (doAttn) {
        if (!lw.attnNorm.data) {
            throw std::runtime_error("forwardLayer: missing attention norm");
        }
        RMSNormW(lw.attnNorm, input, layerTemp, H, modelWeights.normEps);
        parityEmit(ParityCheckpoint::AttnNorm, layerTemp, H);
        parityEmitLayer(static_cast<int>(layer), "ATTN_NORM", layerTemp, H);

        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,"FWD_LAYER layer=%zu ATTENTION\n",layer); std::fflush(stderr);
        }
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
        parityEmit(ParityCheckpoint::AttnResidual, output, H);
        parityEmitLayer(static_cast<int>(layer), "ATTN_RESIDUAL", output, H);
    } else {
        // If no attention, carry input forward unchanged
        std::memcpy(output, input, H * sizeof(float));
    }

    // ---- SSM branch (Mamba) ----
    if (doSSM) {
        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,"FWD_LAYER layer=%zu SSM\n",layer); std::fflush(stderr);
        }
        // For now: computeSSM has an identity fallback so Nemotron-H models can run
        // and produce TPS numbers. Real selective scan is TODO.
        computeSSM(layer, output, output);
    }

    // ---- FFN branch ----
    if (doFFN) {
        if (lw.ffnNorm.data) {
            RMSNormW(lw.ffnNorm, output, layerTemp, H, modelWeights.normEps);
        } else if (lw.attnNorm.data) {
            // Nemotron-H hybrid layers may reuse attn_norm as pre-FFN norm
            RMSNormW(lw.attnNorm, output, layerTemp, H, modelWeights.normEps);
        } else {
            throw std::runtime_error("forwardLayer: missing FFN norm");
        }
        parityEmit(ParityCheckpoint::FfnNorm, layerTemp, H);
        parityEmitLayer(static_cast<int>(layer), "FFN_NORM", layerTemp, H);

        if (deep2ForwardTraceEnabled()) {
            std::fprintf(stderr,"FWD_LAYER layer=%zu FFN_ENTER\n",layer); std::fflush(stderr);
        }
        if (modelWeights.numExperts > 0) {
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

        if (!finiteVector(output, H)) {
            throw std::runtime_error("forwardLayer: non-finite layer output");
        }
    }

    parityEmit(ParityCheckpoint::LayerResidual, output, H);
    parityEmitLayer(static_cast<int>(layer), "LAYER_RESIDUAL", output, H);
    auto tLayer1 = std::chrono::steady_clock::now();
    if (profiler_) {
        profiler_->recordGpuForward(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tLayer1 - tLayer0).count()));
        profiler_->endLayer(static_cast<uint32_t>(layer));
    }
    if (deep2ForwardTraceEnabled()) {
        std::fprintf(stderr,"FWD_LAYER layer=%zu DONE\n",layer); std::fflush(stderr);
    }
}

// =================== ATTENTION (REAL MHA/GQA) ====================
void Deep2Engine::computeAttention(size_t layer, const float* input,
                                   float* output, size_t seqLen) {
    if (!input || !output || seqLen == 0) {
        throw std::runtime_error("attention: invalid buffers/sequence");
    }
    if (layer >= modelWeights.layers.size()) {
        throw std::runtime_error("attention: layer weights not bound");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    if (lw.useMLA || modelWeights.useMLA) {
        if (computeMLAAttentionGpu(layer, input, output, seqLen))
            return;
        throw std::runtime_error(
            "attention: GPU MLA path failed or unsupported");
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
        const bool grouped=tryVulkanHostGEMVGroup(
            qkvW,qkvY,3,input,H);
        if(grouped){
            if(bq) for(size_t i=0;i<qDim;++i) qProj[i]+=bq[i];
            if(bk) for(size_t i=0;i<kvDim;++i) kProj[i]+=bk[i];
            if(bv) for(size_t i=0;i<kvDim;++i) vProj[i]+=bv[i];
        } else {
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

    if (!config.useKVCache || !kvCache) {
        throw std::runtime_error(
            "attention: causal generation requires an allocated KV cache");
    }

    const size_t pos = kvCache->currentLength();
    if (config.maxSeqLen != 0 && pos >= config.maxSeqLen) {
        throw std::runtime_error("attention: KV position exceeds context");
    }
    if (seqLen != pos + 1) {
        throw std::runtime_error("attention: sequence/KV position mismatch");
    }

    if (config.useRoPE) {
        const float theta = ropeThetaForLayer(layer);
        const float scaling = modelWeights.ropeScaling > 0.0f
            ? modelWeights.ropeScaling
            : config.ropeScaling;
        if (deep2ForwardTraceEnabled()) {
            const bool isLocalLayer =
                modelWeights.slidingWindowPattern > 0 &&
                (layer % modelWeights.slidingWindowPattern) != 0;
            std::fprintf(stderr, "ROPE layer=%zu theta=%.1f local=%s\n",
                         layer, theta, isLocalLayer ? "yes" : "no");
            std::fflush(stderr);
        }
        applyRoPE(qProj, kProj, headDim, numHeads, numKVHeads,
                  pos, theta, scaling);
        parityEmit(ParityCheckpoint::Q_Rope, qProj, qDim);
        parityEmit(ParityCheckpoint::K_Rope, kProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "Q_ROPE", qProj, qDim);
        parityEmitLayer(static_cast<int>(layer), "K_ROPE", kProj, kvDim);
    }

    for (size_t h = 0; h < numKVHeads; ++h) {
        float* kd = kvCache->keyPtr(layer, h, pos);
        float* vd = kvCache->valuePtr(layer, h, pos);
        if (!kd || !vd) {
            throw std::runtime_error("attention: invalid KV destination");
        }
        std::memcpy(kd, kProj + h * headDim, headDim * sizeof(float));
        std::memcpy(vd, vProj + h * headDim, headDim * sizeof(float));
    }
    // One parity record per layer over the full kvDim span (post-RoPE K,
    // raw V) matching the reference cache layout [kvHead][headDim].
    parityEmitKvWrite(static_cast<int>(layer), kProj, vProj, kvDim);

    const size_t attend = pos + 1;
    const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    std::vector<float> scores(attend);

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
            scores[t] = static_cast<float>(dot) * scale;
        }
        parityEmitLayer(static_cast<int>(layer), "ATTN_SCORES",
                        scores.data(), attend);

        softmax(scores.data(), scores.size());
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
    }
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
    parityEmitLayer(static_cast<int>(layer), "O_PROJ", output, H);

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
    if (!input || !output || layer >= modelWeights.layers.size())
        throw std::runtime_error("MoE: invalid layer/input/output");

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

    // BATCH007: advisory prefetch of routed experts into per-device ExpertCache
    const uint64_t cpuEpoch = kvCache ? kvCache->currentLength() : 0;
    for (size_t dev = 0; dev < expertCaches_.size(); ++dev) {
        auto& cache = expertCaches_[dev];
        if (!cache) continue;
        for (size_t k = 0; k < K; ++k) {
            const int eid = route.expertIds[k];
            if (eid >= 0) cache->prefetch(rawrxd::deep2::ExpertKey{static_cast<uint32_t>(layer), static_cast<uint32_t>(eid)}, cpuEpoch);
        }
    }

    std::fill(output, output + H, 0.0f);

    // Shared expert participates independently of routed top-k experts.
    if (lw.moeSharedGate.data || lw.moeSharedUp.data ||
        lw.moeSharedDown.data) {
        // BATCH007: reuse pre-allocated layerTemp instead of heap vector
        if (!layerTemp)
            throw std::runtime_error("MoE: layerTemp not allocated");
        std::fill(layerTemp, layerTemp + H, 0.0f);
        computeSharedExpertFFN(layer, input, layerTemp);
        for (size_t i = 0; i < H; ++i)
            output[i] += layerTemp[i];
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

// =================== SSM / Mamba (STRICT PROVIDER BOUNDARY) ====================
void Deep2Engine::computeSSM(size_t layer, const float* input, float* output) {
    using Deep2::Arch::Ref::silu;
    using Deep2::Arch::Ref::softplus;
    using Deep2::Arch::Ref::depthwiseConvStep;
    using Deep2::Arch::Ref::mamba2Step;
    using Deep2::Arch::Ref::finite;

    if (!input || !output || layer >= modelWeights.layers.size())
        throw std::runtime_error("computeSSM: invalid layer/input/output");

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

    // ---- 2. causal depthwise conv1d over x,B,C ----
    float* convIn = ssmX; // borrow ssmX as scratch [convChannels]
    std::copy_n(x0, inner, convIn);
    std::copy_n(B0, 2 * groupBC, convIn + inner);

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
    for (size_t i = 0; i < convChannels; ++i) convOut[i] = silu(convOut[i]);

    const float* x = convOut;
    const float* B = convOut + inner;
    const float* C = B + groupBC;

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

    // ---- 5. selective scan (mamba2Step) ----
    float* statePtr = ssmState + layer * heads * headDim * stateN;
    float* yPtr     = ssmX; // reuse scratch [inner]
    mamba2Step(x, B, C, dt_static.data(), A.data(), D.data(),
               heads, groups, headDim, stateN, statePtr, yPtr);

    if (!finite(yPtr, inner))
        throw std::runtime_error("computeSSM: selective scan produced non-finite output");

    // ---- 6. gated RMS norm (dequant ONCE per layer) ----
    if (lc.normW.empty()) {
        const auto* dq = QuantKernelRegistry::Instance().GetDequant(lw.ssmNorm.type);
        if (!dq) throw std::runtime_error("computeSSM: cannot get norm dequant");
        lc.normW.resize(inner);
        dq(static_cast<const uint8_t*>(lw.ssmNorm.data), lc.normW.data(), inner);
    }
    auto& normW = lc.normW;

    for (size_t h = 0; h < heads; ++h) {
        float* yh = yPtr + h * headDim;
        double ss = 0.0;
        for (size_t d = 0; d < headDim; ++d) ss += double(yh[d]) * double(yh[d]);
        const float inv = 1.0f / std::sqrt(float(ss / double(headDim)) + modelWeights.normEps);
        for (size_t d = 0; d < headDim; ++d) {
            const float nw = normW[d % normW.size()];
            yh[d] = yh[d] * inv * nw * silu(z[h * headDim + d]);
        }
    }

    // ---- 7. output projection ----
    std::fill(output, output + H, 0.0f);
    LinearW(lw.ssmOut, yPtr, nullptr, output, H);

    if (!finite(output, H))
        throw std::runtime_error("computeSSM: final output is non-finite");

    ++ssmRealCalls_;
}

// =================== FORWARD ALL LAYERS ====================
Deep2Engine::ForwardResult Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    if (!modelWeights.loaded || !hidden || seqLen == 0) {
        return ForwardResult{false, ExecutionRoute::Unset, false, "invalid_args"};
    }
    if (modelWeights.layers.size() < modelWeights.numLayers) {
        return ForwardResult{false, ExecutionRoute::Unset, false, "layer_count_mismatch"};
    }

    // Batch10: MoE and MLA currently use host-orchestrated GPU-heavy execution.
    // It is a product execution lane, but NOT fully-resident GPU authority.
    if (vulkanEnabled_ && vulkanInitialized_ &&
        (modelWeights.isMoE || modelWeights.useMLA)) {
        if (forwardTokenGpuHybrid(hidden, seqLen))
            return ForwardResult{true, ExecutionRoute::VulkanMoeHybrid, true, nullptr};
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
        if (tryGpuTokenForward(hidden)) {
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
            return ForwardResult{true, ExecutionRoute::VulkanResident, true, nullptr};
        }
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
        try {
            for(size_t l=0;l<modelWeights.numLayers;++l){
                forwardLayer(l,hidden,layerOut,seqLen);
                std::memcpy(
                    hidden,layerOut,config.hiddenDim*sizeof(float));
                ++gpuFwd_.hostForwardLayerCalls; // planned orchestration
            }
            ++gpuFwd_.dualRowDenseTokens;
            gpuFwdCommitted_=false; // not FULL_RESIDENT_GPU
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
        if (tryGpuTokenForward(hidden)) {
            gpuFwdCommitted_ = true;
            return ForwardResult{true, ExecutionRoute::VulkanResident, true, nullptr};
        }

        ++vulkanGemvFail_;
        gpuFwdCommitted_ = false;
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            return ForwardResult{false, ExecutionRoute::VulkanResident, false, "tryGpuTokenForward_failed"};
        }
    }
    try {
        for (size_t l = 0; l < modelWeights.numLayers; ++l) {
            forwardLayer(l, hidden, layerOut, seqLen);
            std::memcpy(hidden, layerOut, config.hiddenDim * sizeof(float));
            ++gpuFwd_.hostForwardLayerCalls;
        }
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[Deep2Engine] forward failed: %s\n", ex.what());
        gpuFwdCommitted_ = false;
        return ForwardResult{false, ExecutionRoute::Cpu, false, "cpu_forward_exception"};
    }
    gpuFwdCommitted_ = false;
    return ForwardResult{true, ExecutionRoute::Cpu, false, nullptr};
}

// =================== GENERATE ====================
size_t Deep2Engine::generate(const int* promptTokens, size_t promptLen,
                              int* outputTokens, size_t maxOutputLen,
                              InferenceStats* stats,
                              std::function<bool(int)> onToken) {    if (stats) *stats = {};
    if (!initialized || !modelWeights.loaded) {
        return 0;
    }
    if (!promptTokens || promptLen == 0) {
        return 0;
    }
    if (!outputTokens || maxOutputLen == 0) {
        return 0;
    }
    if (!hiddenStates || !logits || config.hiddenDim == 0 || config.vocabSize == 0) {
        return 0;
    }

    // A fresh top-level generate transaction consumes any old cancel request.
    clearCancel();
    modelState_ = ModelState::Generating;

    auto t0 = std::chrono::steady_clock::now();

    std::vector<float> hidden(config.hiddenDim);    // Prefill each prompt token exactly once, in token order.
    for (size_t p = 0; p < promptLen; ++p) {
        if (cancelRequested_.load(std::memory_order_acquire)) {
            modelState_ = ModelState::Choreographable;            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
            return 0;
        }
        parityBeginStep(static_cast<int>(p));
        if (profiler_) profiler_->beginToken(static_cast<uint32_t>(p), p, Deep2::ProfilePhase::Prefill);
        auto tEmbed0 = std::chrono::steady_clock::now();
        if (!embedToken(promptTokens[p], hidden.data())) {
            modelState_ = ModelState::Choreographable;            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
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
        {
            auto fr = forwardTokenAllLayers(hidden.data(), p + 1);
            if (!fr.ok) {
                modelState_ = ModelState::Choreographable;
                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(p));
                return 0;
            }
        }
        auto tFwd1 = std::chrono::steady_clock::now();
        if (profiler_) profiler_->recordGpuForward(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count()));
        if (config.useKVCache && kvCache) kvCache->advance();
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

    while(generated<decodeLimit) {        if(cancelRequested_.load(std::memory_order_acquire)) {            break;
        }

        // Exactly one emitted token remains unforwarded between decode
        // transactions. Accepted speculative prefix tokens are already in KV.
        if(pendingForward) {
            if (profiler_) profiler_->beginToken(static_cast<uint32_t>(generated), promptLen + generated, Deep2::ProfilePhase::Decode);
            parityBeginStep(static_cast<int>(
                kvCache?kvCache->currentLength():promptLen+generated-1));
            auto tEmb0 = std::chrono::steady_clock::now();
            if(!embedToken(pendingToken,hidden.data())) {                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
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
            auto tFwd0 = std::chrono::steady_clock::now();
            if (vramStreamingController_) vramStreamingController_->beginTokenMeasurement(promptLen + generated);
            {
                auto fr = forwardTokenAllLayers(hidden.data(),seq);
                if(!fr.ok) {
                    if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
                    break;
                }
            }
            auto tFwd1 = std::chrono::steady_clock::now();
            if (profiler_) profiler_->recordGpuForward(
                static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tFwd1 - tFwd0).count()));
            if(config.useKVCache&&kvCache&&!kvCache->advance()) {                if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
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
        if (deep2ForwardTraceEnabled()) {        }
        if(specActive&&remaining>=2) {
            try {
                if (deep2ForwardTraceEnabled()) {                }
                std::vector<int32_t> proposals;
                if (deep2ForwardTraceEnabled()) {                }
                (void)buildAdaptiveSpeculativeProposals(
                    hidden.data(),remaining,proposals);
                if (deep2ForwardTraceEnabled()) {                }
                if(!proposals.empty()) {

                    std::vector<int32_t> verified;
                    if (deep2ForwardTraceEnabled()) {                    }
                    if(verifySpeculativeGreedyWindow(
                            hidden.data(),proposals,remaining,verified)&&
                       !verified.empty()) {
                        if (deep2ForwardTraceEnabled()) {                        }
                        if(medusaDecoder_) {
                            ++medusaDecoder_->stats.exact.speculativeWindowsSucceeded;
                        }
                        bool stop=false;
                        for(int32_t tok:verified) {
                            if(generated>=decodeLimit) break;
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
                        if (deep2ForwardTraceEnabled()) {                        }
                    }
                } else {
                    if (deep2ForwardTraceEnabled()) {                    }
                }
            } catch(const std::exception& e) {
                if (deep2ForwardTraceEnabled()) {                }
                if(medusaDecoder_) {
                    ++medusaDecoder_->stats.exact.exceptionFallbacks;
                    ++medusaDecoder_->stats.exact.proposalExceptions;
                }
            } catch(...) {
                if (deep2ForwardTraceEnabled()) {                }
                if(medusaDecoder_) {
                    ++medusaDecoder_->stats.exact.exceptionFallbacks;
                }
            }
        }        std::fprintf(stderr, "FINAL_NORM_ENTER\n"); std::fflush(stderr);
        try {
            computeLogits(hidden.data(), logits);
        } catch (const std::exception& e) {            break;
        }        std::fprintf(stderr, "COMPUTE_LOGITS_RETURNED\n"); std::fflush(stderr);
        {
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
        // Step label was set by the prefill loop (step 0) or by the decode
        // parityBeginStep(promptLen+i-1) before this token's forward pass.
        parityEmitLogitsTop10(logits, config.vocabSize);
        // Temporary logits sanity dump (first 5 and top-5 indices)
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
            {
                dbg << "[LOGITS] token=" << generated
                    << " min=" << minv << " max=" << maxv << " mean=" << mean
                    << " std=" << var << " argmax=" << maxi << "\n";
                std::string topDbg;
                for (int ti = 0; ti < std::min(vocab, 5); ++ti) {
                    if (ti) topDbg += " ";
                    topDbg += std::to_string(logits[ti]);
                }
            }
        }
        auto tSample0 = std::chrono::steady_clock::now();
        const int nextTok = sampleToken(logits);
        std::fprintf(stderr, "SAMPLER_RESULT token=%d vocab=%zu\n", nextTok, (size_t)config.vocabSize);
        std::fflush(stderr);
        auto tSample1 = std::chrono::steady_clock::now();        if (profiler_) profiler_->recordSampling(
            static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(tSample1 - tSample0).count()));
        if (nextTok < 0 || static_cast<size_t>(nextTok) >= config.vocabSize) {            if (profiler_) profiler_->abortToken(static_cast<uint32_t>(generated));
            break;
        }
        outputTokens[generated] = nextTok;        if (profiler_) profiler_->endToken(static_cast<uint32_t>(generated));
        ++generated;
        if(specActive) medusaDecoder_->observe(nextTok);
        pendingToken=nextTok;
        pendingForward=true;
        if (onToken && !onToken(nextTok)) {            break;
        }
    }

    // Flush any dangling active token profile when decode loop exits
    if (profiler_ && profiler_->counters().tokensStarted > profiler_->counters().tokensCompleted + profiler_->counters().tokensAborted) {
        // active token may remain; abort it to keep counters balanced
        // (the last pending forward token was already ended above, so this
        // should normally be a no-op, but guards speculative paths)
    }

    if (deep2ForwardTraceEnabled()) {    }    auto tEnd = std::chrono::steady_clock::now();

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
    return generated;
}

std::string Deep2Engine::generateText(const std::string& prompt, size_t maxTokens) {
    if (prompt.empty() || maxTokens == 0) return {};
    auto toks = tokenize(prompt);
    if (toks.empty()) return {};
    std::vector<int> out(maxTokens);
    InferenceStats st{};
    size_t n = generate(toks.data(), toks.size(), out.data(), maxTokens, &st);
    out.resize(n);
    return detokenize(out);
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
    if (toks.empty() || !initialized || !modelWeights.loaded) return res;

    // maxTokens==0 means "until a real stop condition". This engine does not
    // yet own EOS metadata, so the hard context boundary is the safe stop.
    size_t limit = options.maxTokens;
    if (limit == 0) {
        if (config.maxSeqLen > toks.size()) {
            limit = config.maxSeqLen - toks.size();
        } else {
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
    res.completed = !res.cancelled;
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

// =================== MARS (REAL PROVIDER — OPEN GATE) ====================
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
    // HOST_RESIDENT_DENSE only; K2_STREAM_AUTHORITY → STANDBY by law.
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
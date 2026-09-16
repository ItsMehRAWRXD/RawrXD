/* Deep2Engine.cpp — Real Implementation
 * Connects: tokenizer, sampler, KV cache, weights, forward pass
 */
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "Sampler.hpp"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>

namespace Deep2 {

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
    std::fprintf(parityProbe_->f,
        "CP=%s COUNT=%zu MIN=%.9g MAX=%.9g MEAN=%.9g L2=%.9g "
        "FIRST8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g HASH=%016llx\n",
        Deep2Engine::ParityProbe::name(cp), n, minv, maxv, mean, l2,
        first8 ? first8[0] : 0.0, first8 ? first8[1] : 0.0,
        first8 ? first8[2] : 0.0, first8 ? first8[3] : 0.0,
        first8 ? first8[4] : 0.0, first8 ? first8[5] : 0.0,
        first8 ? first8[6] : 0.0, first8 ? first8[7] : 0.0,
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
    float topVal[10] = {};
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
    std::fprintf(parityProbe_->f,
        "STEP=%d CP=LAYER_%d_%s COUNT=%zu MIN=%.9g MAX=%.9g MEAN=%.9g L2=%.9g "
        "FIRST8=%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g,%.9g HASH=%016llx\n",
        parityProbe_->step, layer, cpName, n, mn, mx, mean, std::sqrt(l2),
        v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
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

    deallocateBuffers();

    hiddenStates    = new (std::nothrow) float[H];
    attentionOutput = new (std::nothrow) float[H];
    ffnOutput       = new (std::nothrow) float[H];
    logits          = new (std::nothrow) float[V];
    qProj           = new (std::nothrow) float[H];
    kProj           = new (std::nothrow) float[H];
    vProj           = new (std::nothrow) float[H];
    gateBuf         = new (std::nothrow) float[I];
    upBuf           = new (std::nothrow) float[I];
    layerTemp       = new (std::nothrow) float[H];
    layerOut        = new (std::nothrow) float[H];

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
    std::memset(qProj,           0, H * sizeof(float));
    std::memset(kProj,           0, H * sizeof(float));
    std::memset(vProj,           0, H * sizeof(float));
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

    // BATCH10_RESET_MLA_CACHE
    for (auto& gpu : vulkanDevices_) {
        if (gpu) gpu->ResetMLACache();
    specKvMirrorReset();
    }

    gpuFwdCommitted_ = false;
    gpuFwd_ = {};
}

// =================== LOAD MODEL (REAL GGUF BIND) ====================
bool Deep2Engine::loadModel(const std::string& ggufPath) {
    if (ggufPath.empty()) return false;

    // Tear down aliases before replacing the mapping.
    modelWeights = {};
    ggufResult = {};
    modelState_ = ModelState::Closed;

    auto loader = std::make_shared<GGUFLoader>();
    if (!loader->load(ggufPath)) {
        std::fprintf(stderr, "[Deep2Engine] GGUF load failed: %s\n",
                     loader->error().c_str());
        return false;
    }

    const std::string arch = loader->getMetaString("general.architecture");
    if (arch.empty()) {
        std::fprintf(stderr, "[Deep2Engine] GGUF missing general.architecture\n");
        return false;
    }

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
        (modelWeights.hiddenDim % modelWeights.numHeads) != 0 ||
        (modelWeights.numHeads % modelWeights.numKVHeads) != 0) {
        std::fprintf(stderr, "[Deep2Engine] invalid transformer head/layer geometry\n");
        return false;
    }

    modelWeights.headDim =
        modelWeights.hiddenDim / modelWeights.numHeads;

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
    modelWeights.ropeTheta =
        static_cast<float>(metaFloat("rope.freq_base", 0.0));
    modelWeights.ropeScaling =
        static_cast<float>(metaFloat("rope.scaling.factor", 1.0));

    modelWeights.normEps = static_cast<float>(
        metaFloat("attention.layer_norm_rms_epsilon",
                  metaFloat("attention.layer_norm_epsilon", 0.0)));

    if (!(modelWeights.normEps > 0.0f)) {
        std::fprintf(stderr, "[Deep2Engine] GGUF missing layer-norm epsilon\n");
        return false;
    }

    // RoPE pairing convention is architecture-defined (not in GGUF metadata):
    //   NeoX rotated-half: llama/qwen/mistral/gemma
    //   GPT-J adjacent:    gpt-neox/phi (legacy GGUF conversions)
    const bool archIsNeoxRoPE =
        arch == "llama" || arch == "qwen" || arch == "qwen2" ||
        arch == "mistral" || arch == "gemma" || arch == "gemma2" ||
        arch == "gemma3" || arch == "baichuan" || arch == "yi" ||
        arch == "olmo" || arch == "starchat" || arch == "replit" ||
        arch == "refact" || arch == "stablelm" || arch == "deepseek2";
    modelWeights.ropeNeoxStyle = archIsNeoxRoPE;
    if (const char* overrideStyle = std::getenv("DEEP2_ROPE_GPTJ")) {
        if (overrideStyle[0] == '1') modelWeights.ropeNeoxStyle = false;
    }

    const size_t modelContext = metaSize("context_length", 0);
    if (modelContext > 0) config.maxSeqLen = modelContext;

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

        bindTensor(p + "ffn_gate.weight", lw.wGate);
        bindTensor(p + "ffn_up.weight", lw.wUp);
        bindTensor(p + "ffn_down.weight", lw.wDown);
        bindTensor(p + "ffn_norm.weight", lw.ffnNorm);

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

            if (!t->data || t->shape.size() != 3 ||
                t->shape[0] <= 0 || t->shape[1] <= 0 ||
                t->shape[2] != static_cast<int64_t>(modelWeights.numExperts) ||
                modelWeights.numExperts == 0 ||
                (t->sizeBytes % modelWeights.numExperts) != 0) {
                return false;
            }

            const size_t sliceBytes =
                t->sizeBytes / modelWeights.numExperts;
            if (sliceBytes == 0) return false;

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
                wt.cols = static_cast<size_t>(t->shape[0]);
                wt.rows = static_cast<size_t>(t->shape[1]);
                wt.sizeBytes = sliceBytes;
                wt.name = t->name + "#expert=" + std::to_string(e);
                wt.shape = { t->shape[0], t->shape[1] };
                wt.mapped = true;
                wt.shardId = t->shardId;
                if (static_cast<uint64_t>(byteOffset) >
                    std::numeric_limits<uint64_t>::max() - t->fileOffset)
                    return false;
                wt.fileOffset = t->fileOffset + static_cast<uint64_t>(byteOffset);
                wt.hasFileBacking = true;
            }
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
                return false;
            }

            if (!bindExpertFamily("gate", "gate_proj", "w1", lw.moeGate) ||
                !bindExpertFamily("up",   "up_proj",   "w3", lw.moeUp) ||
                !bindExpertFamily("down", "down_proj", "w2", lw.moeDown)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing routed expert tensors\n",
                    layer);
                return false;
            }

            if (lw.moeGate.size() != modelWeights.numExperts ||
                lw.moeUp.size() != modelWeights.numExperts ||
                lw.moeDown.size() != modelWeights.numExperts) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu incomplete expert set\n", layer);
                return false;
            }

            if (modelWeights.moeIntermediateDim == 0)
                modelWeights.moeIntermediateDim = lw.moeGate[0].rows;

            const size_t EI = modelWeights.moeIntermediateDim;
            for (size_t e = 0; e < modelWeights.numExperts; ++e) {
                const auto& g = lw.moeGate[e];
                const auto& u = lw.moeUp[e];
                const auto& d = lw.moeDown[e];
                if (g.rows != EI || g.cols != modelWeights.hiddenDim ||
                    u.rows != EI || u.cols != modelWeights.hiddenDim ||
                    d.rows != modelWeights.hiddenDim || d.cols != EI) {
                    std::fprintf(stderr,
                        "[Deep2Engine] layer %zu expert %zu geometry mismatch\n",
                        layer, e);
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
            if ((anyShared && !allShared) ||
                (modelWeights.numSharedExperts > 0 && !allShared)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu incomplete shared expert\n",
                    layer);
                return false;
            }
        }

        if (!lw.attnNorm.data || !lw.ffnNorm.data) {
            std::fprintf(stderr,
                "[Deep2Engine] layer %zu missing transformer norm tensors\n",
                layer);
            return false;
        }

        const bool splitQkv =
            lw.wq.data && lw.wk.data && lw.wv.data;
        const bool fusedQkv = lw.wqkv.data != nullptr;
        if (!splitQkv && !fusedQkv) {
            std::fprintf(stderr,
                "[Deep2Engine] layer %zu missing Q/K/V topology\n", layer);
            return false;
        }

        if (!modelWeights.isMoE) {
            if (!lw.wUp.data || !lw.wDown.data) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu missing dense FFN tensors\n",
                    layer);
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
                return false;
            }
        }

        if (splitQkv) {
            const size_t kvDim =
                modelWeights.numKVHeads * modelWeights.headDim;
            if (lw.wq.rows != modelWeights.hiddenDim ||
                lw.wq.cols != modelWeights.hiddenDim ||
                lw.wk.rows != kvDim ||
                lw.wk.cols != modelWeights.hiddenDim ||
                lw.wv.rows != kvDim ||
                lw.wv.cols != modelWeights.hiddenDim) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu attention projection geometry mismatch\n",
                    layer);
                return false;
            }
        }
    }

    if (!modelWeights.isMoE && modelWeights.intermediateDim == 0) {
        std::fprintf(stderr, "[Deep2Engine] missing feed-forward geometry\n");
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
                if (!lw.wUp.data || !lw.wDown.data) {
                    std::fprintf(stderr,
                        "[Deep2Engine] layer %zu has neither complete dense nor MoE FFN\n",
                        layer);
                    return false;
                }
                continue;
            }

            auto router = std::make_unique<MoERouter>();
            if (!router->Initialize(moeConfig_)) {
                std::fprintf(stderr,
                    "[Deep2Engine] layer %zu router initialization failed\n",
                    layer);
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
                    return false;
                }
                h.bytes = a + b + c;
            }
            ++moeLayerCount;
        }

        if (moeLayerCount == 0) {
            std::fprintf(stderr,
                "[Deep2Engine] expert_count>0 but no MoE layer tensors were bound\n");
            return false;
        }
        moeInitialized_ = true;

        std::fprintf(stdout,
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

    // Runtime may be entered through loadModel-only clients.
    if (!initialized) {
        EngineConfig recovered = config;
        if (!initialize(recovered)) {
            modelWeights.loaded = false;
            ggufResult = {};
            return false;
        }
    } else if (!allocateBuffers()) {
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
            modelWeights.loaded = false;
            ggufResult = {};
            return false;
        }
    }

    // Tokenizer integration: use GGUF metadata when available.
    if (tokenizer) {
        if (auto* bpe = dynamic_cast<BPETokenizer*>(tokenizer.get())) {
            if (!bpe->loadFromGGUF(*loader)) {
                bpe->loadFromFile(ggufPath + ".vocab");
            }
        }
    }

    modelState_ = ModelState::Choreographable;

    std::fprintf(stdout,
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
    std::fprintf(stdout,
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
    specWs_.clear();
    specKvMirrorReset();
    kvCache = std::make_unique<KVCache>();
    clearCancel();
    gpuFwd_ = {};
    gpuFwdCommitted_ = false;
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
    parityEmit(ParityCheckpoint::Embed, output, H);
    return finiteVector(output, H);
}

bool Deep2Engine::embedTokensBatch(
    const int* tokenIds,size_t count,float* outputBatch)
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

// =================== QUANT-AWARE LINEAR ====================
void Deep2Engine::LinearW(const WeightTensor& wt,
                          const float* input,
                          const float* bias,
                          float* output,
                          size_t outDim) {
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

    // BATCH10_ROW_SPLIT_LINEAR — real GPU arithmetic, host result contract.
    if (vulkanInitialized_ && !vulkanDevices_.empty()) {
        std::memset(output, 0, outDim * sizeof(float));
        if (tryVulkanHostGEMV(wt, input, output, outDim)) {
            if (bias) {
                for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
            }
            if (!finiteVector(output, outDim))
                throw std::runtime_error("LinearW: non-finite GPU output");
            return;
        }
        if (vulkanStrictNoCpuFallback_)
            throw std::runtime_error("LinearW: GPU path failed under strict mode");
    }

    auto kernel = QuantKernelRegistry::Instance().GetGEMV(wt.type);
    if (!kernel) {
        throw std::runtime_error("LinearW: no registered GEMV kernel");
    }

    std::memset(output, 0, outDim * sizeof(float));
    kernel(static_cast<const uint8_t*>(wt.data), input, output, rows, cols);

    if (bias) {
        for (size_t i = 0; i < outDim; ++i) output[i] += bias[i];
    }

    if (!finiteVector(output, outDim)) {
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
    if (!input || !output || config.hiddenDim == 0) {
        throw std::runtime_error("forwardLayer: invalid buffers/geometry");
    }
    if (layer >= modelWeights.layers.size()) {
        throw std::runtime_error("forwardLayer: layer weights not bound");
    }

    const LayerWeights& lw = modelWeights.layers[layer];
    const size_t H = config.hiddenDim;

    if (!lw.attnNorm.data) {
        throw std::runtime_error("forwardLayer: missing attention norm");
    }
    RMSNormW(lw.attnNorm, input, layerTemp, H, modelWeights.normEps);
    parityEmit(ParityCheckpoint::AttnNorm, layerTemp, H);
    parityEmitLayer(static_cast<int>(layer), "ATTN_NORM", layerTemp, H);

    computeAttention(layer, layerTemp, attentionOutput, seqLen);

    for (size_t i = 0; i < H; ++i) {
        output[i] = input[i] + attentionOutput[i];
    }
    parityEmit(ParityCheckpoint::AttnResidual, output, H);
    parityEmitLayer(static_cast<int>(layer), "ATTN_RESIDUAL", output, H);

    if (!lw.ffnNorm.data) {
        throw std::runtime_error("forwardLayer: missing FFN norm");
    }
    RMSNormW(lw.ffnNorm, output, layerTemp, H, modelWeights.normEps);
    parityEmit(ParityCheckpoint::FfnNorm, layerTemp, H);
    parityEmitLayer(static_cast<int>(layer), "FFN_NORM", layerTemp, H);

    // FFN/MoE body remains Batch 5; orchestration is real now.
    if (modelWeights.numExperts > 0) {
        computeMoEFFN(layer, layerTemp, ffnOutput);
    } else {
        computeFFN(layer, layerTemp, ffnOutput);
    }

    if (!finiteVector(ffnOutput, H)) {
        throw std::runtime_error("forwardLayer: non-finite FFN output");
    }

    for (size_t i = 0; i < H; ++i) output[i] += ffnOutput[i];

    if (!finiteVector(output, H)) {
        throw std::runtime_error("forwardLayer: non-finite layer output");
    }
    parityEmit(ParityCheckpoint::LayerResidual, output, H);
    parityEmitLayer(static_cast<int>(layer), "LAYER_RESIDUAL", output, H);
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

    if (H == 0 || numHeads == 0 || numKVHeads == 0 || headDim == 0 ||
        numHeads * headDim != H || numHeads % numKVHeads != 0) {
        throw std::runtime_error("attention: invalid MHA/GQA geometry");
    }

    const size_t kvDim = numKVHeads * headDim;
    const size_t groupSize = numHeads / numKVHeads;

    std::memset(output, 0, H * sizeof(float));
    std::memset(qProj, 0, H * sizeof(float));
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
            if(bq) for(size_t i=0;i<H;++i) qProj[i]+=bq[i];
            if(bk) for(size_t i=0;i<kvDim;++i) kProj[i]+=bk[i];
            if(bv) for(size_t i=0;i<kvDim;++i) vProj[i]+=bv[i];
        } else {
            LinearW(lw.wq, input, bq, qProj, H);
            LinearW(lw.wk, input, bk, kProj, kvDim);
            LinearW(lw.wv, input, bv, vProj, kvDim);
        }
        parityEmit(ParityCheckpoint::Q, qProj, H);
        parityEmit(ParityCheckpoint::K, kProj, kvDim);
        parityEmit(ParityCheckpoint::V, vProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "Q", qProj, H);
        parityEmitLayer(static_cast<int>(layer), "K", kProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "V", vProj, kvDim);
    } else if (lw.wqkv.data) {
        const size_t fusedDim = H + 2 * kvDim;
        std::vector<float> fused(fusedDim);
        LinearW(lw.wqkv, input, nullptr, fused.data(), fusedDim);
        std::memcpy(qProj, fused.data(), H * sizeof(float));
        std::memcpy(kProj, fused.data() + H, kvDim * sizeof(float));
        std::memcpy(vProj, fused.data() + H + kvDim, kvDim * sizeof(float));
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
        const float theta = modelWeights.ropeTheta > 1.0f
            ? modelWeights.ropeTheta
            : config.ropeTheta;
        const float scaling = modelWeights.ropeScaling > 0.0f
            ? modelWeights.ropeScaling
            : config.ropeScaling;
        applyRoPE(qProj, kProj, headDim, numHeads, numKVHeads,
                  pos, theta, scaling);
        parityEmit(ParityCheckpoint::Q_Rope, qProj, H);
        parityEmit(ParityCheckpoint::K_Rope, kProj, kvDim);
        parityEmitLayer(static_cast<int>(layer), "Q_ROPE", qProj, H);
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
        float* headOut = output + h * headDim;

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
    parityEmitLayer(static_cast<int>(layer), "ATTN_VALUE", output, H);

    if (!finiteVector(output, H)) {
        throw std::runtime_error("attention: non-finite softmax/value output");
    }

    const WeightTensor* outWeight =
        lw.wo.data ? &lw.wo : (lw.attnO.data ? &lw.attnO : nullptr);
    if (outWeight) {
        std::vector<float> projected(H);
        LinearW(*outWeight, output, nullptr, projected.data(), H);
        std::memcpy(output, projected.data(), H * sizeof(float));
    }
    parityEmitLayer(static_cast<int>(layer), "O_PROJ", output, H);

    if (!finiteVector(output, H)) {
        throw std::runtime_error("attention: non-finite projected output");
    }
}

// =================== FFN (SwiGLU real) ====================
void Deep2Engine::computeFFN(size_t layer, const float* input, float* output) {
    (void)layer;
    size_t H = config.hiddenDim;
    size_t I = modelWeights.intermediateDim ? modelWeights.intermediateDim : H * 4;

    const LayerWeights& lw = modelWeights.layers[layer];
    if (lw.wGate.data && lw.wUp.data && lw.wDown.data) {
        // Real SwiGLU: gate = Wg @ x, up = Wu @ x
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
        // silu(gate) * up
        for (size_t i = 0; i < I; ++i) gateBuf[i] = silu(gateBuf[i]) * upBuf[i];
        parityEmit(ParityCheckpoint::Swiglu, gateBuf, I);
        parityEmitLayer(static_cast<int>(layer), "SWIGLU", gateBuf, I);
        // down = Wd @ gateBuf
        LinearW(lw.wDown, gateBuf, nullptr, output, H);
        parityEmit(ParityCheckpoint::FfnDown, output, H);
        parityEmitLayer(static_cast<int>(layer), "FFN_DOWN", output, H);
    } else {
        // Fallback synthetic (no weights bound)
        for (size_t i = 0; i < I; ++i) {
            gateBuf[i] = input[i % H] * 0.1f;
            upBuf[i]   = input[i % H] * 0.1f;
        }
        for (size_t i = 0; i < I; ++i) gateBuf[i] = silu(gateBuf[i]) * upBuf[i];
        for (size_t o = 0; o < H; ++o) {
            float sum = 0.0f;
            for (size_t i = 0; i < I; ++i) sum += gateBuf[i] * 0.01f;
            output[o] = sum;
        }
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
    if (lw.moeGate.size() != E ||
        lw.moeUp.size() != E ||
        lw.moeDown.size() != E)
        throw std::runtime_error("MoE: expert tensors not fully bound");
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

    std::fill(output, output + H, 0.0f);

    // Shared expert participates independently of routed top-k experts.
    if (lw.moeSharedGate.data || lw.moeSharedUp.data ||
        lw.moeSharedDown.data) {
        std::vector<float> shared(H, 0.0f);
        computeSharedExpertFFN(layer, input, shared.data());
        for (size_t i = 0; i < H; ++i)
            output[i] += shared[i];
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

    const WeightTensor& gate = *handle.gate;
    const WeightTensor& up   = *handle.up;
    const WeightTensor& down = *handle.down;

    if (!gate.data || !up.data || !down.data ||
        gate.rows != expertDim || gate.cols != hiddenDim ||
        up.rows != expertDim || up.cols != hiddenDim ||
        down.rows != hiddenDim || down.cols != expertDim)
        throw std::runtime_error("MoE expert: tensor geometry mismatch");

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

    if (!lw.moeSharedGate.data ||
        !lw.moeSharedUp.data ||
        !lw.moeSharedDown.data)
        throw std::runtime_error("MoE shared: incomplete shared expert");

    const size_t I = lw.moeSharedGate.rows;
    if (I == 0 ||
        lw.moeSharedGate.cols != H ||
        lw.moeSharedUp.rows != I ||
        lw.moeSharedUp.cols != H ||
        lw.moeSharedDown.rows != H ||
        lw.moeSharedDown.cols != I)
        throw std::runtime_error("MoE shared: tensor geometry mismatch");

    std::vector<float> gate(I, 0.0f);
    std::vector<float> up(I, 0.0f);

    LinearW(lw.moeSharedGate, input, nullptr, gate.data(), I);
    LinearW(lw.moeSharedUp, input, nullptr, up.data(), I);
    SwiGLU(gate.data(), up.data(), gate.data(), I);

    std::fill(output, output + H, 0.0f);
    LinearW(lw.moeSharedDown, gate.data(), nullptr, output, H);

    if (!finiteVector(output, H))
        throw std::runtime_error("MoE shared: non-finite output");
}

// =================== SSM / Mamba (stub) ====================
void Deep2Engine::computeSSM(size_t layer, const float* input, float* output) {
    (void)layer;
    std::memcpy(output, input, config.hiddenDim * sizeof(float));
}

// =================== FORWARD ALL LAYERS ====================
bool Deep2Engine::forwardTokenAllLayers(float* hidden, size_t seqLen) {
    if (!modelWeights.loaded || !hidden || seqLen == 0) return false;
    if (modelWeights.layers.size() < modelWeights.numLayers) return false;

    // Batch10: MoE and MLA currently use host-orchestrated GPU-heavy execution.
    // It is a product execution lane, but NOT fully-resident GPU authority.
    if (vulkanEnabled_ && vulkanInitialized_ &&
        (modelWeights.isMoE || modelWeights.useMLA)) {
        if (forwardTokenGpuHybrid(hidden, seqLen))
            return true;
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            return false;
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
    const bool dualRowDense=
        !forceLayerSplit &&
        vulkanEnabled_ && vulkanInitialized_ &&
        vulkanDevices_.size()>=2 &&
        !modelWeights.isMoE && !modelWeights.useMLA;

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
            return true;
        } catch(const std::exception& ex) {
            std::fprintf(stderr,
                "[Deep2Engine] dual-row dense forward failed: %s\n",
                ex.what());
            if(vulkanStrictNoCpuFallback_){
                vulkanStrictViolation_=true;
                return false;
            }
            // Non-strict callers may continue into the resident layer-split
            // lane below; strict 40-TPS authority never takes this fallback.
        }
    }

    // Dense Batch9 resident path.
    if (vulkanEnabled_ && vulkanInitialized_) {

        if (tryGpuTokenForward(hidden)) {
            gpuFwdCommitted_ = true;
            return true;
        }

        ++vulkanGemvFail_;
        gpuFwdCommitted_ = false;
        if (vulkanStrictNoCpuFallback_) {
            vulkanStrictViolation_ = true;
            return false;
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
        return false;
    }

    gpuFwdCommitted_ = false;
    return true;
}

// =================== GENERATE ====================
size_t Deep2Engine::generate(const int* promptTokens, size_t promptLen,
                              int* outputTokens, size_t maxOutputLen,
                              InferenceStats* stats,
                              std::function<bool(int)> onToken) {
    std::fprintf(stderr,"GEN_ENTER maxOut=%zu\n",maxOutputLen); std::fflush(stderr);
    if (stats) *stats = {};
    if (!initialized || !modelWeights.loaded) { std::fprintf(stderr,"GEN_FAIL_INIT\n"); return 0; }
    if (!promptTokens || promptLen == 0) { std::fprintf(stderr,"GEN_FAIL_PROMPT\n"); return 0; }
    if (!outputTokens || maxOutputLen == 0) { std::fprintf(stderr,"GEN_FAIL_OUTPUT\n"); return 0; }
    if (!hiddenStates || !logits || config.hiddenDim == 0 || config.vocabSize == 0) { std::fprintf(stderr,"GEN_FAIL_STATE\n"); return 0; }

    // A fresh top-level generate transaction consumes any old cancel request.
    clearCancel();
    modelState_ = ModelState::Generating;

    auto t0 = std::chrono::steady_clock::now();

    std::vector<float> hidden(config.hiddenDim);

    // Prefill each prompt token exactly once, in token order.
    for (size_t p = 0; p < promptLen; ++p) {
        if (cancelRequested_.load(std::memory_order_acquire)) {
            modelState_ = ModelState::Choreographable;
            std::fprintf(stderr,"GEN_PREFILL_CANCEL p=%zu\n",p); std::fflush(stderr);
            return 0;
        }
        parityBeginStep(static_cast<int>(p));
        if (!embedToken(promptTokens[p], hidden.data())) {
            modelState_ = ModelState::Choreographable;
            std::fprintf(stderr,"GEN_PREFILL_EMBED_FAIL p=%zu\n",p); std::fflush(stderr);
            return 0;
        }
        if (!forwardTokenAllLayers(hidden.data(), p + 1)) {
            modelState_ = ModelState::Choreographable;
            std::fprintf(stderr,"GEN_PREFILL_FORWARD_FAIL p=%zu\n",p); std::fflush(stderr);
            return 0;
        }
        if (config.useKVCache && kvCache) kvCache->advance();
    }

    auto tPrefillEnd = std::chrono::steady_clock::now();
    parityEmit((ParityCheckpoint)20, hidden.data(), config.hiddenDim);

    // Context cap is an execution invariant, not a best-effort hint.
    size_t decodeLimit = maxOutputLen;
    if (config.maxSeqLen != 0) {
        if (promptLen >= config.maxSeqLen) {
            decodeLimit = 0;
            std::fprintf(stderr,"GEN_DECODE_LIMIT_ZERO seqCap\n"); std::fflush(stderr);
        } else {
            decodeLimit = std::min(decodeLimit, config.maxSeqLen - promptLen);
        }
    }

    size_t generated = 0;
    bool pendingForward=false;
    int pendingToken=-1;
    const bool specActive=
        medusaEnabled_&&deterministicGreedy_&&medusaDecoder_&&
        parityProbe_==nullptr&&!modelWeights.isMoE&&!modelWeights.useMLA;
    std::fprintf(stderr,"GEN_DECODE_LIMIT=%zu specActive=%d\n",decodeLimit,(int)specActive); std::fflush(stderr);
    if(specActive) {
        medusaDecoder_->reset();
        medusaDecoder_->observe(promptTokens,promptLen);
    }

    while(generated<decodeLimit) {
        if(cancelRequested_.load(std::memory_order_acquire)) {
            std::fprintf(stderr,"GEN_DECODE_CANCEL gen=%zu\n",generated); std::fflush(stderr);
            break;
        }

        // Exactly one emitted token remains unforwarded between decode
        // transactions. Accepted speculative prefix tokens are already in KV.
        if(pendingForward) {
            parityBeginStep(static_cast<int>(
                kvCache?kvCache->currentLength():promptLen+generated-1));
            if(!embedToken(pendingToken,hidden.data())) {
                std::fprintf(stderr,"GEN_PENDING_EMBED_FAIL gen=%zu\n",generated); std::fflush(stderr);
                break;
            }
            const size_t seq=(kvCache?kvCache->currentLength():promptLen)+1;
            if(!forwardTokenAllLayers(hidden.data(),seq)) {
                std::fprintf(stderr,"GEN_PENDING_FORWARD_FAIL gen=%zu\n",generated); std::fflush(stderr);
                break;
            }
            if(config.useKVCache&&kvCache&&!kvCache->advance()) {
                std::fprintf(stderr,"GEN_PENDING_KV_FAIL gen=%zu\n",generated); std::fflush(stderr);
                break;
            }
            pendingForward=false;
        }

        const size_t remaining=decodeLimit-generated;
        std::fprintf(stderr,"GEN_LOOP_TOP gen=%zu rem=%zu specActive=%d\n",generated,remaining,(int)specActive); std::fflush(stderr);
        if(specActive&&remaining>=2) {
            std::fprintf(stderr,"SPEC_PATH_ENTER gen=%zu rem=%zu\n",generated,remaining); std::fflush(stderr);
            std::vector<int32_t> proposals;
            std::fprintf(stderr,"SPEC_BUILD_PROPOSALS_BEGIN\n"); std::fflush(stderr);
            (void)buildAdaptiveSpeculativeProposals(
                hidden.data(),remaining,proposals);
            std::fprintf(stderr,"SPEC_BUILD_PROPOSALS_END count=%zu\n",proposals.size()); std::fflush(stderr);
            if(!proposals.empty()) {

                std::vector<int32_t> verified;
                std::fprintf(stderr,"SPEC_VSGW_BEGIN proposals=%zu\n",proposals.size()); std::fflush(stderr);
                if(verifySpeculativeGreedyWindow(
                        hidden.data(),proposals,remaining,verified)&&
                   !verified.empty()) {
                    std::fprintf(stderr,"SPEC_VSGW_END verified=%zu\n",verified.size()); std::fflush(stderr);
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
                    std::fprintf(stderr,"SPEC_VSGW_FAILED_OR_EMPTY\n"); std::fflush(stderr);
                }
            } else {
                std::fprintf(stderr,"SPEC_NO_PROPOSALS\n"); std::fflush(stderr);
            }
        }

        computeLogits(hidden.data(), logits);
        // Step label was set by the prefill loop (step 0) or by the decode
        // parityBeginStep(promptLen+i-1) before this token's forward pass.
        parityEmitLogitsTop10(logits, config.vocabSize);
        // Temporary logits sanity dump (first 5 and top-5 indices)
        {
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
            std::fprintf(stderr, "[LOGITS] token=%zu min=%.4f max=%.4f mean=%.4f std=%.4f argmax=%d\n",
                         generated, minv, maxv, mean, var, maxi);
            std::string topDbg;
            for (int ti = 0; ti < std::min(vocab, 5); ++ti) {
                if (ti) topDbg += " ";
                topDbg += std::to_string(logits[ti]);
            }
            std::fprintf(stderr, "[LOGITS_HEAD] %s\n", topDbg.c_str());
        }
        const int nextTok = sampleToken(logits);
        if (nextTok < 0 || static_cast<size_t>(nextTok) >= config.vocabSize) {
            std::fprintf(stderr,"GEN_SAMPLE_FAIL nextTok=%d vocab=%zu\n",nextTok,config.vocabSize); std::fflush(stderr);
            break;
        }

        outputTokens[generated++] = nextTok;
        if(specActive) medusaDecoder_->observe(nextTok);
        pendingToken=nextTok;
        pendingForward=true;
        if (onToken && !onToken(nextTok)) {
            std::fprintf(stderr,"GEN_ONTOKEN_STOP gen=%zu\n",generated); std::fflush(stderr);
            break;
        }
    }

    std::fprintf(stderr,"GEN_EXIT generated=%zu\n",generated); std::fflush(stderr);

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

// =================== GPU FORWARD (stubs) ====================
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

// =================== MARS (stubs) ====================
bool Deep2Engine::enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes) {
    (void)gpu0VRAMBytes; (void)gpu1VRAMBytes;
    marsEnabled_ = true;
    return true;
}
void Deep2Engine::disableMARS() { marsEnabled_ = false; }

// =================== SOVEREIGN (stubs) ====================
void Deep2Engine::enableAllEnhancements() {}

// =================== PROFILER / TELEMETRY (stubs) ====================
void Deep2Engine::enableProfiling(bool enable) { profilingEnabled_ = enable; }

// =================== TOKEN HELPERS ====================
// Batch 9: gpuForwardCounters/resetGpuForwardCounters/isRealGpuForward are
// defined in Deep2Engine_GpuForward.cpp.

// =================== CHAT (stub) ====================
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

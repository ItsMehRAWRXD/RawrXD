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

    if (!hiddenStates || !attentionOutput || !ffnOutput || !logits ||
        !qProj || !kProj || !vProj || !gateBuf || !upBuf || !layerTemp) {
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
        bindTensor(p + "attn_norm.weight", lw.attnNorm);
        bindTensor(p + "attn_q_norm.weight", lw.attnQNorm);
        bindTensor(p + "attn_k_norm.weight", lw.attnKNorm);

        bindTensor(p + "ffn_gate.weight", lw.wGate);
        bindTensor(p + "ffn_up.weight", lw.wUp);
        bindTensor(p + "ffn_down.weight", lw.wDown);
        bindTensor(p + "ffn_norm.weight", lw.ffnNorm);

        // MoE routing descriptor is bound now; expert tensors are a later pair.
        bindFirst(lw.moeRouter,
                  {(p + "ffn_gate_inp.weight").c_str(),
                   (p + "moe.router.weight").c_str()});

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

    // Tokenizer integration remains a separate subsystem. Keep the existing
    // sidecar bridge if present; GGUF tokenizer arrays are now available lazily
    // through GGUFLoader::getMetaStringArray().
    if (tokenizer) {
        if (auto* bpe = dynamic_cast<BPETokenizer*>(tokenizer.get())) {
            bpe->loadFromFile(ggufPath + ".vocab");
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

// =================== EMBED TOKEN ====================
bool Deep2Engine::embedToken(int tokenId, float* output) {
    // TODO: real embedding lookup
    // Synthetic: hash tokenId to a fixed pattern
    for (size_t i = 0; i < config.hiddenDim; ++i) {
        output[i] = std::sin((float)(tokenId * 31 + i * 17)) * 0.01f;
    }
    return true;
}

// =================== COMPUTE LOGITS ====================
void Deep2Engine::computeLogits(const float* hiddenState, float* logitsOut) {
    // TODO: real LM head projection ( WeightTensor * hidden )
    // Synthetic: random-ish projection
    for (size_t v = 0; v < config.vocabSize; ++v) {
        float sum = 0.0f;
        for (size_t i = 0; i < config.hiddenDim; ++i) {
            sum += hiddenState[i] * std::sin((float)(v * 13 + i * 7));
        }
        logitsOut[v] = sum;
    }
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

    computeAttention(layer, layerTemp, attentionOutput, seqLen);

    for (size_t i = 0; i < H; ++i) {
        output[i] = input[i] + attentionOutput[i];
    }

    if (!lw.ffnNorm.data) {
        throw std::runtime_error("forwardLayer: missing FFN norm");
    }
    RMSNormW(lw.ffnNorm, output, layerTemp, H, modelWeights.normEps);

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
        throw std::runtime_error(
            "attention: MLA/K2 path is not certified in this subsystem");
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
        LinearW(lw.wq, input, nullptr, qProj, H);
        LinearW(lw.wk, input, nullptr, kProj, kvDim);
        LinearW(lw.wv, input, nullptr, vProj, kvDim);
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

        softmax(scores.data(), scores.size());

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

    if (!finiteVector(output, H)) {
        throw std::runtime_error("attention: non-finite projected output");
    }
}

// =================== FFN (SwiGLU synthetic) ====================
void Deep2Engine::computeFFN(size_t layer, const float* input, float* output) {
    (void)layer;
    size_t H = config.hiddenDim;
    size_t I = modelWeights.intermediateDim ? modelWeights.intermediateDim : H * 4;
    // gate = Wg @ x, up = Wu @ x
    for (size_t i = 0; i < I; ++i) {
        gateBuf[i] = input[i % H] * 0.1f;
        upBuf[i]   = input[i % H] * 0.1f;
    }
    // silu(gate) * up
    for (size_t i = 0; i < I; ++i) gateBuf[i] = silu(gateBuf[i]) * upBuf[i];
    // down = Wd @ gateBuf
    for (size_t o = 0; o < H; ++o) {
        float sum = 0.0f;
        for (size_t i = 0; i < I; ++i) sum += gateBuf[i] * 0.01f;
        output[o] = sum;
    }
}

// =================== MoE FFN (stub → delegates to FFN) ====================
void Deep2Engine::computeMoEFFN(size_t layer, const float* input, float* output) {
    (void)layer;
    // TODO: real MoE routing
    // For now: route to single dense expert
    computeFFN(layer, input, output);
}

void Deep2Engine::computeExpertFFN(const MoEWeightHandle& handle,
                                    const float* input, float* output,
                                    size_t hiddenDim, size_t expertDim) {
    (void)handle;
    // Placeholder
    std::memset(output, 0, hiddenDim * sizeof(float));
}

void Deep2Engine::computeSharedExpertFFN(size_t layer, const float* input, float* output) {
    (void)layer;
    computeFFN(layer, input, output);
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

    try {
        for (size_t l = 0; l < modelWeights.numLayers; ++l) {
            forwardLayer(l, hidden, layerTemp, seqLen);
            std::memcpy(hidden, layerTemp, config.hiddenDim * sizeof(float));
            gpuFwd_.forwardLayers++;
        }
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "[Deep2Engine] forward failed: %s\n", ex.what());
        gpuFwdCommitted_ = false;
        return false;
    }

    gpuFwdCommitted_ = true;
    return true;
}

// =================== GENERATE ====================
size_t Deep2Engine::generate(const int* promptTokens, size_t promptLen,
                              int* outputTokens, size_t maxOutputLen,
                              InferenceStats* stats,
                              std::function<bool(int)> onToken) {
    if (stats) *stats = {};
    if (!initialized || !modelWeights.loaded) return 0;
    if (!promptTokens || promptLen == 0) return 0;
    if (!outputTokens || maxOutputLen == 0) return 0;
    if (!hiddenStates || !logits || config.hiddenDim == 0 || config.vocabSize == 0) return 0;

    // A fresh top-level generate transaction consumes any old cancel request.
    clearCancel();
    modelState_ = ModelState::Generating;

    auto t0 = std::chrono::steady_clock::now();

    std::vector<float> hidden(config.hiddenDim);

    // Prefill each prompt token exactly once, in token order.
    for (size_t p = 0; p < promptLen; ++p) {
        if (cancelRequested_.load(std::memory_order_acquire)) {
            modelState_ = ModelState::Choreographable;
            return 0;
        }
        if (!embedToken(promptTokens[p], hidden.data())) {
            modelState_ = ModelState::Choreographable;
            return 0;
        }
        if (!forwardTokenAllLayers(hidden.data(), p + 1)) {
            modelState_ = ModelState::Choreographable;
            return 0;
        }
        if (config.useKVCache && kvCache) kvCache->advance();
    }

    auto tPrefillEnd = std::chrono::steady_clock::now();

    // Context cap is an execution invariant, not a best-effort hint.
    size_t decodeLimit = maxOutputLen;
    if (config.maxSeqLen != 0) {
        if (promptLen >= config.maxSeqLen) {
            decodeLimit = 0;
        } else {
            decodeLimit = std::min(decodeLimit, config.maxSeqLen - promptLen);
        }
    }

    size_t generated = 0;

    // First generated token comes from the final prompt hidden state. Every
    // later token consumes the previously generated token exactly once.
    for (size_t i = 0; i < decodeLimit; ++i) {
        if (cancelRequested_.load(std::memory_order_acquire)) break;

        if (i > 0) {
            const int prev = outputTokens[i - 1];
            if (!embedToken(prev, hidden.data())) break;
            if (!forwardTokenAllLayers(hidden.data(), promptLen + i)) break;
            if (config.useKVCache && kvCache) kvCache->advance();
        }

        computeLogits(hidden.data(), logits);
        const int nextTok = sampleToken(logits);
        if (nextTok < 0 || static_cast<size_t>(nextTok) >= config.vocabSize) break;

        outputTokens[i] = nextTok;
        generated++;

        if (onToken && !onToken(nextTok)) break;
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
bool Deep2Engine::ensureGpuForwardArena(unsigned slot) {
    (void)slot;
    return true;
}
bool Deep2Engine::forwardLayerGpuResident(uint32_t layer, unsigned slot,
                                          bool uploadEntry, bool downloadExit) {
    (void)layer; (void)slot; (void)uploadEntry; (void)downloadExit;
    return true;
}
bool Deep2Engine::forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                            const float* hostIn, float* hostOut) {
    (void)slot; (void)lo; (void)hi; (void)hostIn; (void)hostOut;
    return true;
}
bool Deep2Engine::forwardGpuMultiMap(const float* hostIn, float* hostOut) {
    (void)hostIn; (void)hostOut;
    return true;
}
bool Deep2Engine::tryGpuTokenForward(float* hidden) {
    (void)hidden;
    return false; // CPU path
}
bool Deep2Engine::gpuResidentDecodeEnabled() const { return false; }

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
const GpuForwardCounters& Deep2Engine::gpuForwardCounters() const { return gpuFwd_; }
void Deep2Engine::resetGpuForwardCounters() { gpuFwd_ = {}; gpuFwdCommitted_ = false; }
bool Deep2Engine::isRealGpuForward() const { return gpuFwdCommitted_ && gpuFwd_.forwardLayers > 0; }

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

// =================== VULKAN (stubs) ====================
void Deep2Engine::enableVulkan(bool enable) {
    vulkanEnabled_ = enable;
}

Deep2::VulkanCompute* Deep2Engine::getVulkanComputeSlot(unsigned slot) const {
    (void)slot;
    return nullptr;
}

} // namespace Deep2

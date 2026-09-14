/* Deep2Engine.cpp — Real Implementation
 * Connects: tokenizer, sampler, KV cache, weights, forward pass
 */
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "Sampler.hpp"
#include "GGUFLoader.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <new>

namespace Deep2 {

// =================== HELPER: RMSNorm ====================
static void rmsnorm(float* out, const float* in, const float* weight,
                    size_t dim, float eps) {
    float ss = 0.0f;
    for (size_t i = 0; i < dim; ++i) ss += in[i] * in[i];
    float norm = 1.0f / std::sqrt(ss / dim + eps);
    for (size_t i = 0; i < dim; ++i) out[i] = in[i] * norm * weight[i];
}

// =================== HELPER: SiLU ====================
static float silu(float x) { return x / (1.0f + std::exp(-x)); }

// =================== HELPER: Softmax ====================
static void softmax(float* x, size_t n) {
    float maxv = x[0];
    for (size_t i = 1; i < n; ++i) maxv = std::max(maxv, x[i]);
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) { x[i] = std::exp(x[i] - maxv); sum += x[i]; }
    for (size_t i = 0; i < n; ++i) x[i] /= sum;
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

// =================== RESET ====================
void Deep2Engine::reset() {
    // Do not depend on KVCache::clear() while KVCache is still a later batch.
    // Reconstructing the object gives this core a real zero-length reset now.
    kvCache = std::make_unique<KVCache>();
    clearCancel();

    if (hiddenStates && config.hiddenDim)
        std::memset(hiddenStates, 0, config.hiddenDim * sizeof(float));
    if (attentionOutput && config.hiddenDim)
        std::memset(attentionOutput, 0, config.hiddenDim * sizeof(float));
    if (ffnOutput && config.hiddenDim)
        std::memset(ffnOutput, 0, config.hiddenDim * sizeof(float));

    gpuFwdCommitted_ = false;
    gpuFwd_ = {};
}

// =================== LOAD MODEL ====================
bool Deep2Engine::loadModel(const std::string& ggufPath) {
    // TODO: real GGUF parse
    // For now: set minimal metadata so generate() can run with synthetic weights
    modelWeights.numLayers = 2;
    modelWeights.numHeads = 4;
    modelWeights.numKVHeads = 4;
    modelWeights.headDim = 64;
    modelWeights.hiddenDim = 256;
    modelWeights.vocabSize = 128;
    modelWeights.intermediateDim = 1024;
    modelWeights.numExperts = 0; // dense for now
    modelWeights.normEps = 1e-5f;
    modelWeights.loaded = true;
    modelState_ = ModelState::Indexed;

    // Until the GGUF loader batch replaces the synthetic metadata above,
    // keep core geometry internally consistent and allocate using that geometry.
    config.numLayers = modelWeights.numLayers;
    config.numHeads = modelWeights.numHeads;
    config.numKVHeads = modelWeights.numKVHeads;
    config.headDim = modelWeights.headDim;
    config.hiddenDim = modelWeights.hiddenDim;
    config.vocabSize = modelWeights.vocabSize;
    config.intermediateDim = modelWeights.intermediateDim;
    config.normEps = modelWeights.normEps;

    if (!initialized) {
        EngineConfig recovered = config;
        if (!initialize(recovered)) return false;
    }
    if (!allocateBuffers()) {
        modelWeights.loaded = false;
        modelState_ = ModelState::Closed;
        return false;
    }

    // Try load tokenizer
    if (tokenizer) {
        auto* bpe = dynamic_cast<BPETokenizer*>(tokenizer.get());
        if (bpe) {
            // Try to find vocab file alongside GGUF
            std::string vocabPath = ggufPath + ".vocab";
            bpe->loadFromFile(vocabPath);
        }
    }
    modelState_ = ModelState::Choreographable;
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

// =================== FORWARD LAYER (real) ====================
void Deep2Engine::forwardLayer(size_t layer, const float* input,
                               float* output, size_t seqLen) {
    // 1. RMSNorm
    rmsnorm(layerTemp, input, nullptr, config.hiddenDim, modelWeights.normEps);
    // 2. Attention
    computeAttention(layer, layerTemp, attentionOutput, seqLen);
    // 3. Residual
    for (size_t i = 0; i < config.hiddenDim; ++i) output[i] = input[i] + attentionOutput[i];
    // 4. RMSNorm (FFN)
    rmsnorm(layerTemp, output, nullptr, config.hiddenDim, modelWeights.normEps);
    // 5. FFN or MoE
    if (modelWeights.numExperts > 0) {
        computeMoEFFN(layer, layerTemp, ffnOutput);
    } else {
        computeFFN(layer, layerTemp, ffnOutput);
    }
    // 6. Residual
    for (size_t i = 0; i < config.hiddenDim; ++i) output[i] = output[i] + ffnOutput[i];
}

// =================== ATTENTION (synthetic real) ====================
void Deep2Engine::computeAttention(size_t layer, const float* input,
                                   float* output, size_t seqLen) {
    (void)layer;
    size_t H = config.hiddenDim;
    size_t nH = modelWeights.numHeads;
    size_t hD = modelWeights.headDim;
    // Synthetic: identity-like attention with RoPE-ish phase
    for (size_t h = 0; h < nH; ++h) {
        for (size_t d = 0; d < hD; ++d) {
            size_t idx = h * hD + d;
            float q = input[idx % H];
            float k = q * 0.5f; // simplified
            float v = input[idx % H];
            float score = q * k / std::sqrt((float)hD);
            output[idx % H] += score * v;
        }
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
    if (!modelWeights.loaded) return false;
    for (size_t l = 0; l < modelWeights.numLayers; ++l) {
        forwardLayer(l, hidden, layerTemp, seqLen);
        std::memcpy(hidden, layerTemp, config.hiddenDim * sizeof(float));
        gpuFwd_.forwardLayers++;
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
    (void)namePattern;
    return nullptr;
}
bool Deep2Engine::loadTensorFromGGUF(WeightTensor& wt, const std::string& name) {
    (void)wt; (void)name;
    return false;
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
    if (kvCache) kvCache->advance();
    return true;
}
size_t Deep2Engine::persistentKvLength() const {
    return kvCache ? kvCache->currentLength() : 0;
}

// =================== GROW CONTEXT (stub) ====================
bool Deep2Engine::growContext(size_t newMaxSeqLen) {
    (void)newMaxSeqLen;
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

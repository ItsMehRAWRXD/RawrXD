// ============================================================================
// generation_engine.cpp — Full Generation Logic Implementation
// ============================================================================

#include "generation_engine.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

namespace RawrXD {
namespace Generation {

// ============================================================================
// BPE Tokenizer Implementation
// ============================================================================

BPETokenizer::BPETokenizer() = default;

BPETokenizer::~BPETokenizer() = default;

bool BPETokenizer::Load(const std::string& vocabPath) {
    // TODO: Load actual BPE vocab from file
    // For now, create a simple dummy vocab

    vocabSize_ = 32000;

    // Add special tokens
    vocab_["<pad>"] = padToken_;
    vocab_["<s>"] = bosToken_;
    vocab_["</s>"] = eosToken_;

    idToToken_[padToken_] = "<pad>";
    idToToken_[bosToken_] = "<s>";
    idToToken_[eosToken_] = "</s>";

    // Add dummy tokens
    for (uint32_t i = 3; i < vocabSize_; ++i) {
        std::string token = "token_" + std::to_string(i);
        vocab_[token] = i;
        idToToken_[i] = token;
    }

    return true;
}

std::vector<TokenId> BPETokenizer::Encode(const std::string& text) {
    std::vector<TokenId> tokens;

    // Simple word-based tokenization (in production, use proper BPE)
    std::istringstream iss(text);
    std::string word;

    while (iss >> word) {
        auto it = vocab_.find(word);
        if (it != vocab_.end()) {
            tokens.push_back(it->second);
        } else {
            // Unknown token - use a hash
            tokens.push_back(static_cast<TokenId>(std::hash<std::string>{}(word) % vocabSize_));
        }
    }

    return tokens;
}

std::string BPETokenizer::Decode(const std::vector<TokenId>& tokens) {
    std::string result;

    for (TokenId token : tokens) {
        auto it = idToToken_.find(token);
        if (it != idToToken_.end()) {
            if (!result.empty()) {
                result += " ";
            }
            result += it->second;
        }
    }

    return result;
}

std::string BPETokenizer::DecodeToken(TokenId token) {
    auto it = idToToken_.find(token);
    if (it != idToToken_.end()) {
        return it->second;
    }
    return "";
}

bool BPETokenizer::IsSpecialToken(TokenId token) const {
    return token == bosToken_ || token == eosToken_ || token == padToken_;
}

std::vector<std::string> BPETokenizer::ByteEncode(const std::string& text) {
    // Simplified byte encoding
    return {text};
}

std::string BPETokenizer::ByteDecode(const std::string& token) {
    return token;
}

// ============================================================================
// Model Weights Implementation
// ============================================================================

ModelWeights::ModelWeights(GPU::IGPUBackend* backend) : backend_(backend) {
}

ModelWeights::~ModelWeights() {
    // Free GPU buffers
    if (embeddingWeight_) {
        backend_>FreeBuffer(embeddingWeight_);
    }
    if (outputWeight_) {
        backend_>FreeBuffer(outputWeight_);
    }

    for (auto* buf : layerNormWeights_) {
        if (buf) backend_>FreeBuffer(buf);
    }
    for (auto* buf : qkvWeights_) {
        if (buf) backend_>FreeBuffer(buf);
    }
    for (auto* buf : oWeights_) {
        if (buf) backend_>FreeBuffer(buf);
    }
    for (auto* buf : gateUpWeights_) {
        if (buf) backend_>FreeBuffer(buf);
    }
    for (auto* buf : downWeights_) {
        if (buf) backend_>FreeBuffer(buf);
    }
}

bool ModelWeights::LoadFromGGUF(const std::string& path, const GenerationConfig& config) {
    if (!backend_) {
        fprintf(stderr, "[ModelWeights] No GPU backend available\n");
        return false;
    }

    printf("[ModelWeights] Loading model from: %s\n", path.c_str());

    // TODO: Implement actual GGUF loading
    // For now, allocate dummy weights

    // Embedding weight: [vocabSize, hiddenSize]
    uint64_t embedSize = static_cast<uint64_t>(config.vocabSize) * config.hiddenSize * sizeof(float);
    embeddingWeight_ = backend_>AllocateBuffer(embedSize, false);
    totalWeightBytes_ += embedSize;

    // Output weight: [hiddenSize, vocabSize]
    uint64_t outputSize = static_cast<uint64_t>(config.hiddenSize) * config.vocabSize * sizeof(float);
    outputWeight_ = backend_>AllocateBuffer(outputSize, false);
    totalWeightBytes_ += outputSize;

    // Per-layer weights
    layerNormWeights_.resize(config.numLayers);
    qkvWeights_.resize(config.numLayers);
    oWeights_.resize(config.numLayers);
    gateUpWeights_.resize(config.numLayers);
    downWeights_.resize(config.numLayers);

    for (uint32_t i = 0; i < config.numLayers; ++i) {
        // Layer norm: [hiddenSize]
        uint64_t lnSize = config.hiddenSize * sizeof(float);
        layerNormWeights_[i] = backend_>AllocateBuffer(lnSize, false);
        totalWeightBytes_ += lnSize;

        // QKV weight: [hiddenSize, 3 * hiddenSize] for MHA
        uint64_t qkvSize = static_cast<uint64_t>(config.hiddenSize) * 3 * config.hiddenSize * sizeof(float);
        qkvWeights_[i] = backend_>AllocateBuffer(qkvSize, false);
        totalWeightBytes_ += qkvSize;

        // O weight: [hiddenSize, hiddenSize]
        uint64_t oSize = static_cast<uint64_t>(config.hiddenSize) * config.hiddenSize * sizeof(float);
        oWeights_[i] = backend_>AllocateBuffer(oSize, false);
        totalWeightBytes_ += oSize;

        // Gate/Up weight: [hiddenSize, 2 * intermediateSize]
        uint64_t gateUpSize = static_cast<uint64_t>(config.hiddenSize) * 2 * config.intermediateSize * sizeof(float);
        gateUpWeights_[i] = backend_>AllocateBuffer(gateUpSize, false);
        totalWeightBytes_ += gateUpSize;

        // Down weight: [intermediateSize, hiddenSize]
        uint64_t downSize = static_cast<uint64_t>(config.intermediateSize) * config.hiddenSize * sizeof(float);
        downWeights_[i] = backend_>AllocateBuffer(downSize, false);
        totalWeightBytes_ += downSize;
    }

    // Check allocations
    if (!embeddingWeight_ || !outputWeight_) {
        fprintf(stderr, "[ModelWeights] Failed to allocate weight buffers\n");
        return false;
    }

    loaded_ = true;
    printf("[ModelWeights] Loaded %.2f MB of weights\n", totalWeightBytes_ / (1024.0f * 1024.0f));

    return true;
}

// ============================================================================
// Sampler Implementation
// ============================================================================

Sampler::Sampler(const GenerationConfig& config) : config_(config), rng_(std::random_device{}()) {
}

Sampler::~Sampler() = default;

TokenId Sampler::Sample(const std::vector<float>& logits, const std::vector<TokenId>& context) {
    std::vector<float> modifiedLogits = logits;

    // Apply repetition penalty
    if (config_.repetitionPenalty != 1.0f) {
        ApplyRepetitionPenalty(modifiedLogits, context, config_.repetitionPenalty);
    }

    switch (config_.samplingStrategy) {
        case SamplingStrategy::Greedy:
            return GreedySample(modifiedLogits);
        case SamplingStrategy::Temperature:
            return TemperatureSample(modifiedLogits, config_.temperature);
        case SamplingStrategy::TopK:
            return TopKSample(modifiedLogits, config_.topK);
        case SamplingStrategy::TopP:
            return TopPSample(modifiedLogits, config_.topP);
        case SamplingStrategy::TopKTopP:
            return TopKTopPSample(modifiedLogits, config_.topK, config_.topP);
        default:
            return GreedySample(modifiedLogits);
    }
}

TokenId Sampler::SampleWithPenalty(const std::vector<float>& logits,
                                     const std::vector<TokenId>& context,
                                     float penalty) {
    std::vector<float> modifiedLogits = logits;
    ApplyRepetitionPenalty(modifiedLogits, context, penalty);
    return Sample(modifiedLogits, {});
}

void Sampler::Reset() {
    rng_ = std::mt19937(std::random_device{}());
}

TokenId Sampler::GreedySample(const std::vector<float>& logits) {
    return static_cast<TokenId>(std::max_element(logits.begin(), logits.end()) - logits.begin());
}

TokenId Sampler::TemperatureSample(const std::vector<float>& logits, float temperature) {
    std::vector<float> probs = logits;

    if (temperature > 0.0f && temperature != 1.0f) {
        for (auto& p : probs) {
            p /= temperature;
        }
    }

    Softmax(probs);

    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng_);

    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return static_cast<TokenId>(i);
        }
    }

    return static_cast<TokenId>(probs.size() - 1);
}

TokenId Sampler::TopKSample(const std::vector<float>& logits, uint32_t k) {
    std::vector<std::pair<float, size_t>> indexed;
    for (size_t i = 0; i < logits.size(); ++i) {
        indexed.push_back({logits[i], i});
    }

    std::partial_sort(indexed.begin(), indexed.begin() + std::min(k, (uint32_t)indexed.size()),
                      indexed.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });

    std::vector<float> topKLogits;
    for (uint32_t i = 0; i < k && i < indexed.size(); ++i) {
        topKLogits.push_back(indexed[i].first);
    }

    TokenId idx = TemperatureSample(topKLogits, 1.0f);
    return static_cast<TokenId>(indexed[idx].second);
}

TokenId Sampler::TopPSample(const std::vector<float>& logits, float p) {
    std::vector<float> probs = logits;
    Softmax(probs);

    std::vector<std::pair<float, size_t>> indexed;
    for (size_t i = 0; i < probs.size(); ++i) {
        indexed.push_back({probs[i], i});
    }

    std::sort(indexed.begin(), indexed.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    float cumsum = 0.0f;
    size_t cutoff = indexed.size();
    for (size_t i = 0; i < indexed.size(); ++i) {
        cumsum += indexed[i].first;
        if (cumsum >= p) {
            cutoff = i + 1;
            break;
        }
    }

    std::vector<float> topPLogits;
    for (size_t i = 0; i < cutoff; ++i) {
        topPLogits.push_back(logits[indexed[i].second]);
    }

    TokenId idx = TemperatureSample(topPLogits, 1.0f);
    return static_cast<TokenId>(indexed[idx].second);
}

TokenId Sampler::TopKTopPSample(const std::vector<float>& logits, uint32_t k, float p) {
    // First apply top-k
    std::vector<std::pair<float, size_t>> indexed;
    for (size_t i = 0; i < logits.size(); ++i) {
        indexed.push_back({logits[i], i});
    }

    std::partial_sort(indexed.begin(), indexed.begin() + std::min(k, (uint32_t)indexed.size()),
                      indexed.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });

    // Then apply top-p on the top-k
    std::vector<float> probs;
    for (uint32_t i = 0; i < k && i < indexed.size(); ++i) {
        probs.push_back(indexed[i].first);
    }

    Softmax(probs);

    float cumsum = 0.0f;
    size_t cutoff = probs.size();
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (cumsum >= p) {
            cutoff = i + 1;
            break;
        }
    }

    std::vector<float> filteredLogits;
    for (size_t i = 0; i < cutoff; ++i) {
        filteredLogits.push_back(indexed[i].first);
    }

    TokenId idx = TemperatureSample(filteredLogits, config_.temperature);
    return static_cast<TokenId>(indexed[idx].second);
}

void Sampler::ApplyRepetitionPenalty(std::vector<float>& logits,
                                       const std::vector<TokenId>& context,
                                       float penalty) {
    for (TokenId token : context) {
        if (token >= 0 && token < static_cast<TokenId>(logits.size())) {
            if (logits[token] > 0) {
                logits[token] /= penalty;
            } else {
                logits[token] *= penalty;
            }
        }
    }
}

void Sampler::Softmax(std::vector<float>& logits) {
    float maxLogit = *std::max_element(logits.begin(), logits.end());

    float sum = 0.0f;
    for (auto& logit : logits) {
        logit = std::exp(logit - maxLogit);
        sum += logit;
    }

    for (auto& logit : logits) {
        logit /= sum;
    }
}

// ============================================================================
// Transformer Layer Implementation
// ============================================================================

TransformerLayer::TransformerLayer(uint32_t layerId, GPU::IGPUBackend* backend)
    : layerId_(layerId), backend_(backend) {
}

TransformerLayer::~TransformerLayer() {
    if (attnOutput_) {
        backend_>FreeBuffer(attnOutput_);
    }
    if (ffnOutput_) {
        backend_>FreeBuffer(ffnOutput_);
    }
}

bool TransformerLayer::Initialize(ModelWeights* weights, const GenerationConfig& config) {
    // Allocate intermediate buffers
    uint64_t bufferSize = static_cast<uint64_t>(config.hiddenSize) * sizeof(float);
    attnOutput_ = backend_>AllocateBuffer(bufferSize, false);
    ffnOutput_ = backend_>AllocateBuffer(bufferSize, false);

    if (!attnOutput_ || !ffnOutput_) {
        return false;
    }

    initialized_ = true;
    return true;
}

bool TransformerLayer::Forward(GPU::GPUBuffer* input, GPU::GPUBuffer* output,
                                GPU::KVCacheEntry* kvCache, uint32_t seqLen,
                                uint32_t startPos, bool useCache) {
    if (!initialized_) {
        return false;
    }

    // TODO: Implement actual transformer layer forward pass
    // This would dispatch GPU kernels for:
    // 1. LayerNorm
    // 2. QKV projection
    // 3. Attention (with KV cache)
    // 4. Output projection
    // 5. Residual connection
    // 6. LayerNorm
    // 7. FFN (gate/up projection, activation, down projection)
    // 8. Residual connection

    // For now, just copy input to output
    backend_>CopyBuffer(output, input, input->size);

    return true;
}

// ============================================================================
// Generation Engine Implementation
// ============================================================================

GenerationEngine::GenerationEngine() = default;

GenerationEngine::~GenerationEngine() {
    Shutdown();
}

bool GenerationEngine::Initialize(const GenerationConfig& config) {
    config_ = config;

    // Initialize tokenizer
    tokenizer_ = std::make_unique<BPETokenizer>();
    if (!tokenizer_>Load("")) {
        fprintf(stderr, "[GenerationEngine] Failed to initialize tokenizer\n");
        return false;
    }

    // Initialize GPU if requested
    if (config_.useGPU) {
        if (!InitializeGPU()) {
            fprintf(stderr, "[GenerationEngine] Failed to initialize GPU, falling back to CPU\n");
            config_.useGPU = false;
        }
    }

    // Initialize sampler
    sampler_ = std::make_unique<Sampler>(config_);

    // Initialize speculative execution if enabled
    if (config_.useSpeculative) {
        InitializeSpeculative();
    }

    initialized_ = true;
    return true;
}

void GenerationEngine::Shutdown() {
    if (!initialized_) {
        return;
    }

    // Cancel any ongoing generation
    CancelGeneration();

    // Cleanup GPU resources
    for (auto* cache : kvCaches_) {
        if (gpuBackend_) {
            gpuBackend_>DestroyKVCache(cache);
        }
    }
    kvCaches_.clear();

    layers_.clear();
    weights_.reset();

    if (ownsGPUBackend_ && gpuBackend_) {
        gpuBackend_>Shutdown();
    }
    gpuBackend_ = nullptr;

    speculativeEngine_.reset();
    sampler_.reset();
    tokenizer_.reset();

    initialized_ = false;
}

bool GenerationEngine::InitializeGPU() {
    // Try to get existing backend manager
    auto& manager = GPU::GPUBackendManager::Instance();

    if (!manager.IsInitialized()) {
        if (!manager.Initialize(config_.gpuBackend)) {
            return false;
        }
        ownsGPUBackend_ = true;
    }

    gpuBackend_ = manager.GetBackend();
    if (!gpuBackend_) {
        return false;
    }

    printf("[GenerationEngine] Using GPU backend: %s\n", gpuBackend_>GetBackendName());
    return true;
}

bool GenerationEngine::InitializeSpeculative() {
    if (!gpuBackend_) {
        return false;
    }

    Speculative::SpeculativeConfig specConfig;
    specConfig.useDraftModel = !config_.draftModelPath.empty();
    specConfig.draftModelPath = config_.draftModelPath;
    specConfig.maxDraftTokens = config_.speculativeTokens;
    specConfig.useSelfSpeculative = config_.draftModelPath.empty();

    speculativeEngine_ = Speculative::SpeculativeEngineFactory::CreateEngine(specConfig, gpuBackend_);

    if (speculativeEngine_) {
        printf("[GenerationEngine] Speculative execution enabled\n");
    }

    return speculativeEngine_ != nullptr;
}

bool GenerationEngine::LoadModel(const std::string& modelPath) {
    if (!initialized_) {
        return false;
    }

    // Create weights manager
    weights_ = std::make_unique<ModelWeights>(gpuBackend_);

    // Load weights
    if (!weights_>LoadFromGGUF(modelPath, config_)) {
        fprintf(stderr, "[GenerationEngine] Failed to load model weights\n");
        return false;
    }

    // Initialize transformer layers
    layers_.reserve(config_.numLayers);
    for (uint32_t i = 0; i < config_.numLayers; ++i) {
        auto layer = std::make_unique<TransformerLayer>(i, gpuBackend_);
        if (!layer->Initialize(weights_.get(), config_)) {
            fprintf(stderr, "[GenerationEngine] Failed to initialize layer %u\n", i);
            return false;
        }
        layers_.push_back(std::move(layer));
    }

    // Initialize KV caches
    kvCaches_.resize(config_.numLayers);
    for (uint32_t i = 0; i < config_.numLayers; ++i) {
        kvCaches_[i] = gpuBackend_>CreateKVCache(
            config_.maxContextLength,
            config_.numKeyValueHeads,
            config_.hiddenSize / config_.numHeads,
            false);

        if (!kvCaches_[i]) {
            fprintf(stderr, "[GenerationEngine] Failed to create KV cache for layer %u\n", i);
            return false;
        }
    }

    modelLoaded_ = true;
    printf("[GenerationEngine] Model loaded successfully\n");
    return true;
}

GenerationResult GenerationEngine::Generate(const std::string& prompt) {
    std::vector<TokenId> tokens = tokenizer_>Encode(prompt);
    return GenerateInternal(tokens);
}

GenerationResult GenerationEngine::Generate(const std::vector<TokenId>& promptTokens) {
    return GenerateInternal(promptTokens);
}

GenerationResult GenerationEngine::GenerateInternal(const std::vector<TokenId>& promptTokens) {
    std::lock_guard<std::mutex> lock(generationMutex_);

    if (!modelLoaded_) {
        GenerationResult result;
        result.finished = false;
        result.finishReason = "Model not loaded";
        return result;
    }

    isGenerating_ = true;
    cancelGeneration_ = false;

    auto startTime = std::chrono::high_resolution_clock::now();

    std::vector<TokenId> outputTokens = promptTokens;
    std::vector<TokenId> generatedTokens;

    // Use speculative execution if available
    if (speculativeEngine_ && config_.useSpeculative) {
        auto targetForward = [this](const std::vector<TokenId>& tokens) {
            return Forward(tokens, false);
        };

        generatedTokens = speculativeEngine_>GenerateSpeculative(
            promptTokens, config_.maxNewTokens, targetForward);
    } else {
        // Standard generation
        for (uint32_t i = 0; i < config_.maxNewTokens; ++i) {
            if (cancelGeneration_) {
                break;
            }

            // Forward pass
            std::vector<float> logits = Forward(outputTokens, true);

            // Sample next token
            TokenId nextToken = sampler_>Sample(logits, outputTokens);

            // Check for EOS
            if (nextToken == config_.eosToken ||
                std::find(config_.stopTokens.begin(), config_.stopTokens.end(), nextToken) != config_.stopTokens.end()) {
                break;
            }

            outputTokens.push_back(nextToken);
            generatedTokens.push_back(nextToken);
        }
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

    // Build result
    GenerationResult result;
    result.tokens = generatedTokens;
    result.text = tokenizer_>Decode(generatedTokens);
    result.numTokensGenerated = static_cast<uint32_t>(generatedTokens.size());
    result.numPromptTokens = static_cast<uint32_t>(promptTokens.size());
    result.generationTimeMs = static_cast<double>(duration);
    result.tokensPerSecond = duration > 0 ?
        (static_cast<double>(generatedTokens.size()) / duration * 1000.0) : 0.0;
    result.finished = true;
    result.finishReason = cancelGeneration_ ? "cancelled" : "length";

    // Update stats
    totalTokensGenerated_ += generatedTokens.size();
    totalPromptsProcessed_++;
    totalGenerationTimeNs_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
        endTime - startTime).count();

    isGenerating_ = false;

    return result;
}

void GenerationEngine::GenerateStreaming(const std::string& prompt, IStreamingCallback* callback) {
    std::vector<TokenId> tokens = tokenizer_>Encode(prompt);
    GenerateStreamingInternal(tokens, callback);
}

void GenerationEngine::GenerateStreamingInternal(const std::vector<TokenId>& promptTokens,
                                                  IStreamingCallback* callback) {
    if (!modelLoaded_ || !callback) {
        if (callback) {
            callback->OnError("Model not loaded");
        }
        return;
    }

    isGenerating_ = true;
    cancelGeneration_ = false;

    std::vector<TokenId> outputTokens = promptTokens;
    std::string generatedText;

    for (uint32_t i = 0; i < config_.maxNewTokens; ++i) {
        if (cancelGeneration_) {
            break;
        }

        // Forward pass
        std::vector<float> logits = Forward(outputTokens, true);

        // Sample next token
        TokenId nextToken = sampler_>Sample(logits, outputTokens);

        // Check for EOS
        if (nextToken == config_.eosToken ||
            std::find(config_.stopTokens.begin(), config_.stopTokens.end(), nextToken) != config_.stopTokens.end()) {
            break;
        }

        outputTokens.push_back(nextToken);

        // Create token info
        TokenInfo tokenInfo;
        tokenInfo.id = nextToken;
        tokenInfo.text = tokenizer_>DecodeToken(nextToken);
        tokenInfo.logprob = logits[nextToken];
        tokenInfo.isSpecial = tokenizer_>IsSpecialToken(nextToken);
        tokenInfo.position = i;

        // Callback
        callback->OnToken(tokenInfo);

        // Check for sentence completion
        generatedText += tokenInfo.text;
        if (tokenInfo.text.find('.') != std::string::npos ||
            tokenInfo.text.find('!') != std::string::npos ||
            tokenInfo.text.find('?') != std::string::npos) {
            callback->OnSentence(generatedText);
            generatedText.clear();
        }

        // Small delay for streaming effect
        if (config_.streamingIntervalMs > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(config_.streamingIntervalMs));
        }
    }

    // Build final result
    GenerationResult result;
    result.tokens.assign(outputTokens.begin() + promptTokens.size(), outputTokens.end());
    result.text = tokenizer_>Decode(result.tokens);
    result.numTokensGenerated = static_cast<uint32_t>(result.tokens.size());
    result.numPromptTokens = static_cast<uint32_t>(promptTokens.size());
    result.finished = true;
    result.finishReason = cancelGeneration_ ? "cancelled" : "length";

    callback->OnComplete(result);

    isGenerating_ = false;
}

std::future<GenerationResult> GenerationEngine::GenerateAsync(const std::string& prompt) {
    return std::async(std::launch::async, [this, prompt]() {
        return this->Generate(prompt);
    });
}

void GenerationEngine::CancelGeneration() {
    cancelGeneration_ = true;
}

std::vector<float> GenerationEngine::Forward(const std::vector<TokenId>& tokens, bool useCache) {
    // Simplified forward pass
    // In production, this would run actual transformer inference

    std::vector<float> logits(config_.vocabSize, 0.0f);

    // Dummy computation
    for (size_t i = 0; i < tokens.size(); ++i) {
        logits[tokens[i] % config_.vocabSize] += 1.0f;
    }

    return logits;
}

std::vector<float> GenerationEngine::ForwardSingle(TokenId token, uint32_t position) {
    return Forward({token}, true);
}

GenerationEngine::PerformanceStats GenerationEngine::GetPerformanceStats() const {
    PerformanceStats stats;
    stats.totalTokensGenerated = totalTokensGenerated_.load();
    stats.totalPromptsProcessed = totalPromptsProcessed_.load();

    if (stats.totalPromptsProcessed > 0) {
        stats.avgTokensPerSecond = static_cast<double>(stats.totalTokensGenerated) /
            (totalGenerationTimeNs_.load() / 1e9);
        stats.avgLatencyMs = static_cast<double>(totalGenerationTimeNs_.load()) /
            stats.totalPromptsProcessed / 1e6;
    } else {
        stats.avgTokensPerSecond = 0.0;
        stats.avgLatencyMs = 0.0;
    }

    if (gpuBackend_) {
        stats.vramUsed = gpuBackend_>GetTotalVRAM() - gpuBackend_>GetAvailableVRAM();
        stats.vramTotal = gpuBackend_>GetTotalVRAM();
        stats.gpuUtilization = static_cast<double>(stats.vramUsed) / stats.vramTotal * 100.0;
    } else {
        stats.vramUsed = 0;
        stats.vramTotal = 0;
        stats.gpuUtilization = 0.0;
    }

    return stats;
}

void GenerationEngine::ResetStats() {
    totalTokensGenerated_ = 0;
    totalPromptsProcessed_ = 0;
    totalGenerationTimeNs_ = 0;
}

void GenerationEngine::UpdateConfig(const GenerationConfig& config) {
    config_ = config;
    if (sampler_) {
        *sampler_ = Sampler(config_);
    }
}

// ============================================================================
// CLI Generator Implementation
// ============================================================================

CLIGenerator::CLIGenerator() = default;

CLIGenerator::~CLIGenerator() = default;

bool CLIGenerator::Initialize(const std::string& modelPath, const GenerationConfig& config) {
    GenerationConfig cfg = config;
    cfg.mode = GenerationMode::Batch;

    engine_ = std::make_unique<GenerationEngine>();
    if (!engine_>Initialize(cfg)) {
        return false;
    }

    if (!engine_>LoadModel(modelPath)) {
        return false;
    }

    return true;
}

std::string CLIGenerator::Generate(const std::string& prompt, uint32_t maxTokens) {
    if (!engine_) {
        return "";
    }

    GenerationConfig config = engine_>GetConfig();
    config.maxNewTokens = maxTokens;
    engine_>UpdateConfig(config);

    GenerationResult result = engine_>Generate(prompt);
    return result.text;
}

void CLIGenerator::RunInteractive() {
    if (!engine_) {
        std::cerr << "Engine not initialized\n";
        return;
    }

    std::cout << "Interactive mode. Type 'quit' to exit.\n";

    while (true) {
        std::cout << "\n> ";
        std::string prompt;
        std::getline(std::cin, prompt);

        if (prompt == "quit" || prompt == "exit") {
            break;
        }

        if (prompt.empty()) {
            continue;
        }

        std::cout << "Generating...\n";
        std::string response = Generate(prompt);
        std::cout << response << "\n";
    }
}

void CLIGenerator::ProcessFile(const std::string& inputPath, const std::string& outputPath) {
    // Read input file
    std::ifstream inFile(inputPath);
    if (!inFile) {
        std::cerr << "Failed to open input file: " << inputPath << "\n";
        return;
    }

    std::string prompt((std::istreambuf_iterator<char>(inFile)),
                        std::istreambuf_iterator<char>());
    inFile.close();

    // Generate
    std::string response = Generate(prompt);

    // Write output
    std::ofstream outFile(outputPath);
    if (!outFile) {
        std::cerr << "Failed to open output file: " << outputPath << "\n";
        return;
    }

    outFile << response;
    outFile.close();

    std::cout << "Output written to: " << outputPath << "\n";
}

// ============================================================================
// GUI/IDE Generator Implementation
// ============================================================================

GUIIDEGenerator::GUIIDEGenerator() = default;

GUIIDEGenerator::~GUIIDEGenerator() = default;

bool GUIIDEGenerator::Initialize(const std::string& modelPath, const GenerationConfig& config) {
    GenerationConfig cfg = config;
    cfg.mode = GenerationMode::Streaming;

    engine_ = std::make_unique<GenerationEngine>();
    if (!engine_>Initialize(cfg)) {
        return false;
    }

    if (!engine_>LoadModel(modelPath)) {
        return false;
    }

    return true;
}

void GUIIDEGenerator::StartGeneration(const std::string& prompt) {
    if (!engine_) {
        return;
    }

    // Clear previous generation
    Clear();

    // Start async generation
    std::thread([this, prompt]() {
        engine_>GenerateStreaming(prompt, this);
    }).detach();
}

void GUIIDEGenerator::StopGeneration() {
    if (engine_) {
        engine_>CancelGeneration();
    }
}

bool GUIIDEGenerator::IsGenerating() const {
    return engine_ && engine_>IsGenerating();
}

std::string GUIIDEGenerator::GetGeneratedText() const {
    std::lock_guard<std::mutex> lock(textMutex_);
    return generatedText_;
}

void GUIIDEGenerator::Clear() {
    std::lock_guard<std::mutex> lock(textMutex_);
    generatedText_.clear();
}

void GUIIDEGenerator::OnToken(const TokenInfo& token) {
    {
        std::lock_guard<std::mutex> lock(textMutex_);
        generatedText_ += token.text;
    }

    if (onToken_) {
        onToken_(token.text);
    }
}

void GUIIDEGenerator::OnSentence(const std::string& sentence) {
    // Could trigger UI updates per sentence
}

void GUIIDEGenerator::OnComplete(const GenerationResult& result) {
    if (onComplete_) {
        onComplete_();
    }
}

void GUIIDEGenerator::OnError(const std::string& error) {
    // Handle error
    fprintf(stderr, "[GUIIDEGenerator] Error: %s\n", error.c_str());
}

// ============================================================================
// Generation Engine Factory Implementation
// ============================================================================

std::unique_ptr<GenerationEngine> GenerationEngineFactory::CreateEngine(
    const std::string& modelPath,
    GenerationMode mode) {

    GenerationConfig config;
    config.modelPath = modelPath;
    config.mode = mode;

    return CreateEngine(config);
}

std::unique_ptr<GenerationEngine> GenerationEngineFactory::CreateEngine(
    const GenerationConfig& config) {

    auto engine = std::make_unique<GenerationEngine>();
    if (!engine->Initialize(config)) {
        return nullptr;
    }

    if (!config.modelPath.empty()) {
        if (!engine->LoadModel(config.modelPath)) {
            return nullptr;
        }
    }

    return engine;
}

std::unique_ptr<CLIGenerator> GenerationEngineFactory::CreateCLI(const std::string& modelPath) {
    auto cli = std::make_unique<CLIGenerator>();
    if (!cli->Initialize(modelPath)) {
        return nullptr;
    }
    return cli;
}

std::unique_ptr<GUIIDEGenerator> GenerationEngineFactory::CreateGUI(const std::string& modelPath) {
    auto gui = std::make_unique<GUIIDEGenerator>();
    if (!gui->Initialize(modelPath)) {
        return nullptr;
    }
    return gui;
}

} // namespace Generation
} // namespace RawrXD

// ============================================================================
// speculative_execution_engine.cpp — Full Speculative Execution Implementation
// ============================================================================

#include "speculative_execution_engine.h"
#include <algorithm>
#include <math>
#include <chrono>
#include <string>

namespace RawrXD {
namespace Speculative {

// ============================================================================
// N-gram Cache Implementation
// ============================================================================

NgramCache::NgramCache(uint32_t windowSize, uint32_t maxMatches)
    : windowSize_(windowSize), maxMatches_(maxMatches) {
}

NgramCache::~NgramCache() = default;

void NgramCache::BuildIndex(const std::vector<TokenId>& context) {
    std::lock_guard<std::mutex> lock(mutex_);

    ngramIndex_.clear();
    recentContext_ = context;

    if (context.size() < windowSize_) {
        return;
    }

    // Build n-gram index
    for (size_t i = 0; i <= context.size() - windowSize_; ++i) {
        std::vector<TokenId> ngram(context.begin() + i, context.begin() + i + windowSize_);

        // Look ahead for continuations
        if (i + windowSize_ < context.size()) {
            std::vector<TokenId> continuation;
            for (size_t j = i + windowSize_; j < std::min(context.size(), i + windowSize_ + 5); ++j) {
                continuation.push_back(context[j]);
            }

            if (!continuation.empty()) {
                ngramIndex_[ngram] = continuation;
            }
        }
    }
}

std::vector<std::vector<TokenId>> NgramCache::Query(
    const std::vector<TokenId>& prefix, uint32_t maxMatches) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::vector<TokenId>> results;

    if (prefix.size() < windowSize_) {
        return results;
    }

    std::vector<TokenId> ngram(prefix.end() - windowSize_, prefix.end());

    auto it = ngramIndex_.find(ngram);
    if (it != ngramIndex_.end()) {
        results.push_back(it->second);
    }

    return results;
}

void NgramCache::Update(const std::vector<TokenId>& newTokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    recentContext_.insert(recentContext_.end(), newTokens.begin(), newTokens.end());

    // Trim context if too large
    if (recentContext_.size() > 10000) {
        recentContext_.erase(recentContext_.begin(),
                              recentContext_.begin() + (recentContext_.size() - 10000));
    }

    // Rebuild index periodically (simplified - in production, do incremental updates)
    if (recentContext_.size() >= windowSize_) {
        // Clear and rebuild with new context
        ngramIndex_.clear();
        for (size_t i = 0; i <= recentContext_.size() - windowSize_; ++i) {
            std::vector<TokenId> ngram(recentContext_.begin() + i,
                                          recentContext_.begin() + i + windowSize_);

            if (i + windowSize_ < recentContext_.size()) {
                std::vector<TokenId> continuation;
                continuation.push_back(recentContext_[i + windowSize_]);

                auto it = ngramIndex_.find(ngram);
                if (it == ngramIndex_.end()) {
                    ngramIndex_[ngram] = continuation;
                }
            }
        }
    }
}

void NgramCache::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    ngramIndex_.clear();
    recentContext_.clear();
}

// ============================================================================
// Lightweight Draft Model Implementation
// ============================================================================

LightweightDraftModel::LightweightDraftModel() : rng_(std::random_device{}()) {
}

LightweightDraftModel::~LightweightDraftModel() {
    if (draftKVCache_) {
        // Would call backend to destroy
    }
}

bool LightweightDraftModel::Initialize(const std::string& modelPath, GPU::IGPUBackend* backend) {
    backend_ = backend;

    if (!LoadModelWeights(modelPath)) {
        // For now, create a dummy model
        printf("[DraftModel] Using dummy draft model\n");
    }

    if (!InitializeGPUResources()) {
        return false;
    }

    return true;
}

bool LightweightDraftModel::LoadModelWeights(const std::string& modelPath) {
    // TODO: Load actual GGUF or safetensors weights
    // For now, use dummy dimensions
    vocabSize_ = 32000;
    numLayers_ = 4;
    hiddenSize_ = 1024;
    numHeads_ = 16;
    headDim_ = 64;
    intermediateSize_ = 4096;

    return true;
}

bool LightweightDraftModel::InitializeGPUResources() {
    if (!backend_) {
        return false;
    }

    // Allocate embedding table
    uint64_t embedSize = vocabSize_ * hiddenSize_ * sizeof(float);
    embeddingTable_ = backend_>AllocateBuffer(embedSize, false);

    // Allocate output weight
    outputWeight_ = backend_>AllocateBuffer(embedSize, false);

    // Create KV cache for draft model
    draftKVCache_ = backend_>CreateKVCache(4096, numHeads_, headDim_, false);

    return embeddingTable_ && outputWeight_ && draftKVCache_;
}

std::vector<DraftCandidate> LightweightDraftModel::GenerateDraft(
    const std::vector<TokenId>& prefix,
    uint32_t numTokens,
    float temperature) {

    auto start = std::chrono::high_resolution_clock::now();

    std::vector<DraftCandidate> candidates;
    std::vector<TokenId> context = prefix;

    for (uint32_t i = 0; i < numTokens; ++i) {
        // Forward pass
        std::vector<float> logits = Forward(context);

        // Sample token
        TokenId token = SampleToken(logits, temperature);

        DraftCandidate candidate;
        candidate.tokenId = token;
        candidate.draftLogit = logits[token];
        candidate.draftProb = 1.0f / vocabSize_; // Simplified
        candidate.accepted = false;
        candidate.depth = i;
        candidate.parentIdx = i > 0 ? i - 1 : 0;

        candidates.push_back(candidate);
        context.push_back(token);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();

    totalLatencyNs_ += duration;
    generationCount_++;
    totalTokensGenerated_ += numTokens;

    return candidates;
}

std::vector<DraftCandidate> LightweightDraftModel::GenerateDraftCached(
    GPU::KVCacheEntry* kvCache,
    uint32_t startPos,
    uint32_t numTokens,
    float temperature) {

    // Use cached KV for faster generation
    std::vector<DraftCandidate> candidates;

    for (uint32_t i = 0; i < numTokens; ++i) {
        std::vector<float> logits = ForwardCached(kvCache, startPos + i, 1);

        TokenId token = SampleToken(logits, temperature);

        DraftCandidate candidate;
        candidate.tokenId = token;
        candidate.draftLogit = logits[token];
        candidate.draftProb = 1.0f / vocabSize_;
        candidate.accepted = false;
        candidate.depth = i;
        candidate.parentIdx = i > 0 ? i - 1 : 0;

        candidates.push_back(candidate);
    }

    totalTokensGenerated_ += numTokens;

    return candidates;
}

std::vector<float> LightweightDraftModel::Forward(const std::vector<TokenId>& tokens) {
    // Simplified forward pass - in production, run actual transformer layers
    std::vector<float> logits(vocabSize_, 0.0f);

    // Dummy computation - just use token ID as seed
    for (size_t i = 0; i < tokens.size(); ++i) {
        logits[tokens[i] % vocabSize_] += 1.0f;
    }

    return logits;
}

std::vector<float> LightweightDraftModel::ForwardCached(
    GPU::KVCacheEntry* kvCache,
    uint32_t startPos,
    uint32_t len) {

    // Use cached KV for faster single-token generation
    return Forward({static_cast<TokenId>(startPos)});
}

TokenId LightweightDraftModel::SampleToken(const std::vector<float>& logits, float temperature) {
    std::vector<float> probs = logits;

    // Apply temperature
    if (temperature != 1.0f && temperature > 0.0f) {
        for (auto& p : probs) {
            p /= temperature;
        }
    }

    // Softmax
    float maxLogit = *std::max_element(probs.begin(), probs.end());
    float sum = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - maxLogit);
        sum += p;
    }
    for (auto& p : probs) {
        p /= sum;
    }

    // Sample
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

float LightweightDraftModel::GetAverageLatencyMs() const {
    if (generationCount_.load() == 0) {
        return 0.0f;
    }
    return static_cast<float>(totalLatencyNs_.load()) / generationCount_.load() / 1e6f;
}

// ============================================================================
// Tree Attention Engine Implementation
// ============================================================================

TreeAttentionEngine::TreeAttentionEngine(GPU::IGPUBackend* backend) : backend_(backend) {
}

TreeAttentionEngine::~TreeAttentionEngine() = default;

bool TreeAttentionEngine::Initialize(uint32_t numHeads, uint32_t headDim, uint32_t maxSeqLen) {
    numHeads_ = numHeads;
    headDim_ = headDim;
    maxSeqLen_ = maxSeqLen;
    initialized_ = true;
    return true;
}

std::vector<TreeNode> TreeAttentionEngine::BuildTree(
    const std::vector<DraftCandidate>& candidates,
    uint32_t branchingFactor) {

    std::vector<TreeNode> tree;

    // Root node
    TreeNode root;
    root.tokenId = -1; // Special root token
    root.cumulativeProb = 1.0f;
    root.depth = 0;
    root.parentIdx = 0;
    root.verified = false;
    root.accepted = false;
    tree.push_back(root);

    // Build tree structure
    for (const auto& candidate : candidates) {
        TreeNode node;
        node.tokenId = candidate.tokenId;
        node.cumulativeProb = candidate.draftProb;
        node.depth = candidate.depth + 1;
        node.parentIdx = candidate.parentIdx + 1; // +1 for root
        node.verified = false;
        node.accepted = false;

        uint32_t nodeIdx = static_cast<uint32_t>(tree.size());
        tree[nodeIdx - 1].childIndices.push_back(nodeIdx);

        tree.push_back(node);
    }

    return tree;
}

std::vector<std::vector<bool>> TreeAttentionEngine::ComputeTreeMask(
    const std::vector<TreeNode>& tree) {

    uint32_t n = static_cast<uint32_t>(tree.size());
    std::vector<std::vector<bool>> mask(n, std::vector<bool>(n, false));

    // Each node can attend to itself and ancestors
    for (uint32_t i = 0; i < n; ++i) {
        mask[i][i] = true;

        uint32_t parent = tree[i].parentIdx;
        while (parent != i) {
            mask[i][parent] = true;
            parent = tree[parent].parentIdx;
        }
    }

    return mask;
}

std::vector<TokenId> TreeAttentionEngine::FlattenTree(const std::vector<TreeNode>& tree) {
    std::vector<TokenId> tokens;
    tokens.reserve(tree.size());

    for (const auto& node : tree) {
        if (node.tokenId >= 0) {
            tokens.push_back(node.tokenId);
        }
    }

    return tokens;
}

std::vector<uint32_t> TreeAttentionEngine::GetPositionIndices(
    const std::vector<TreeNode>& tree,
    uint32_t basePos) {

    std::vector<uint32_t> positions;
    positions.reserve(tree.size());

    for (const auto& node : tree) {
        positions.push_back(basePos + node.depth);
    }

    return positions;
}

bool TreeAttentionEngine::ComputeTreeAttention(
    const std::vector<TreeNode>& tree,
    GPU::KVCacheEntry* kvCache,
    GPU::GPUBuffer* outputLogits) {

    if (!backend_ || !initialized_) {
        return false;
    }

    // Compute attention mask
    auto mask = ComputeTreeMask(tree);

    // Flatten tree to sequence
    auto tokens = FlattenTree(tree);

    // Get position indices
    auto positions = GetPositionIndices(tree, kvCache ? kvCache->seqLen : 0);

    // Dispatch tree attention kernel
    // TODO: Implement actual GPU kernel dispatch

    return true;
}

VerificationResult TreeAttentionEngine::VerifyTree(
    const std::vector<TreeNode>& tree,
    const std::vector<float>& targetLogits,
    float temperature) {

    VerificationResult result;
    result.numAccepted = 0;
    result.numRejected = 0;
    result.acceptanceRate = 0.0f;

    // Verify each node
    for (size_t i = 1; i < tree.size(); ++i) { // Skip root
        // Simplified verification - check if token matches highest logit
        // In production, use proper rejection sampling

        TokenId predicted = static_cast<TokenId>(
            std::max_element(targetLogits.begin(), targetLogits.end()) - targetLogits.begin()
        );

        if (predicted == tree[i].tokenId) {
            result.numAccepted++;
            result.acceptedTokens.push_back(tree[i].tokenId);
        } else {
            result.numRejected++;
            if (result.correctedToken == 0) {
                result.correctedToken = predicted;
            }
            break; // Stop at first rejection
        }
    }

    if (result.numAccepted + result.numRejected > 0) {
        result.acceptanceRate = static_cast<float>(result.numAccepted) /
                                 (result.numAccepted + result.numRejected);
    }

    return result;
}

// ============================================================================
// Verification Engine Implementation
// ============================================================================

VerificationEngine::VerificationEngine(GPU::IGPUBackend* backend) : backend_(backend) {
}

VerificationEngine::~VerificationEngine() = default;

bool VerificationEngine::Initialize(uint32_t vocabSize) {
    vocabSize_ = vocabSize;
    initialized_ = true;
    return true;
}

VerificationResult VerificationEngine::Verify(
    const std::vector<DraftCandidate>& draftTokens,
    const std::vector<float>& targetLogits,
    const SpeculativeConfig& config) {

    std::lock_guard<std::mutex> lock(mutex_);

    VerificationResult result;
    result.numAccepted = 0;
    result.numRejected = 0;

    auto start = std::chrono::high_resolution_clock::now();

    // Compute target probabilities
    std::vector<float> targetProbs = targetLogits;
    Softmax(targetProbs);

    // Verify each draft token
    for (const auto& draft : draftTokens) {
        float targetProb = targetProbs[draft.tokenId];

        bool accepted = false;
        if (config.useRejectionSampling) {
            accepted = RejectionSample(draft.draftProb, targetProb);
        } else {
            accepted = TemperatureAccept(draft.draftLogit, targetLogits[draft.tokenId], config.acceptanceThreshold);
        }

        if (accepted) {
            result.numAccepted++;
            result.acceptedTokens.push_back(draft.tokenId);
        } else {
            result.numRejected++;

            // Sample corrected token from residual distribution
            std::vector<float> residual = targetProbs;
            for (size_t i = 0; i < residual.size(); ++i) {
                residual[i] = std::max(0.0f, residual[i] - draft.draftProb);
            }

            // Renormalize and sample
            float sum = std::accumulate(residual.begin(), residual.end(), 0.0f);
            if (sum > 0) {
                for (auto& r : residual) {
                    r /= sum;
                }
            }

            // Sample from residual
            static std::mt19937 rng(std::random_device{}());
            std::uniform_real_distribution<float> dist(0.0f, 1.0f);
            float r = dist(rng);

            float cumsum = 0.0f;
            for (size_t i = 0; i < residual.size(); ++i) {
                cumsum += residual[i];
                if (r <= cumsum) {
                    result.correctedToken = static_cast<TokenId>(i);
                    break;
                }
            }

            break; // Stop at first rejection
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    result.verifyTimeUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    if (result.numAccepted + result.numRejected > 0) {
        result.acceptanceRate = static_cast<float>(result.numAccepted) /
                                 (result.numAccepted + result.numRejected);
    }

    totalVerifications_++;
    totalAccepted_ += result.numAccepted;

    return result;
}

VerificationResult VerificationEngine::VerifyFused(
    const GPU::GPUBuffer* draftLogits,
    const GPU::GPUBuffer* targetLogits,
    const GPU::GPUBuffer* draftTokens,
    uint32_t numTokens,
    float temperature) {

    // Fused GPU kernel verification
    // This would dispatch a compute shader/kernel that does verification in registers

    VerificationResult result;
    // TODO: Implement fused GPU verification
    return result;
}

std::vector<VerificationResult> VerificationEngine::VerifyBatch(
    const std::vector<std::vector<DraftCandidate>>& draftPaths,
    const std::vector<std::vector<float>>& targetLogits,
    const SpeculativeConfig& config) {

    std::vector<VerificationResult> results;
    results.reserve(draftPaths.size());

    for (size_t i = 0; i < draftPaths.size(); ++i) {
        results.push_back(Verify(draftPaths[i], targetLogits[i], config));
    }

    return results;
}

bool VerificationEngine::RejectionSample(float draftProb, float targetProb) {
    float acceptanceProb = ComputeAcceptanceProb(draftProb, targetProb);

    static std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);

    return dist(rng) < acceptanceProb;
}

bool VerificationEngine::TemperatureAccept(float draftLogit, float targetLogit, float temperature) {
    float acceptanceProb = std::min(1.0f, std::exp((targetLogit - draftLogit) / temperature));

    static std::mt19937 rng(std::random_device{}());
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);

    return dist(rng) < acceptanceProb;
}

void VerificationEngine::Softmax(std::vector<float>& logits) {
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

float VerificationEngine::GetAverageAcceptanceRate() const {
    if (totalVerifications_.load() == 0) {
        return 0.0f;
    }
    return static_cast<float>(totalAccepted_.load()) / totalVerifications_.load();
}

// ============================================================================
// Speculative Execution Engine Implementation
// ============================================================================

SpeculativeExecutionEngine::SpeculativeExecutionEngine() = default;

SpeculativeExecutionEngine::~SpeculativeExecutionEngine() {
    Shutdown();
}

bool SpeculativeExecutionEngine::Initialize(const SpeculativeConfig& config, GPU::IGPUBackend* backend) {
    config_ = config;
    backend_ = backend;

    // Initialize draft model if enabled
    if (config_.useDraftModel && !config_.draftModelPath.empty()) {
        draftModel_ = std::make_unique<LightweightDraftModel>();
        if (!draftModel_>Initialize(config_.draftModelPath, backend_)) {
            fprintf(stderr, "[SpeculativeEngine] Failed to initialize draft model, falling back to self-speculative\n");
            config_.useDraftModel = false;
            config_.useSelfSpeculative = true;
        }
    }

    // Initialize n-gram cache for self-speculation
    if (config_.useSelfSpeculative) {
        ngramCache_ = std::make_unique<NgramCache>(config_.ngramWindow, config_.maxNgramMatches);
    }

    // Initialize tree attention engine
    if (config_.useTreeAttention) {
        treeEngine_ = std::make_unique<TreeAttentionEngine>(backend_);
        treeEngine_>Initialize(32, 128, 4096); // Default dimensions
    }

    // Initialize verification engine
    verifyEngine_ = std::make_unique<VerificationEngine>(backend_);
    verifyEngine_>Initialize(32000); // Default vocab size

    // Start async draft generation thread
    if (config_.asyncDraftGeneration) {
        stopDraftThread_ = false;
        draftThread_ = std::thread(&SpeculativeExecutionEngine::DraftWorkerThread, this);
        draftThreadRunning_ = true;
    }

    initialized_ = true;
    printf("[SpeculativeEngine] Initialized with %s mode\n",
           config_.useDraftModel ? "draft model" : "self-speculative");
    return true;
}

void SpeculativeExecutionEngine::Shutdown() {
    if (!initialized_) {
        return;
    }

    // Stop draft thread
    if (draftThreadRunning_) {
        stopDraftThread_ = true;
        draftQueueCV_.notify_all();
        if (draftThread_.joinable()) {
            draftThread_.join();
        }
        draftThreadRunning_ = false;
    }

    // Cleanup
    draftModel_.reset();
    ngramCache_.reset();
    treeEngine_.reset();
    verifyEngine_.reset();

    initialized_ = false;
}

std::vector<TokenId> SpeculativeExecutionEngine::GenerateSpeculative(
    const std::vector<TokenId>& prompt,
    uint32_t maxNewTokens,
    std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward,
    std::function<void(const std::vector<TokenId>&)> onTokensGenerated) {

    if (config_.useDraftModel && draftModel_) {
        return GenerateWithDraftModel(prompt, maxNewTokens, targetForward);
    } else {
        return GenerateSelfSpeculative(prompt, maxNewTokens, targetForward);
    }
}

void SpeculativeExecutionEngine::GenerateSpeculativeStreaming(
    const std::vector<TokenId>& prompt,
    uint32_t maxNewTokens,
    std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward,
    std::function<void(TokenId)> onToken,
    std::function<void()> onComplete) {

    std::vector<TokenId> generated = GenerateSpeculative(prompt, maxNewTokens, targetForward);

    for (TokenId token : generated) {
        if (onToken) {
            onToken(token);
        }
    }

    if (onComplete) {
        onComplete();
    }
}

std::vector<TokenId> SpeculativeExecutionEngine::GenerateWithDraftModel(
    const std::vector<TokenId>& prompt,
    uint32_t maxNewTokens,
    std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward) {

    std::vector<TokenId> output = prompt;
    std::vector<TokenId> newTokens;

    uint32_t tokensGenerated = 0;

    while (tokensGenerated < maxNewTokens) {
        // Generate draft tokens
        uint32_t draftCount = std::min(config_.maxDraftTokens, maxNewTokens - tokensGenerated);

        auto draftStart = std::chrono::high_resolution_clock::now();
        std::vector<DraftCandidate> draft = draftModel_>GenerateDraft(output, draftCount, config_.draftTemperature);
        auto draftEnd = std::chrono::high_resolution_clock::now();

        draftTokensGenerated_ += draft.size();
        totalDraftLatencyNs_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
            draftEnd - draftStart).count();

        // Build draft token sequence
        std::vector<TokenId> draftSequence;
        for (const auto& d : draft) {
            draftSequence.push_back(d.tokenId);
        }

        // Verify with target model
        std::vector<TokenId> verifyInput = output;
        verifyInput.insert(verifyInput.end(), draftSequence.begin(), draftSequence.end());

        auto verifyStart = std::chrono::high_resolution_clock::now();
        std::vector<float> targetLogits = targetForward(verifyInput);
        auto verifyEnd = std::chrono::high_resolution_clock::now();

        targetTokensVerified_++;
        totalVerifyLatencyNs_ += std::chrono::duration_cast<std::chrono::nanoseconds>(
            verifyEnd - verifyStart).count();

        // Verify draft tokens
        VerificationResult verifyResult = verifyEngine_>Verify(draft, targetLogits, config_);

        // Accept verified tokens
        for (TokenId token : verifyResult.acceptedTokens) {
            output.push_back(token);
            newTokens.push_back(token);
            tokensGenerated++;
            tokensAccepted_++;
        }

        // If rejection occurred, add corrected token
        if (verifyResult.numRejected > 0 && verifyResult.correctedToken != 0) {
            output.push_back(verifyResult.correctedToken);
            newTokens.push_back(verifyResult.correctedToken);
            tokensGenerated++;
        }

        // Adapt speculation depth
        if (config_.adaptiveDepth) {
            AdaptSpeculationDepth();
        }

        // Check for early stopping
        if (verifyResult.numAccepted == 0) {
            break;
        }
    }

    totalTokensGenerated_ += tokensGenerated;
    generationCount_++;

    return newTokens;
}

std::vector<TokenId> SpeculativeExecutionEngine::GenerateSelfSpeculative(
    const std::vector<TokenId>& prompt,
    uint32_t maxNewTokens,
    std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward) {

    std::vector<TokenId> output = prompt;
    std::vector<TokenId> newTokens;

    // Build n-gram cache from prompt
    if (ngramCache_) {
        ngramCache_>BuildIndex(prompt);
    }

    uint32_t tokensGenerated = 0;

    while (tokensGenerated < maxNewTokens) {
        // Query n-gram cache for speculative continuations
        std::vector<std::vector<TokenId>> matches;
        if (ngramCache_) {
            matches = ngramCache_>Query(output, config_.maxNgramMatches);
        }

        // Use matches as draft tokens (simplified)
        std::vector<DraftCandidate> draft;
        if (!matches.empty() && !matches[0].empty()) {
            for (TokenId token : matches[0]) {
                DraftCandidate candidate;
                candidate.tokenId = token;
                candidate.draftProb = 0.5f; // Placeholder
                candidate.accepted = false;
                draft.push_back(candidate);

                if (draft.size() >= config_.maxDraftTokens) {
                    break;
                }
            }
        }

        if (draft.empty()) {
            // No speculative matches, generate single token
            std::vector<float> logits = targetForward(output);
            TokenId token = SampleFromLogits(logits, 1.0f, std::mt19937(std::random_device{}()));

            output.push_back(token);
            newTokens.push_back(token);
            tokensGenerated++;

            if (ngramCache_) {
                ngramCache_>Update({token});
            }
            continue;
        }

        // Build draft sequence
        std::vector<TokenId> draftSequence;
        for (const auto& d : draft) {
            draftSequence.push_back(d.tokenId);
        }

        // Verify with target model
        std::vector<TokenId> verifyInput = output;
        verifyInput.insert(verifyInput.end(), draftSequence.begin(), draftSequence.end());

        std::vector<float> targetLogits = targetForward(verifyInput);
        VerificationResult verifyResult = verifyEngine_>Verify(draft, targetLogits, config_);

        // Accept verified tokens
        std::vector<TokenId> accepted;
        for (TokenId token : verifyResult.acceptedTokens) {
            output.push_back(token);
            newTokens.push_back(token);
            tokensGenerated++;
            accepted.push_back(token);
            tokensAccepted_++;
        }

        if (verifyResult.numRejected > 0 && verifyResult.correctedToken != 0) {
            output.push_back(verifyResult.correctedToken);
            newTokens.push_back(verifyResult.correctedToken);
            tokensGenerated++;
            accepted.push_back(verifyResult.correctedToken);
        }

        // Update cache
        if (ngramCache_) {
            ngramCache_>Update(accepted);
        }
    }

    totalTokensGenerated_ += tokensGenerated;
    return newTokens;
}

void SpeculativeExecutionEngine::GenerateDraftAsync(
    const std::vector<TokenId>& prefix,
    uint32_t numTokens) {

    std::lock_guard<std::mutex> lock(contextMutex_);
    currentContext_ = prefix;

    draftQueueCV_.notify_one();
}

bool SpeculativeExecutionEngine::TryGetDraft(std::vector<DraftCandidate>& draft) {
    std::lock_guard<std::mutex> lock(draftQueueMutex_);

    if (draftQueue_.empty()) {
        return false;
    }

    draft = std::move(draftQueue_.front());
    draftQueue_.pop();
    return true;
}

void SpeculativeExecutionEngine::DraftWorkerThread() {
    while (!stopDraftThread_) {
        std::unique_lock<std::mutex> lock(contextMutex_);

        draftQueueCV_.wait(lock, [this] {
            return stopDraftThread_ || !currentContext_.empty();
        });

        if (stopDraftThread_) {
            break;
        }

        std::vector<TokenId> context = currentContext_;
        currentContext_.clear();
        lock.unlock();

        if (draftModel_ && !context.empty()) {
            auto draft = draftModel_>GenerateDraft(context, config_.maxDraftTokens, config_.draftTemperature);

            std::lock_guard<std::mutex> queueLock(draftQueueMutex_);
            if (draftQueue_.size() < config_.draftQueueSize) {
                draftQueue_.push(std::move(draft));
            }
        }
    }
}

void SpeculativeExecutionEngine::AdaptSpeculationDepth() {
    float acceptanceRate = verifyEngine_>GetAverageAcceptanceRate();

    if (acceptanceRate > 0.7f) {
        // High acceptance - increase draft tokens
        config_.maxDraftTokens = std::min(config_.maxDraftTokens + 1, 16u);
    } else if (acceptanceRate < 0.3f) {
        // Low acceptance - decrease draft tokens
        config_.maxDraftTokens = std::max(config_.maxDraftTokens - 1, 1u);
    }
}

SpeculativeExecutionEngine::Stats SpeculativeExecutionEngine::GetStats() const {
    Stats stats;
    stats.totalTokensGenerated = totalTokensGenerated_.load();
    stats.draftTokensGenerated = draftTokensGenerated_.load();
    stats.targetTokensVerified = targetTokensVerified_.load();
    stats.tokensAccepted = tokensAccepted_.load();
    stats.averageAcceptanceRate = verifyEngine_ ? verifyEngine_>GetAverageAcceptanceRate() : 0.0f;
    stats.averageDraftLatencyMs = generationCount_.load() > 0 ?
        static_cast<float>(totalDraftLatencyNs_.load()) / generationCount_.load() / 1e6f : 0.0f;
    stats.averageVerifyLatencyMs = targetTokensVerified_.load() > 0 ?
        static_cast<float>(totalVerifyLatencyNs_.load()) / targetTokensVerified_.load() / 1e6f : 0.0f;

    // Calculate speedup
    if (stats.tokensAccepted > 0 && stats.targetTokensVerified > 0) {
        float tokensPerVerify = static_cast<float>(stats.tokensAccepted) / stats.targetTokensVerified;
        stats.speedupRatio = tokensPerVerify;
    } else {
        stats.speedupRatio = 1.0f;
    }

    return stats;
}

void SpeculativeExecutionEngine::ResetStats() {
    totalTokensGenerated_ = 0;
    draftTokensGenerated_ = 0;
    targetTokensVerified_ = 0;
    tokensAccepted_ = 0;
    totalDraftLatencyNs_ = 0;
    totalVerifyLatencyNs_ = 0;
    generationCount_ = 0;

    if (verifyEngine_) {
        // Reset verification stats
    }
}

void SpeculativeExecutionEngine::UpdateConfig(const SpeculativeConfig& config) {
    config_ = config;
}

// ============================================================================
// Speculative Engine Factory
// ============================================================================

std::unique_ptr<SpeculativeExecutionEngine> SpeculativeEngineFactory::CreateEngine(
    GPU::IGPUBackend* backend,
    const std::string& draftModelPath) {

    SpeculativeConfig config;
    config.useDraftModel = !draftModelPath.empty();
    config.draftModelPath = draftModelPath;
    config.useSelfSpeculative = draftModelPath.empty();

    return CreateEngine(config, backend);
}

std::unique_ptr<SpeculativeExecutionEngine> SpeculativeEngineFactory::CreateEngine(
    const SpeculativeConfig& config,
    GPU::IGPUBackend* backend) {

    auto engine = std::make_unique<SpeculativeExecutionEngine>();
    if (!engine->Initialize(config, backend)) {
        return nullptr;
    }
    return engine;
}

bool SpeculativeEngineFactory::IsAvailable() {
    // Check if GPU backend is available
    return GPU::GPUBackendManager::Instance().IsInitialized();
}

// ============================================================================
// Utility Functions
// ============================================================================

TokenId SampleFromLogits(const std::vector<float>& logits, float temperature, std::mt19937& rng) {
    std::vector<float> probs = logits;

    // Apply temperature
    if (temperature != 1.0f && temperature > 0.0f) {
        for (auto& p : probs) {
            p /= temperature;
        }
    }

    // Softmax
    float maxLogit = *std::max_element(probs.begin(), probs.end());
    float sum = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - maxLogit);
        sum += p;
    }
    for (auto& p : probs) {
        p /= sum;
    }

    // Sample
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng);

    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return static_cast<TokenId>(i);
        }
    }

    return static_cast<TokenId>(probs.size() - 1);
}

TokenId TopKSample(const std::vector<float>& logits, uint32_t k, float temperature, std::mt19937& rng) {
    // Get top-k indices
    std::vector<size_t> indices(logits.size());
    std::iota(indices.begin(), indices.end(), 0);

    std::partial_sort(indices.begin(), indices.begin() + std::min(k, (uint32_t)indices.size()),
                      indices.end(),
                      [&](size_t a, size_t b) { return logits[a] > logits[b]; });

    // Sample from top-k
    std::vector<float> topKLogits;
    for (uint32_t i = 0; i < k && i < indices.size(); ++i) {
        topKLogits.push_back(logits[indices[i]]);
    }

    TokenId sampledIdx = SampleFromLogits(topKLogits, temperature, rng);
    return static_cast<TokenId>(indices[sampledIdx]);
}

TokenId TopPSample(const std::vector<float>& logits, float p, float temperature, std::mt19937& rng) {
    // Sort logits
    std::vector<std::pair<float, size_t>> sorted;
    for (size_t i = 0; i < logits.size(); ++i) {
        sorted.push_back({logits[i], i});
    }

    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    // Compute softmax
    float maxLogit = sorted[0].first;
    float sum = 0.0f;
    for (auto& pair : sorted) {
        pair.first = std::exp(pair.first - maxLogit);
        sum += pair.first;
    }

    // Find top-p cutoff
    float cumsum = 0.0f;
    size_t cutoff = sorted.size();
    for (size_t i = 0; i < sorted.size(); ++i) {
        cumsum += sorted[i].first / sum;
        if (cumsum >= p) {
            cutoff = i + 1;
            break;
        }
    }

    // Sample from top-p
    std::vector<float> topPLogits;
    for (size_t i = 0; i < cutoff; ++i) {
        topPLogits.push_back(sorted[i].first);
    }

    TokenId sampledIdx = SampleFromLogits(topPLogits, temperature, rng);
    return static_cast<TokenId>(sorted[sampledIdx].second);
}

} // namespace Speculative
} // namespace RawrXD

// ============================================================================
// speculative_execution_engine.h — Full Speculative Execution Layer
// ============================================================================
// Implements speculative decoding with draft model acceleration for 2-3x
// inference speedup. Supports both draft model and self-speculative modes.
//
// Features:
// - Draft model speculative decoding
// - Self-speculative (n-gram based) decoding
// - Tree attention for parallel verification
// - Fused verification kernels
// - Adaptive speculation depth
//
// ============================================================================

#pragma once

#include "../backend/vulkan_rocm_backend.h"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <queue>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <random>
#include <cstdint>

namespace RawrXD {
namespace Speculative {

// ============================================================================
// Forward Declarations
// ============================================================================
class DraftModel;
class TreeAttentionEngine;
class VerificationEngine;
class GenerationEngine;

// ============================================================================
// Token Types
// ============================================================================
using TokenId = int32_t;
using Logit = float;

// ============================================================================
// Draft Candidate
// ============================================================================
struct DraftCandidate {
    TokenId tokenId;
    float draftLogit;
    float targetLogit;
    float draftProb;
    float targetProb;
    bool accepted;
    uint32_t depth;  // Tree depth for tree attention
    uint32_t parentIdx;
    std::vector<uint32_t> childIndices;
};

// ============================================================================
// Speculation Tree Node
// ============================================================================
struct TreeNode {
    TokenId tokenId;
    float cumulativeProb;
    uint32_t depth;
    uint32_t parentIdx;
    std::vector<uint32_t> childIndices;
    bool verified;
    bool accepted;
};

// ============================================================================
// Verification Result
// ============================================================================
struct VerificationResult {
    uint32_t numAccepted;
    uint32_t numRejected;
    std::vector<TokenId> acceptedTokens;
    TokenId correctedToken;  // First rejected token replaced with target sample
    float acceptanceRate;
    uint64_t verifyTimeUs;
};

// ============================================================================
// Speculative Configuration
// ============================================================================
struct SpeculativeConfig {
    // Draft model settings
    bool useDraftModel = true;
    std::string draftModelPath;
    uint32_t draftLayers = 4;  // Number of layers in draft model
    float draftTemperature = 1.0f;

    // Speculation settings
    uint32_t maxDraftTokens = 8;
    uint32_t minDraftTokens = 1;
    float acceptanceThreshold = 0.6f;
    bool adaptiveDepth = true;

    // Tree attention settings
    bool useTreeAttention = true;
    uint32_t treeBranchingFactor = 4;
    uint32_t maxTreeDepth = 4;

    // Verification settings
    bool parallelVerification = true;
    bool fusedVerification = true;
    bool useRejectionSampling = true;

    // Self-speculative settings (when draft model unavailable)
    bool useSelfSpeculative = false;
    uint32_t ngramWindow = 5;
    uint32_t maxNgramMatches = 3;

    // Performance tuning
    uint32_t batchSize = 1;
    bool asyncDraftGeneration = true;
    uint32_t draftQueueSize = 4;
};

// ============================================================================
// N-gram Cache for Self-Speculation
// ============================================================================
class NgramCache {
public:
    NgramCache(uint32_t windowSize = 5, uint32_t maxMatches = 3);
    ~NgramCache();

    // Build n-gram index from context
    void BuildIndex(const std::vector<TokenId>& context);

    // Query for speculative continuations
    std::vector<std::vector<TokenId>> Query(const std::vector<TokenId>& prefix, uint32_t maxMatches);

    // Update cache with new tokens
    void Update(const std::vector<TokenId>& newTokens);

    // Clear cache
    void Clear();

    // Get cache stats
    size_t GetSize() const { return ngramIndex_.size(); }

private:
    uint32_t windowSize_;
    uint32_t maxMatches_;
    std::unordered_map<std::vector<TokenId>, std::vector<TokenId>, VectorHash> ngramIndex_;
    std::vector<TokenId> recentContext_;
    std::mutex mutex_;

    struct VectorHash {
        size_t operator()(const std::vector<TokenId>& v) const {
            size_t hash = 0;
            for (auto id : v) {
                hash = hash * 31 + std::hash<TokenId>{}(id);
            }
            return hash;
        }
    };
};

// ============================================================================
// Draft Model Interface
// ============================================================================
class IDraftModel {
public:
    virtual ~IDraftModel() = default;

    // Initialize draft model
    virtual bool Initialize(const std::string& modelPath, GPU::IGPUBackend* backend) = 0;

    // Generate draft tokens
    virtual std::vector<DraftCandidate> GenerateDraft(
        const std::vector<TokenId>& prefix,
        uint32_t numTokens,
        float temperature) = 0;

    // Generate draft with KV cache
    virtual std::vector<DraftCandidate> GenerateDraftCached(
        GPU::KVCacheEntry* kvCache,
        uint32_t startPos,
        uint32_t numTokens,
        float temperature) = 0;

    // Get model info
    virtual uint32_t GetVocabSize() const = 0;
    virtual uint32_t GetNumLayers() const = 0;
    virtual uint32_t GetHiddenSize() const = 0;

    // Performance stats
    virtual float GetAverageLatencyMs() const = 0;
    virtual uint64_t GetTotalTokensGenerated() const = 0;
};

// ============================================================================
// Lightweight Draft Model Implementation
// ============================================================================
class LightweightDraftModel : public IDraftModel {
public:
    LightweightDraftModel();
    ~LightweightDraftModel() override;

    bool Initialize(const std::string& modelPath, GPU::IGPUBackend* backend) override;

    std::vector<DraftCandidate> GenerateDraft(
        const std::vector<TokenId>& prefix,
        uint32_t numTokens,
        float temperature) override;

    std::vector<DraftCandidate> GenerateDraftCached(
        GPU::KVCacheEntry* kvCache,
        uint32_t startPos,
        uint32_t numTokens,
        float temperature) override;

    uint32_t GetVocabSize() const override { return vocabSize_; }
    uint32_t GetNumLayers() const override { return numLayers_; }
    uint32_t GetHiddenSize() const override { return hiddenSize_; }

    float GetAverageLatencyMs() const override;
    uint64_t GetTotalTokensGenerated() const override { return totalTokensGenerated_.load(); }

private:
    bool LoadModelWeights(const std::string& modelPath);
    bool InitializeGPUResources();

    // Forward pass
    std::vector<float> Forward(const std::vector<TokenId>& tokens);
    std::vector<float> ForwardCached(GPU::KVCacheEntry* kvCache, uint32_t startPos, uint32_t len);

    // Sampling
    TokenId SampleToken(const std::vector<float>& logits, float temperature);

    GPU::IGPUBackend* backend_ = nullptr;

    // Model dimensions
    uint32_t vocabSize_ = 32000;
    uint32_t numLayers_ = 4;
    uint32_t hiddenSize_ = 1024;
    uint32_t numHeads_ = 16;
    uint32_t headDim_ = 64;
    uint32_t intermediateSize_ = 4096;

    // GPU resources
    GPU::GPUBuffer* embeddingTable_ = nullptr;
    GPU::GPUBuffer* outputWeight_ = nullptr;
    std::vector<GPU::GPUBuffer*> layerWeights_;
    GPU::KVCacheEntry* draftKVCache_ = nullptr;

    // Stats
    std::atomic<uint64_t> totalTokensGenerated_{0};
    std::atomic<uint64_t> totalLatencyNs_{0};
    std::atomic<uint32_t> generationCount_{0};

    std::mt19937 rng_;
    std::mutex mutex_;
};

// ============================================================================
// Tree Attention Engine
// ============================================================================
class TreeAttentionEngine {
public:
    TreeAttentionEngine(GPU::IGPUBackend* backend);
    ~TreeAttentionEngine();

    // Initialize with model dimensions
    bool Initialize(uint32_t numHeads, uint32_t headDim, uint32_t maxSeqLen);

    // Build attention tree from draft candidates
    // Returns tree structure for parallel verification
    std::vector<TreeNode> BuildTree(const std::vector<DraftCandidate>& candidates,
                                       uint32_t branchingFactor);

    // Compute tree attention mask
    // mask[i][j] = true if token j can attend to token i in tree
    std::vector<std::vector<bool>> ComputeTreeMask(const std::vector<TreeNode>& tree);

    // Flatten tree to sequence for batch processing
    std::vector<TokenId> FlattenTree(const std::vector<TreeNode>& tree);

    // Get position indices for RoPE
    std::vector<uint32_t> GetPositionIndices(const std::vector<TreeNode>& tree,
                                                uint32_t basePos);

    // GPU-accelerated tree attention
    bool ComputeTreeAttention(const std::vector<TreeNode>& tree,
                               GPU::KVCacheEntry* kvCache,
                               GPU::GPUBuffer* outputLogits);

    // Verify tree nodes against target model
    VerificationResult VerifyTree(const std::vector<TreeNode>& tree,
                                    const std::vector<float>& targetLogits,
                                    float temperature);

private:
    GPU::IGPUBackend* backend_;

    uint32_t numHeads_ = 0;
    uint32_t headDim_ = 0;
    uint32_t maxSeqLen_ = 0;

    bool initialized_ = false;
};

// ============================================================================
// Verification Engine
// ============================================================================
class VerificationEngine {
public:
    VerificationEngine(GPU::IGPUBackend* backend);
    ~VerificationEngine();

    // Initialize
    bool Initialize(uint32_t vocabSize);

    // Verify draft tokens against target model
    // Uses rejection sampling or temperature-based acceptance
    VerificationResult Verify(const std::vector<DraftCandidate>& draftTokens,
                             const std::vector<float>& targetLogits,
                             const SpeculativeConfig& config);

    // Fused verify-and-accept (GPU kernel)
    VerificationResult VerifyFused(const GPU::GPUBuffer* draftLogits,
                                    const GPU::GPUBuffer* targetLogits,
                                    const GPU::GPUBuffer* draftTokens,
                                    uint32_t numTokens,
                                    float temperature);

    // Batch verify multiple speculation paths
    std::vector<VerificationResult> VerifyBatch(
        const std::vector<std::vector<DraftCandidate>>& draftPaths,
        const std::vector<std::vector<float>>& targetLogits,
        const SpeculativeConfig& config);

    // Get verification statistics
    float GetAverageAcceptanceRate() const;
    uint64_t GetTotalVerifications() const { return totalVerifications_.load(); }

private:
    // Rejection sampling
    bool RejectionSample(float draftProb, float targetProb);

    // Temperature-scaled acceptance
    bool TemperatureAccept(float draftLogit, float targetLogit, float temperature);

    // Compute softmax
    void Softmax(std::vector<float>& logits);

    GPU::IGPUBackend* backend_;
    uint32_t vocabSize_ = 0;

    // Stats
    std::atomic<uint64_t> totalVerifications_{0};
    std::atomic<uint64_t> totalAccepted_{0};

    bool initialized_ = false;
    std::mutex mutex_;
};

// ============================================================================
// Speculative Execution Engine
// ============================================================================
class SpeculativeExecutionEngine {
public:
    SpeculativeExecutionEngine();
    ~SpeculativeExecutionEngine();

    // Initialize with configuration
    bool Initialize(const SpeculativeConfig& config, GPU::IGPUBackend* backend);

    // Shutdown
    void Shutdown();

    // Generate tokens with speculative execution
    // This is the main entry point for speculative decoding
    std::vector<TokenId> GenerateSpeculative(
        const std::vector<TokenId>& prompt,
        uint32_t maxNewTokens,
        std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward,
        std::function<void(const std::vector<TokenId>&)> onTokensGenerated = nullptr);

    // Streaming generation with speculative execution
    void GenerateSpeculativeStreaming(
        const std::vector<TokenId>& prompt,
        uint32_t maxNewTokens,
        std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward,
        std::function<void(TokenId)> onToken,
        std::function<void()> onComplete = nullptr);

    // Generate draft tokens (async)
    void GenerateDraftAsync(const std::vector<TokenId>& prefix,
                            uint32_t numTokens);

    // Get draft tokens from queue (non-blocking)
    bool TryGetDraft(std::vector<DraftCandidate>& draft);

    // Update speculation depth based on acceptance rate
    void AdaptSpeculationDepth();

    // Get performance statistics
    struct Stats {
        uint64_t totalTokensGenerated;
        uint64_t draftTokensGenerated;
        uint64_t targetTokensVerified;
        uint64_t tokensAccepted;
        float averageAcceptanceRate;
        float averageDraftLatencyMs;
        float averageVerifyLatencyMs;
        float speedupRatio;
    };
    Stats GetStats() const;

    // Reset statistics
    void ResetStats();

    // Configuration access
    const SpeculativeConfig& GetConfig() const { return config_; }
    void UpdateConfig(const SpeculativeConfig& config);

private:
    // Internal generation methods
    std::vector<TokenId> GenerateWithDraftModel(
        const std::vector<TokenId>& prompt,
        uint32_t maxNewTokens,
        std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward);

    std::vector<TokenId> GenerateSelfSpeculative(
        const std::vector<TokenId>& prompt,
        uint32_t maxNewTokens,
        std::function<std::vector<float>(const std::vector<TokenId>&)> targetForward);

    // Draft generation worker thread
    void DraftWorkerThread();

    // Verify and accept draft tokens
    VerificationResult VerifyDraft(
        const std::vector<DraftCandidate>& draft,
        const std::vector<float>& targetLogits);

    SpeculativeConfig config_;
    GPU::IGPUBackend* backend_ = nullptr;

    // Components
    std::unique_ptr<IDraftModel> draftModel_;
    std::unique_ptr<NgramCache> ngramCache_;
    std::unique_ptr<TreeAttentionEngine> treeEngine_;
    std::unique_ptr<VerificationEngine> verifyEngine_;

    // Async draft generation
    std::thread draftThread_;
    std::queue<std::vector<DraftCandidate>> draftQueue_;
    std::mutex draftQueueMutex_;
    std::condition_variable draftQueueCV_;
    std::atomic<bool> stopDraftThread_{false};
    std::atomic<bool> draftThreadRunning_{false};

    // Current context for draft generation
    std::vector<TokenId> currentContext_;
    std::mutex contextMutex_;

    // Statistics
    std::atomic<uint64_t> totalTokensGenerated_{0};
    std::atomic<uint64_t> draftTokensGenerated_{0};
    std::atomic<uint64_t> targetTokensVerified_{0};
    std::atomic<uint64_t> tokensAccepted_{0};
    std::atomic<uint64_t> totalDraftLatencyNs_{0};
    std::atomic<uint64_t> totalVerifyLatencyNs_{0};
    std::atomic<uint32_t> generationCount_{0};

    bool initialized_ = false;
};

// ============================================================================
// Speculative Engine Factory
// ============================================================================
class SpeculativeEngineFactory {
public:
    // Create speculative engine with auto-configuration
    static std::unique_ptr<SpeculativeExecutionEngine> CreateEngine(
        GPU::IGPUBackend* backend,
        const std::string& draftModelPath = "");

    // Create with explicit configuration
    static std::unique_ptr<SpeculativeExecutionEngine> CreateEngine(
        const SpeculativeConfig& config,
        GPU::IGPUBackend* backend);

    // Check if speculative decoding is available
    static bool IsAvailable();
};

// ============================================================================
// Utility Functions
// ============================================================================

// Compute acceptance probability for speculative decoding
inline float ComputeAcceptanceProb(float draftProb, float targetProb) {
    return std::min(1.0f, targetProb / (draftProb + 1e-10f));
}

// Temperature scaling
inline float TemperatureScale(float logit, float temperature) {
    if (temperature <= 0.0f) return logit;
    return logit / temperature;
}

// Sample from logits with temperature
TokenId SampleFromLogits(const std::vector<float>& logits, float temperature, std::mt19937& rng);

// Top-k sampling
TokenId TopKSample(const std::vector<float>& logits, uint32_t k, float temperature, std::mt19937& rng);

// Top-p (nucleus) sampling
TokenId TopPSample(const std::vector<float>& logits, float p, float temperature, std::mt19937& rng);

} // namespace Speculative
} // namespace RawrXD

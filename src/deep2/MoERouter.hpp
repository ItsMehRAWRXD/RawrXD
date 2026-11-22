// ============================================================================
// MoERouter.hpp - Mixture of Experts Router
// DeepSeek-V3.1 compatible: 256 experts, top-8 routing
// ============================================================================

#pragma once

#include <cstddef>
#include <string>
#include <vector>
#include <cstdint>
#include <cmath>
#include <random>
#include <algorithm>
#include <numeric>
#include "ReapRouteTracker.hpp"

namespace Deep2 {

// MoE configuration
struct MoEConfig {
    size_t numExperts = 256;         // Total experts
    size_t numActiveExperts = 8;     // Top-k experts per token
    size_t expertDim = 2048;        // Per-expert hidden dimension
    size_t hiddenDim = 7168;        // Model hidden dimension
    float routerAuxLoss = 0.001f;   // Auxiliary loss coefficient
    float routerZLoss = 0.01f;      // Z-loss coefficient
    bool useSharedExpert = true;    // Shared expert across all tokens
    size_t sharedExpertDim = 2048;  // Shared expert dimension
    bool useLoadBalancing = false;  /* inference: no RNG noise (greedy lock) */
    float capacityFactor = 1.25f;  // Expert capacity multiplier

    // --- Metadata-driven routing semantics (see MoERoutingCore.hpp) ---
    // 0 = Softmax (Qwen/Mixtral style), 1 = Sigmoid (DeepSeek-V3 / Kimi / GLM).
    // Mirrors llama.cpp expert_gating_func: 1=softmax, 2=sigmoid.
    int32_t scoringFunc = 0;
    // Group-limited routing: nGroup groups of experts, keep topkGroup groups.
    // nGroup <= 1 or topkGroup <= 0 disables group limiting.
    int32_t nGroup = 1;
    int32_t topkGroup = 0;
    // Renormalize selected weights to sum 1 (conditional top-k normalization).
    bool normTopkProb = true;
    // Multiply final expert weights (DeepSeek-V3: ~2.827).
    float routedScalingFactor = 1.0f;
};

// Expert routing result
struct ExpertRoute {
    int expertId;
    float weight;  // Gating weight
};

// Per-token routing
struct TokenRoute {
    std::vector<ExpertRoute> topExperts;  // Top-k experts
    std::vector<float> routerLogits;     // Raw router logits
    float auxLoss;                        // Auxiliary loss contribution
};

// Expert statistics
struct ExpertStats {
    uint64_t totalTokens = 0;
    uint64_t overflowTokens = 0;
    float loadBalance = 1.0f;
    std::vector<uint64_t> tokenCounts;
    std::vector<float> avgWeights;
};

// MoE Router
class MoERouter {
public:
    MoERouter();
    ~MoERouter();

    // Initialize with configuration
    void Initialize(const MoEConfig& config);
    void SetLayerIndex(size_t layer) { layerIndex_ = layer; }
    void EnableReapObservation(bool enabled) { reapObservation_ = enabled; }

    // Route a single token
    TokenRoute Route(const float* hiddenState);
    TokenRoute Route(const float* hiddenState) const;

    // Route a batch of tokens
    std::vector<TokenRoute> RouteBatch(
        const float* hiddenStates,
        size_t numTokens
    );

    // Expose the actual top-K expert IDs from the most recent Route() call.
    // This is the prediction signal for the prefetch pipeline.
    // Returns empty if no route has been computed yet.
    std::vector<int> GetLastRouteExpertIds() const;

    // Get expert weights (router parameters)
    void SetRouterWeights(const float* weights, size_t rows, size_t cols);

    // Selection-only correction bias (exp_probs_b). Applied to the selection
    // scores only, never to the final expert weights. n must equal numExperts.
    void SetCorrectionBias(const float* bias, size_t n);

    // Load balancing
    void UpdateLoadBalance();
    float GetLoadBalance() const { return stats_.loadBalance; }

    // Capacity-aware routing
    bool HasCapacity(int expertId) const;
    void IncrementExpertLoad(int expertId);
    void ResetExpertLoads();

    // Statistics
    const ExpertStats& GetStats() const { return stats_; }
    void ResetStats();

    // Loss computation
    float ComputeAuxLoss(const std::vector<TokenRoute>& routes) const;
    float ComputeZLoss(const std::vector<TokenRoute>& routes) const;

    // Serialization
    void Save(const std::string& path) const;
    void Load(const std::string& path);

    // GPU integration: read-only access to router weights for GpuWeightView construction
    // Returns pointer to weights data with layout [numExperts, hiddenDim] (row-major)
    const float* GetRouterWeightsPtr() const noexcept { return routerWeights_.data(); }
    size_t GetRouterWeightRows() const noexcept { return config_.numExperts; }
    size_t GetRouterWeightCols() const noexcept { return config_.hiddenDim; }

private:
    MoEConfig config_;
    mutable ExpertStats stats_;
    
    // Router weights: [hiddenDim, numExperts]
    std::vector<float> routerWeights_;

    // Selection-only correction bias (exp_probs_b), [numExperts].
    std::vector<float> eScoreCorrectionBias_;
    
    // Expert load tracking
    mutable std::vector<uint64_t> expertLoads_;
    mutable std::vector<uint64_t> expertCapacities_;
    
    // Random generator for noise
    std::mt19937 rng_;
    size_t layerIndex_ = 0;
    bool reapObservation_ = false;

    // Last route result (stored for prefetch prediction exposure)
    mutable std::vector<int> lastRouteExpertIds_;

    // Softmax over router logits
    std::vector<float> Softmax(const std::vector<float>& logits) const;

    // Top-k selection
    std::vector<ExpertRoute> TopK(
        const std::vector<float>& gatingScores,
        int k
    ) const;

    // Noisy top-k gating
    std::vector<float> NoisyTopKGating(
        const float* hiddenState,
        std::vector<float>& logits
    );

    // Load balancing loss
    float ComputeLoadBalanceLoss(
        const std::vector<std::vector<float>>& expertProbs
    ) const;
};  // <-- Close MoERouter class

// Individual expert FFN
class MoEExpert {
public:
    MoEExpert();
    ~MoEExpert();

    void Initialize(size_t expertDim, size_t hiddenDim, int expertId);

    // Forward pass: expert FFN
    void Forward(
        const float* input,
        float* output,
        size_t numTokens
    );

    // Set weights
    void SetWeights(
        const float* w1,  // gate_proj
        const float* w2,  // down_proj
        const float* w3   // up_proj
    );

    int GetExpertId() const { return expertId_; }

private:
    int expertId_ = -1;
    size_t expertDim_;
    size_t hiddenDim_;
    
    const float* w1_ = nullptr;
    const float* w2_ = nullptr;
    const float* w3_ = nullptr;
};

// Full MoE layer
class MoELayer {
public:
    MoELayer();
    ~MoELayer();

    void Initialize(const MoEConfig& config);

    // Forward pass
    void Forward(
        const float* input,
        float* output,
        size_t numTokens
    );

    // Access components
    MoERouter& GetRouter() { return router_; }
    std::vector<MoEExpert>& GetExperts() { return experts_; }

private:
    MoEConfig config_;
    MoERouter router_;
    std::vector<MoEExpert> experts_;
    
    // Shared expert
    MoEExpert sharedExpert_;
    bool hasSharedExpert_ = false;
    
    // Temporary buffers
    std::vector<float> expertInput_;
    std::vector<float> expertOutput_;
    std::vector<float> sharedOutput_;
};

} // namespace Deep2

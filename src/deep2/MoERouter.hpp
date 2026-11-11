// ============================================================================
// MoERouter.hpp - Mixture of Experts Router
// DeepSeek-V3.1 compatible: 256 experts, top-8 routing
// ============================================================================

#pragma once

#include <vector>
#include <cstdint>
#include <cmath>
#include <random>
#include <algorithm>
#include <numeric>

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
    bool useLoadBalancing = true;   // Enable load balancing
    float capacityFactor = 1.25f;  // Expert capacity multiplier
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

    // Route a single token
    TokenRoute Route(const float* hiddenState);

    // Route a batch of tokens
    std::vector<TokenRoute> RouteBatch(
        const float* hiddenStates,
        size_t numTokens
    );

    // Get expert weights (router parameters)
    void SetRouterWeights(const float* weights, size_t rows, size_t cols);

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

private:
    MoEConfig config_;
    ExpertStats stats_;
    
    // Router weights: [hiddenDim, numExperts]
    std::vector<float> routerWeights_;
    
    // Expert load tracking
    std::vector<uint64_t> expertLoads_;
    std::vector<uint64_t> expertCapacities_;
    
    // Random generator for noise
    std::mt19937 rng_;

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
};

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

// ============================================================================
// MoERouter.cpp - Mixture of Experts Router Implementation
// ============================================================================

#include "MoERouter.hpp"
#include <fstream>
#include <iostream>
#include <cstring>

namespace Deep2 {

// ============================================================
// MoERouter
// ============================================================

MoERouter::MoERouter() : rng_(std::random_device{}()) {}
MoERouter::~MoERouter() = default;

void MoERouter::Initialize(const MoEConfig& config) {
    config_ = config;
    
    // Initialize router weights
    routerWeights_.resize(config_.hiddenDim * config_.numExperts, 0.0f);
    
    // Initialize expert loads
    expertLoads_.resize(config_.numExperts, 0);
    expertCapacities_.resize(config_.numExperts, 0);
    
    // Initialize statistics
    stats_.tokenCounts.resize(config_.numExperts, 0);
    stats_.avgWeights.resize(config_.numExperts, 0.0f);
    
    // Calculate expert capacity
    uint64_t capacity = static_cast<uint64_t>(config_.capacityFactor * config_.numActiveExperts);
    std::fill(expertCapacities_.begin(), expertCapacities_.end(), capacity);
}

void MoERouter::SetRouterWeights(const float* weights, size_t rows, size_t cols) {
    if (rows * cols > routerWeights_.size()) {
        routerWeights_.resize(rows * cols);
    }
    memcpy(routerWeights_.data(), weights, rows * cols * sizeof(float));
}

TokenRoute MoERouter::Route(const float* hiddenState) {
    TokenRoute route;
    std::vector<float> logits(config_.numExperts);
    
    // Compute router logits: score = W * x
    for (size_t e = 0; e < config_.numExperts; ++e) {
        float score = 0;
        for (size_t d = 0; d < config_.hiddenDim; ++d) {
            score += routerWeights_[d * config_.numExperts + e] * hiddenState[d];
        }
        logits[e] = score;
    }
    
    route.routerLogits = logits;
    
    // Apply softmax to get gating scores
    auto gatingScores = Softmax(logits);
    
    // Add noise for load balancing (during training)
    if (config_.useLoadBalancing) {
        std::normal_distribution<float> noise(0.0f, 0.01f);
        for (auto& score : gatingScores) {
            score += noise(rng_);
        }
    }
    
    // Select top-k experts
    route.topExperts = TopK(gatingScores, config_.numActiveExperts);
    
    // Track statistics
    stats_.totalTokens++;
    for (const auto& expert : route.topExperts) {
        stats_.tokenCounts[expert.expertId]++;
        stats_.avgWeights[expert.expertId] += expert.weight;
    }
    
    return route;
}

std::vector<TokenRoute> MoERouter::RouteBatch(
    const float* hiddenStates, size_t numTokens) {
    std::vector<TokenRoute> routes(numTokens);
    
    for (size_t t = 0; t < numTokens; ++t) {
        routes[t] = Route(hiddenStates + t * config_.hiddenDim);
    }
    
    return routes;
}

std::vector<float> MoERouter::Softmax(const std::vector<float>& logits) const {
    std::vector<float> result(logits.size());
    
    float maxLogit = *std::max_element(logits.begin(), logits.end());
    float sum = 0;
    
    for (size_t i = 0; i < logits.size(); ++i) {
        result[i] = std::exp(logits[i] - maxLogit);
        sum += result[i];
    }
    
    float invSum = 1.0f / sum;
    for (auto& v : result) {
        v *= invSum;
    }
    
    return result;
}

std::vector<ExpertRoute> MoERouter::TopK(
    const std::vector<float>& gatingScores, int k) const {
    std::vector<ExpertRoute> result;
    result.reserve(k);
    
    // Get indices sorted by score
    std::vector<int> indices(gatingScores.size());
    std::iota(indices.begin(), indices.end(), 0);
    
    std::partial_sort(indices.begin(), indices.begin() + k, indices.end(),
        [&gatingScores](int a, int b) {
            return gatingScores[a] > gatingScores[b];
        });
    
    // Take top-k
    float topKSum = 0;
    for (int i = 0; i < k; ++i) {
        topKSum += gatingScores[indices[i]];
    }
    
    for (int i = 0; i < k; ++i) {
        ExpertRoute route;
        route.expertId = indices[i];
        route.weight = gatingScores[indices[i]] / (topKSum + 1e-10f);
        result.push_back(route);
    }
    
    return result;
}

void MoERouter::UpdateLoadBalance() {
    if (stats_.totalTokens == 0) return;
    
    // Calculate load balance (lower is better, 1.0 is perfect)
    float sum = 0;
    float sumSq = 0;
    
    for (size_t e = 0; e < config_.numExperts; ++e) {
        float load = static_cast<float>(stats_.tokenCounts[e]) / stats_.totalTokens;
        sum += load;
        sumSq += load * load;
    }
    
    stats_.loadBalance = sum * sum / (sumSq * config_.numExperts + 1e-10f);
}

bool MoERouter::HasCapacity(int expertId) const {
    if (expertId < 0 || expertId >= (int)expertLoads_.size()) return false;
    return expertLoads_[expertId] < expertCapacities_[expertId];
}

void MoERouter::IncrementExpertLoad(int expertId) {
    if (expertId >= 0 && expertId < (int)expertLoads_.size()) {
        expertLoads_[expertId]++;
    }
}

void MoERouter::ResetExpertLoads() {
    std::fill(expertLoads_.begin(), expertLoads_.end(), 0);
}

void MoERouter::ResetStats() {
    stats_ = ExpertStats{};
    stats_.tokenCounts.resize(config_.numExperts, 0);
    stats_.avgWeights.resize(config_.numExperts, 0.0f);
}

float MoERouter::ComputeAuxLoss(const std::vector<TokenRoute>& routes) const {
    if (routes.empty()) return 0;
    
    float loss = 0;
    size_t numTokens = routes.size();
    
    // Compute importance and load for each expert
    std::vector<float> importance(config_.numExperts, 0);
    std::vector<float> load(config_.numExperts, 0);
    
    for (const auto& route : routes) {
        auto probs = Softmax(route.routerLogits);
        
        for (size_t e = 0; e < config_.numExperts; ++e) {
            importance[e] += probs[e];
        }
        
        for (const auto& expert : route.topExperts) {
            load[expert.expertId] += expert.weight;
        }
    }
    
    // Compute coefficient of variation
    float meanImportance = std::accumulate(importance.begin(), importance.end(), 0.0f) / config_.numExperts;
    float varImportance = 0;
    for (float imp : importance) {
        varImportance += (imp - meanImportance) * (imp - meanImportance);
    }
    varImportance /= config_.numExperts;
    
    loss = config_.routerAuxLoss * varImportance;
    return loss;
}

float MoERouter::ComputeZLoss(const std::vector<TokenRoute>& routes) const {
    if (routes.empty()) return 0;
    
    float loss = 0;
    for (const auto& route : routes) {
        float maxLogit = *std::max_element(route.routerLogits.begin(), route.routerLogits.end());
        float logSumExp = maxLogit + std::log(
            std::accumulate(route.routerLogits.begin(), route.routerLogits.end(), 0.0f,
                [maxLogit](float sum, float logit) {
                    return sum + std::exp(logit - maxLogit);
                }));
        loss += logSumExp * logSumExp;
    }
    
    return config_.routerZLoss * loss / routes.size();
}

void MoERouter::Save(const std::string& path) const {
    std::ofstream file(path, std::ios::binary);
    if (!file) return;
    
    file.write(reinterpret_cast<const char*>(&config_), sizeof(config_));
    uint64_t weightSize = routerWeights_.size();
    file.write(reinterpret_cast<const char*>(&weightSize), sizeof(weightSize));
    file.write(reinterpret_cast<const char*>(routerWeights_.data()), weightSize * sizeof(float));
}

void MoERouter::Load(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return;
    
    file.read(reinterpret_cast<char*>(&config_), sizeof(config_));
    uint64_t weightSize;
    file.read(reinterpret_cast<char*>(&weightSize), sizeof(weightSize));
    routerWeights_.resize(weightSize);
    file.read(reinterpret_cast<char*>(routerWeights_.data()), weightSize * sizeof(float));
}

// ============================================================
// MoEExpert
// ============================================================

MoEExpert::MoEExpert() = default;
MoEExpert::~MoEExpert() = default;

void MoEExpert::Initialize(size_t expertDim, size_t hiddenDim, int expertId) {
    expertDim_ = expertDim;
    hiddenDim_ = hiddenDim;
    expertId_ = expertId;
}

void MoEExpert::Forward(const float* input, float* output, size_t numTokens) {
    if (!w1_ || !w2_ || !w3_) return;
    
    for (size_t t = 0; t < numTokens; ++t) {
        const float* tokenIn = input + t * hiddenDim_;
        float* tokenOut = output + t * expertDim_;
        
        // Gate projection: gate = input * w1
        std::vector<float> gate(expertDim_);
        for (size_t i = 0; i < expertDim_; ++i) {
            float sum = 0;
            for (size_t j = 0; j < hiddenDim_; ++j) {
                sum += tokenIn[j] * w1_[j * expertDim_ + i];
            }
            gate[i] = sum;
        }
        
        // Up projection: up = input * w3
        std::vector<float> up(expertDim_);
        for (size_t i = 0; i < expertDim_; ++i) {
            float sum = 0;
            for (size_t j = 0; j < hiddenDim_; ++j) {
                sum += tokenIn[j] * w3_[j * expertDim_ + i];
            }
            up[i] = sum;
        }
        
        // SwiGLU activation: silu(gate) * up
        for (size_t i = 0; i < expertDim_; ++i) {
            float sigmoid = 1.0f / (1.0f + std::exp(-gate[i]));
            up[i] = sigmoid * gate[i] * up[i];
        }
        
        // Down projection: output = up * w2
        for (size_t i = 0; i < hiddenDim_; ++i) {
            float sum = 0;
            for (size_t j = 0; j < expertDim_; ++j) {
                sum += up[j] * w2_[j * hiddenDim_ + i];
            }
            tokenOut[i] = sum;
        }
    }
}

void MoEExpert::SetWeights(const float* w1, const float* w2, const float* w3) {
    w1_ = w1;
    w2_ = w2;
    w3_ = w3;
}

// ============================================================
// MoELayer
// ============================================================

MoELayer::MoELayer() = default;
MoELayer::~MoELayer() = default;

void MoELayer::Initialize(const MoEConfig& config) {
    config_ = config;
    router_.Initialize(config);
    
    // Create experts
    experts_.resize(config_.numExperts);
    for (size_t e = 0; e < config_.numExperts; ++e) {
        experts_[e].Initialize(config_.expertDim, config_.hiddenDim, e);
    }
    
    // Create shared expert
    if (config_.useSharedExpert) {
        hasSharedExpert_ = true;
        sharedExpert_.Initialize(config_.sharedExpertDim, config_.hiddenDim, -1);
    }
    
    // Allocate buffers
    expertInput_.resize(config_.hiddenDim);
    expertOutput_.resize(config_.hiddenDim);
    sharedOutput_.resize(config_.hiddenDim);
}

void MoELayer::Forward(const float* input, float* output, size_t numTokens) {
    // Route tokens
    auto routes = router_.RouteBatch(input, numTokens);
    
    // Process each token
    for (size_t t = 0; t < numTokens; ++t) {
        const float* tokenIn = input + t * config_.hiddenDim;
        float* tokenOut = output + t * config_.hiddenDim;
        
        // Initialize output
        memset(tokenOut, 0, config_.hiddenDim * sizeof(float));
        
        // Process shared expert
        if (hasSharedExpert_) {
            sharedExpert_.Forward(tokenIn, sharedOutput_.data(), 1);
            for (size_t d = 0; d < config_.hiddenDim; ++d) {
                tokenOut[d] += sharedOutput_[d];
            }
        }
        
        // Process routed experts
        for (const auto& route : routes[t].topExperts) {
            if (route.expertId >= 0 && route.expertId < (int)experts_.size()) {
                experts_[route.expertId].Forward(tokenIn, expertOutput_.data(), 1);
                
                // Weighted sum
                for (size_t d = 0; d < config_.hiddenDim; ++d) {
                    tokenOut[d] += route.weight * expertOutput_[d];
                }
            }
        }
    }
}

} // namespace Deep2

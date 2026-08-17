// ============================================================================
// K2MoEWeights.cpp — K2-004/005 MoE Tensor Schema Implementation
// ============================================================================

#include "K2MoEWeights.hpp"
#include <algorithm>
#include <cmath>
#include <numeric>

namespace Deep2 {

// ============================================================================
// MoEWeights
// ============================================================================

ExpertSlice MoEWeights::GetExpertGate(uint32_t expertId, const KimiK2Config& config) const {
    ExpertSlice slice;
    slice.source = ffnGateExps;
    slice.expertCount = config.numExperts;
    slice.expertId = expertId;
    // ffnGateExps shape: [moeIntermediateSize, hiddenDim, numExperts]
    // Each expert: [moeIntermediateSize, hiddenDim]
    const uint64_t expertSize = config.moeIntermediateSize * config.hiddenDim * sizeof(float);
    slice.expertStrideBytes = expertSize;
    slice.byteOffset = expertId * expertSize;
    slice.byteSize = expertSize;
    return slice;
}

ExpertSlice MoEWeights::GetExpertUp(uint32_t expertId, const KimiK2Config& config) const {
    ExpertSlice slice;
    slice.source = ffnUpExps;
    slice.expertCount = config.numExperts;
    slice.expertId = expertId;
    const uint64_t expertSize = config.moeIntermediateSize * config.hiddenDim * sizeof(float);
    slice.expertStrideBytes = expertSize;
    slice.byteOffset = expertId * expertSize;
    slice.byteSize = expertSize;
    return slice;
}

ExpertSlice MoEWeights::GetExpertDown(uint32_t expertId, const KimiK2Config& config) const {
    ExpertSlice slice;
    slice.source = ffnDownExps;
    slice.expertCount = config.numExperts;
    slice.expertId = expertId;
    const uint64_t expertSize = config.hiddenDim * config.moeIntermediateSize * sizeof(float);
    slice.expertStrideBytes = expertSize;
    slice.byteOffset = expertId * expertSize;
    slice.byteSize = expertSize;
    return slice;
}

bool MoEWeights::Validate(const KimiK2Config& config, std::string& error) const {
    // Router tensors
    if (!ffnGateInp.data()) { error = "MoEWeights: ffn_gate_inp missing"; return false; }
    if (!expProbsB.data()) { error = "MoEWeights: exp_probs_b missing"; return false; }

    // Expert tensors (for MoE layers)
    if (config.numExperts > 0) {
        if (!ffnGateExps.data()) { error = "MoEWeights: ffn_gate_exps missing"; return false; }
        if (!ffnUpExps.data()) { error = "MoEWeights: ffn_up_exps missing"; return false; }
        if (!ffnDownExps.data()) { error = "MoEWeights: ffn_down_exps missing"; return false; }
    }

    // Shared expert
    if (!ffnGateShexp.data()) { error = "MoEWeights: ffn_gate_shexp missing"; return false; }
    if (!ffnUpShexp.data()) { error = "MoEWeights: ffn_up_shexp missing"; return false; }
    if (!ffnDownShexp.data()) { error = "MoEWeights: ffn_down_shexp missing"; return false; }

    // Norm
    if (!ffnNorm.data()) { error = "MoEWeights: ffn_norm missing"; return false; }

    return true;
}

bool MoEWeights::DetectMoE(const std::string& tensorName) {
    static const char* kMoEPrefixes[] = {
        "ffn_gate_exps", "ffn_up_exps", "ffn_down_exps",
        "ffn_gate_inp", "exp_probs_b"
    };
    for (const char* prefix : kMoEPrefixes) {
        if (tensorName.find(prefix) != std::string::npos) return true;
    }
    return false;
}

bool MoEWeights::DetectDenseFFN(const std::string& tensorName) {
    return tensorName.find("ffn_gate") != std::string::npos &&
           tensorName.find("exps") == std::string::npos &&
           tensorName.find("shexp") == std::string::npos;
}

bool MoEWeights::DetectSharedExpert(const std::string& tensorName) {
    return tensorName.find("shexp") != std::string::npos;
}

// ============================================================================
// KimiK2Router
// ============================================================================

bool KimiK2Router::Initialize(const KimiK2Config& config, std::string& error) {
    if (config.numExperts == 0) {
        error = "KimiK2Router: numExperts is zero";
        return false;
    }
    if (config.expertsPerToken == 0) {
        error = "KimiK2Router: expertsPerToken is zero";
        return false;
    }
    config_ = config;
    initialized_ = true;
    return true;
}

void KimiK2Router::SetRouterWeights(const RawrXD::TensorView& gateInp,
                                     const RawrXD::TensorView& bias) {
    if (!gateInp.data() || !bias.data()) return;

    const size_t hiddenDim = gateInp.dims()[0];
    const size_t numExperts = gateInp.dims()[1];

    routerWeights_.resize(hiddenDim * numExperts);
    routerBias_.resize(numExperts);

    // Copy from tensor views (assuming float32)
    const float* gateData = static_cast<const float*>(gateInp.data());
    std::copy(gateData, gateData + routerWeights_.size(), routerWeights_.begin());

    const float* biasData = static_cast<const float*>(bias.data());
    std::copy(biasData, biasData + numExperts, routerBias_.begin());
}

bool KimiK2Router::Route(const float* hidden, MoERoutingResult& result, std::string& error) {
    if (!initialized_) {
        error = "KimiK2Router: not initialized";
        return false;
    }
    if (!hidden) {
        error = "KimiK2Router: null hidden pointer";
        return false;
    }
    if (routerWeights_.empty()) {
        error = "KimiK2Router: router weights not set";
        return false;
    }

    const uint32_t hiddenDim = config_.hiddenDim;
    const uint32_t numExperts = config_.numExperts;
    const uint32_t k = config_.expertsPerToken;
    const float routedScalingFactor = config_.routedScalingFactor;

    // Compute scores: sigmoid(hidden @ W + b)
    std::vector<float> scores(numExperts);
    for (uint32_t e = 0; e < numExperts; ++e) {
        float dot = routerBias_[e];
        for (uint32_t h = 0; h < hiddenDim; ++h) {
            dot += hidden[h] * routerWeights_[h * numExperts + e];
        }
        // Sigmoid
        scores[e] = 1.0f / (1.0f + std::exp(-dot));
    }

    // Top-k selection (noaux_tc — no auxiliary loss, just top-k)
    std::vector<uint32_t> indices(numExperts);
    std::iota(indices.begin(), indices.end(), 0);
    std::partial_sort(indices.begin(), indices.begin() + k, indices.end(),
        [&](uint32_t a, uint32_t b) { return scores[a] > scores[b]; });

    // Copy top-k results
    result.count = k;
    float weightSum = 0.0f;
    for (uint32_t i = 0; i < k; ++i) {
        result.expertIds[i] = indices[i];
        result.weights[i] = scores[indices[i]];
        weightSum += result.weights[i];
    }

    // norm_topk_prob: normalize weights to sum to 1.0
    if (weightSum > 0.0f) {
        for (uint32_t i = 0; i < k; ++i) {
            result.weights[i] /= weightSum;
        }
    }

    // Apply routed_scaling_factor
    for (uint32_t i = 0; i < k; ++i) {
        result.weights[i] *= routedScalingFactor;
    }

    totalTokensRouted++;
    totalExpertActivations += k;
    return true;
}

std::vector<MoERoutingResult> KimiK2Router::RouteBatch(
    const float* hiddenBatch,
    uint32_t numTokens,
    std::string& error) {
    std::vector<MoERoutingResult> results;
    results.reserve(numTokens);

    for (uint32_t t = 0; t < numTokens; ++t) {
        MoERoutingResult result;
        if (!Route(hiddenBatch + t * config_.hiddenDim, result, error)) {
            return {}; // Return empty on first failure
        }
        results.push_back(std::move(result));
    }
    return results;
}

} // namespace Deep2

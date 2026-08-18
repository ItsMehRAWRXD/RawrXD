// ============================================================================
// K2MoEWeights.cpp — K2-004/005 MoE Tensor Schema Implementation
// ============================================================================

#include "K2MoEWeights.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "UniversalTensorDescriptor.hpp"
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
    // Detect layer type: dense FFN (layer 0) vs MoE (layers 1+)
    const bool isDenseLayer = !ffnGate.dims().empty() || !ffnUp.dims().empty() || !ffnDown.dims().empty();
    const bool isMoELayer = !ffnGateInp.dims().empty();

    if (!isDenseLayer && !isMoELayer) {
        error = "MoEWeights: layer has neither dense FFN nor MoE tensors";
        return false;
    }

    // Router tensors (required for MoE layers only)
    if (isMoELayer) {
        if (ffnGateInp.dims().empty()) { error = "MoEWeights: ffn_gate_inp missing"; return false; }
        if (expProbsB.dims().empty()) { error = "MoEWeights: exp_probs_b missing"; return false; }

        // Expert tensors
        if (ffnGateExps.dims().empty()) { error = "MoEWeights: ffn_gate_exps missing"; return false; }
        if (ffnUpExps.dims().empty()) { error = "MoEWeights: ffn_up_exps missing"; return false; }
        if (ffnDownExps.dims().empty()) { error = "MoEWeights: ffn_down_exps missing"; return false; }
    }

    // Shared expert (required for MoE layers, optional for dense layer 0)
    if (isMoELayer) {
        if (ffnGateShexp.dims().empty()) { error = "MoEWeights: ffn_gate_shexp missing"; return false; }
        if (ffnUpShexp.dims().empty()) { error = "MoEWeights: ffn_up_shexp missing"; return false; }
        if (ffnDownShexp.dims().empty()) { error = "MoEWeights: ffn_down_shexp missing"; return false; }
    }

    // Norm (always present)
    if (ffnNorm.dims().empty()) { error = "MoEWeights: ffn_norm missing"; return false; }

    return true;
}

bool MoEWeights::ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer, std::string& error) {
    char gateInpName[64], expProbsBName[64];
    char gateExpsName[64], upExpsName[64], downExpsName[64];
    char gateShexpName[64], upShexpName[64], downShexpName[64];
    char gateName[64], upName[64], downName[64];
    char normName[64];

    snprintf(gateInpName, sizeof(gateInpName), "blk.%u.ffn_gate_inp.weight", layer);
    snprintf(expProbsBName, sizeof(expProbsBName), "blk.%u.exp_probs_b.bias", layer);
    snprintf(gateExpsName, sizeof(gateExpsName), "blk.%u.ffn_gate_exps.weight", layer);
    snprintf(upExpsName, sizeof(upExpsName), "blk.%u.ffn_up_exps.weight", layer);
    snprintf(downExpsName, sizeof(downExpsName), "blk.%u.ffn_down_exps.weight", layer);
    snprintf(gateShexpName, sizeof(gateShexpName), "blk.%u.ffn_gate_shexp.weight", layer);
    snprintf(upShexpName, sizeof(upShexpName), "blk.%u.ffn_up_shexp.weight", layer);
    snprintf(downShexpName, sizeof(downShexpName), "blk.%u.ffn_down_shexp.weight", layer);
    snprintf(gateName, sizeof(gateName), "blk.%u.ffn_gate.weight", layer);
    snprintf(upName, sizeof(upName), "blk.%u.ffn_up.weight", layer);
    snprintf(downName, sizeof(downName), "blk.%u.ffn_down.weight", layer);
    snprintf(normName, sizeof(normName), "blk.%u.ffn_norm.weight", layer);

    auto resolve = [&](const char* name, RawrXD::TensorView& view) -> bool {
        auto refOpt = index.Find(name);
        if (!refOpt) return false;
        const auto& ref = *refOpt;

        RawrXD::UniversalTensorDescriptor desc;
        desc.numDims = ref.nDims;
        for (uint8_t i = 0; i < ref.nDims && i < 8; ++i) {
            desc.shape[i] = ref.shape[i];
        }
        desc.layout = RawrXD::TensorLayout::DENSE;
        desc.role = RawrXD::TensorRole::WEIGHT;
        desc.memorySpace = RawrXD::UniversalTensorDescriptor::MemorySpace::NVME;
        desc.data = nullptr;

        switch (ref.ggmlType) {
            case 0:  desc.quantType = RawrXD::QuantType::F32; break;
            case 1:  desc.quantType = RawrXD::QuantType::F16; break;
            case 2:  desc.quantType = RawrXD::QuantType::Q4_0; break;
            case 3:  desc.quantType = RawrXD::QuantType::Q4_1; break;
            case 6:  desc.quantType = RawrXD::QuantType::Q5_0; break;
            case 7:  desc.quantType = RawrXD::QuantType::Q5_1; break;
            case 8:  desc.quantType = RawrXD::QuantType::Q8_0; break;
            case 9:  desc.quantType = RawrXD::QuantType::Q8_1; break;
            case 10: desc.quantType = RawrXD::QuantType::Q2_K; break;
            case 11: desc.quantType = RawrXD::QuantType::Q3_K; break;
            case 12: desc.quantType = RawrXD::QuantType::Q4_K; break;
            case 13: desc.quantType = RawrXD::QuantType::Q5_K; break;
            case 14: desc.quantType = RawrXD::QuantType::Q6_K; break;
            case 17: desc.quantType = RawrXD::QuantType::IQ2_XXS; break;
            case 18: desc.quantType = RawrXD::QuantType::IQ2_XS; break;
            case 19: desc.quantType = RawrXD::QuantType::IQ3_XXS; break;
            case 21: desc.quantType = RawrXD::QuantType::IQ4_NL; break;
            case 24: desc.quantType = RawrXD::QuantType::IQ4_XS; break;
            default: desc.quantType = RawrXD::QuantType::UNKNOWN; break;
        }

        view = RawrXD::TensorView::FromBuffer(desc, nullptr, false);
        return true;
    };

    // Layer 0 uses dense FFN (no router, no routed experts)
    // Layers 1+ use MoE (router + routed experts + shared expert)
    bool hasDenseFFN = false;
    if (layer == 0) {
        hasDenseFFN = resolve(gateName, ffnGate) && resolve(upName, ffnUp) && resolve(downName, ffnDown);
    }

    if (!hasDenseFFN) {
        // Router (required for MoE layers)
        if (!resolve(gateInpName, ffnGateInp)) { error = std::string("MoEWeights: ") + gateInpName + " not found"; return false; }
        if (!resolve(expProbsBName, expProbsB)) { error = std::string("MoEWeights: ") + expProbsBName + " not found"; return false; }

        // Routed experts
        if (!resolve(gateExpsName, ffnGateExps)) { error = std::string("MoEWeights: ") + gateExpsName + " not found"; return false; }
        if (!resolve(upExpsName, ffnUpExps))     { error = std::string("MoEWeights: ") + upExpsName + " not found"; return false; }
        if (!resolve(downExpsName, ffnDownExps)) { error = std::string("MoEWeights: ") + downExpsName + " not found"; return false; }
    }

    // Shared expert (present for MoE layers, optional for dense layer 0)
    if (layer > 0 || !hasDenseFFN) {
        if (!resolve(gateShexpName, ffnGateShexp)) { error = std::string("MoEWeights: ") + gateShexpName + " not found"; return false; }
        if (!resolve(upShexpName, ffnUpShexp))       { error = std::string("MoEWeights: ") + upShexpName + " not found"; return false; }
        if (!resolve(downShexpName, ffnDownShexp))   { error = std::string("MoEWeights: ") + downShexpName + " not found"; return false; }
    }

    // Norm (always present)
    if (!resolve(normName, ffnNorm)) { error = std::string("MoEWeights: ") + normName + " not found"; return false; }

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

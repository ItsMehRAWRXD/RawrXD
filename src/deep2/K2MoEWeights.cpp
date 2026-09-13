/* K2MoEWeights.cpp — physical ExpertSlice + selection-only eScoreCorrectionBias. */
#include "K2MoEWeights.hpp"
#include "K2GlobalTensorIndex.hpp"
#include "UniversalTensorDescriptor.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <numeric>

namespace Deep2 {
namespace {

ExpertSlice MakePhysicalSlice(const RawrXD::TensorView& src, uint32_t expertId,
                              uint32_t expertCount) {
    ExpertSlice slice;
    slice.source = src;
    slice.expertCount = expertCount;
    slice.expertId = expertId;
    if (!expertCount) return slice;
    const uint64_t total = src.byteSize();
    slice.expertStrideBytes = total / (uint64_t)expertCount;
    slice.byteOffset = (uint64_t)expertId * slice.expertStrideBytes;
    slice.byteSize = slice.expertStrideBytes;
    return slice;
}

} // namespace

ExpertSlice MoEWeights::GetExpertGate(uint32_t expertId,
                                      const KimiK2Config& config) const {
    return MakePhysicalSlice(ffnGateExps, expertId, config.numExperts);
}
ExpertSlice MoEWeights::GetExpertUp(uint32_t expertId,
                                    const KimiK2Config& config) const {
    return MakePhysicalSlice(ffnUpExps, expertId, config.numExperts);
}
ExpertSlice MoEWeights::GetExpertDown(uint32_t expertId,
                                      const KimiK2Config& config) const {
    return MakePhysicalSlice(ffnDownExps, expertId, config.numExperts);
}

bool MoEWeights::Validate(const KimiK2Config& config, std::string& error) const {
    (void)config;
    const bool isDense = !ffnGate.dims().empty() || !ffnUp.dims().empty() ||
                         !ffnDown.dims().empty();
    const bool isMoE = !ffnGateInp.dims().empty();
    if (!isDense && !isMoE) {
        error = "MoEWeights: neither dense nor MoE";
        return false;
    }
    if (isMoE) {
        if (ffnGateInp.dims().empty()) {
            error = "MoEWeights: ffn_gate_inp missing";
            return false;
        }
        if (eScoreCorrectionBias.dims().empty()) {
            error = "MoEWeights: eScoreCorrectionBias (exp_probs_b) missing";
            return false;
        }
        if (ffnGateExps.dims().empty() || ffnUpExps.dims().empty() ||
            ffnDownExps.dims().empty()) {
            error = "MoEWeights: routed expert tensors missing";
            return false;
        }
        if (ffnGateShexp.dims().empty() || ffnUpShexp.dims().empty() ||
            ffnDownShexp.dims().empty()) {
            error = "MoEWeights: shared expert missing";
            return false;
        }
    }
    if (ffnNorm.dims().empty()) {
        error = "MoEWeights: ffn_norm missing";
        return false;
    }
    return true;
}

bool MoEWeights::ResolveFromTensorIndex(const GlobalTensorIndex& index,
                                        uint32_t layer, std::string& error) {
    char gateInpName[64], biasName[64];
    char gateExpsName[64], upExpsName[64], downExpsName[64];
    char gateShexpName[64], upShexpName[64], downShexpName[64];
    char gateName[64], upName[64], downName[64], normName[64];
    std::snprintf(gateInpName, sizeof(gateInpName), "blk.%u.ffn_gate_inp.weight", layer);
    std::snprintf(biasName, sizeof(biasName), "blk.%u.exp_probs_b.bias", layer);
    std::snprintf(gateExpsName, sizeof(gateExpsName), "blk.%u.ffn_gate_exps.weight", layer);
    std::snprintf(upExpsName, sizeof(upExpsName), "blk.%u.ffn_up_exps.weight", layer);
    std::snprintf(downExpsName, sizeof(downExpsName), "blk.%u.ffn_down_exps.weight", layer);
    std::snprintf(gateShexpName, sizeof(gateShexpName), "blk.%u.ffn_gate_shexp.weight", layer);
    std::snprintf(upShexpName, sizeof(upShexpName), "blk.%u.ffn_up_shexp.weight", layer);
    std::snprintf(downShexpName, sizeof(downShexpName), "blk.%u.ffn_down_shexp.weight", layer);
    std::snprintf(gateName, sizeof(gateName), "blk.%u.ffn_gate.weight", layer);
    std::snprintf(upName, sizeof(upName), "blk.%u.ffn_up.weight", layer);
    std::snprintf(downName, sizeof(downName), "blk.%u.ffn_down.weight", layer);
    std::snprintf(normName, sizeof(normName), "blk.%u.ffn_norm.weight", layer);

    auto resolve = [&](const char* name, RawrXD::TensorView& view) -> bool {
        auto refOpt = index.Find(name);
        if (!refOpt) return false;
        const auto& ref = *refOpt;
        RawrXD::UniversalTensorDescriptor desc;
        desc.numDims = ref.nDims;
        for (uint8_t i = 0; i < ref.nDims && i < 8; ++i) desc.shape[i] = ref.shape[i];
        desc.layout = RawrXD::TensorLayout::DENSE;
        desc.role = RawrXD::TensorRole::WEIGHT;
        desc.memorySpace = RawrXD::UniversalTensorDescriptor::MemorySpace::NVME;
        desc.data = nullptr;
        switch (ref.ggmlType) {
            case 0: desc.quantType = RawrXD::QuantType::F32; break;
            case 1: desc.quantType = RawrXD::QuantType::F16; break;
            case 8: desc.quantType = RawrXD::QuantType::Q8_0; break;
            case 12: desc.quantType = RawrXD::QuantType::Q4_K; break;
            case 14: desc.quantType = RawrXD::QuantType::Q6_K; break;
            default: desc.quantType = RawrXD::QuantType::UNKNOWN; break;
        }
        /* Physical GGUF bytes as BLOCKED 1-byte elems — not dim0*dim1*sizeof(float). */
        if (ref.byteSize) {
            desc.layout = RawrXD::TensorLayout::BLOCKED;
            desc.numDims = 1;
            desc.shape[0] = ref.byteSize;
            desc.blockSize = 1;
            desc.blockSizeBytes = 1;
        }
        view = RawrXD::TensorView::FromBuffer(desc, nullptr, false);
        return true;
    };

    bool hasDense = false;
    if (layer == 0)
        hasDense = resolve(gateName, ffnGate) && resolve(upName, ffnUp) &&
                   resolve(downName, ffnDown);
    if (!hasDense) {
        if (!resolve(gateInpName, ffnGateInp)) {
            error = std::string("MoEWeights: ") + gateInpName + " not found";
            return false;
        }
        if (!resolve(biasName, eScoreCorrectionBias)) {
            error = std::string("MoEWeights: ") + biasName + " not found";
            return false;
        }
        if (!resolve(gateExpsName, ffnGateExps) || !resolve(upExpsName, ffnUpExps) ||
            !resolve(downExpsName, ffnDownExps)) {
            error = "MoEWeights: routed expert tensor missing";
            return false;
        }
    }
    if (layer > 0 || !hasDense) {
        if (!resolve(gateShexpName, ffnGateShexp) || !resolve(upShexpName, ffnUpShexp) ||
            !resolve(downShexpName, ffnDownShexp)) {
            error = "MoEWeights: shared expert missing";
            return false;
        }
    }
    if (!resolve(normName, ffnNorm)) {
        error = std::string("MoEWeights: ") + normName + " not found";
        return false;
    }
    return true;
}

bool MoEWeights::DetectMoE(const std::string& tensorName) {
    return tensorName.find("ffn_gate_exps") != std::string::npos ||
           tensorName.find("ffn_gate_inp") != std::string::npos ||
           tensorName.find("exp_probs_b") != std::string::npos;
}
bool MoEWeights::DetectDenseFFN(const std::string& tensorName) {
    return tensorName.find("ffn_gate") != std::string::npos &&
           tensorName.find("exps") == std::string::npos &&
           tensorName.find("shexp") == std::string::npos;
}
bool MoEWeights::DetectSharedExpert(const std::string& tensorName) {
    return tensorName.find("shexp") != std::string::npos;
}

bool KimiK2Router::Initialize(const KimiK2Config& config, std::string& error) {
    if (!config.numExperts || !config.expertsPerToken) {
        error = "KimiK2Router: numExperts/expertsPerToken zero";
        return false;
    }
    config_ = config;
    initialized_ = true;
    return true;
}

void KimiK2Router::SetRouterWeights(const RawrXD::TensorView& gateInp,
                                    const RawrXD::TensorView& eScoreCorrectionBias) {
    if (!gateInp.data() || !eScoreCorrectionBias.data()) return;
    const size_t hiddenDim = gateInp.dims()[0];
    const size_t numExperts = gateInp.dims()[1];
    routerWeights_.resize(hiddenDim * numExperts);
    eScoreCorrectionBias_.resize(numExperts);
    const float* g = static_cast<const float*>(gateInp.data());
    std::copy(g, g + routerWeights_.size(), routerWeights_.begin());
    const float* b = static_cast<const float*>(eScoreCorrectionBias.data());
    std::copy(b, b + numExperts, eScoreCorrectionBias_.begin());
}

std::vector<float> KimiK2Router::ComputeSigmoidScores(const float* hidden) {
    const uint32_t H = config_.hiddenDim;
    const uint32_t E = config_.numExperts;
    std::vector<float> scores(E);
    for (uint32_t e = 0; e < E; ++e) {
        float logit = 0.f; /* NO bias in pre-sigmoid logits */
        for (uint32_t h = 0; h < H; ++h)
            logit += hidden[h] * routerWeights_[h * E + e];
        scores[e] = 1.f / (1.f + std::exp(-logit));
    }
    return scores;
}

MoERoutingResult KimiK2Router::SelectExpertsNoAuxTC(
    const std::vector<float>& scores, const std::vector<float>& choiceScores) {
    MoERoutingResult result{};
    const uint32_t E = config_.numExperts;
    const uint32_t k = config_.expertsPerToken;
    std::vector<uint32_t> idx(E);
    std::iota(idx.begin(), idx.end(), 0);
    std::partial_sort(idx.begin(), idx.begin() + k, idx.end(),
                      [&](uint32_t a, uint32_t b) {
                          return choiceScores[a] > choiceScores[b];
                      });
    result.count = k;
    for (uint32_t i = 0; i < k; ++i) {
        result.expertIds[i] = idx[i];
        result.weights[i] = scores[idx[i]]; /* UNBIASED scores, not choice */
    }
    return result;
}

void KimiK2Router::NormalizeAndScaleSelectedWeights(MoERoutingResult& result) {
    float sum = 0.f;
    for (uint32_t i = 0; i < result.count; ++i) sum += result.weights[i];
    const float scale =
        config_.routedScalingFactor > 0.f ? config_.routedScalingFactor : 2.827f;
    if (sum > 0.f) {
        for (uint32_t i = 0; i < result.count; ++i)
            result.weights[i] = (result.weights[i] / sum) * scale;
    }
}

bool KimiK2Router::Route(const float* hidden, MoERoutingResult& result,
                         std::string& error) {
    if (!initialized_ || !hidden || routerWeights_.empty()) {
        error = "KimiK2Router: not ready";
        return false;
    }
    const std::vector<float> scores = ComputeSigmoidScores(hidden);
    std::vector<float> choice = scores;
    if (eScoreCorrectionBias_.size() == scores.size()) {
        for (size_t e = 0; e < scores.size(); ++e)
            choice[e] = scores[e] + eScoreCorrectionBias_[e]; /* selection ONLY */
    }
    result = SelectExpertsNoAuxTC(scores, choice);
    NormalizeAndScaleSelectedWeights(result);
    totalTokensRouted++;
    totalExpertActivations += result.count;
    return true;
}

std::vector<MoERoutingResult> KimiK2Router::RouteBatch(const float* hiddenBatch,
                                                      uint32_t numTokens,
                                                      std::string& error) {
    std::vector<MoERoutingResult> out;
    out.reserve(numTokens);
    for (uint32_t t = 0; t < numTokens; ++t) {
        MoERoutingResult r;
        if (!Route(hiddenBatch + t * config_.hiddenDim, r, error)) return {};
        out.push_back(std::move(r));
    }
    return out;
}

} // namespace Deep2

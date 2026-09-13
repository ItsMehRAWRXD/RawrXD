// ============================================================================
// K2MoEWeights.hpp — K2-004/005 MoE Tensor Schema with Expert Addressing
//
// Router (K2 0905):
//   scores[e] = sigmoid(logit[e])
//   choice[e] = scores[e] + eScoreCorrectionBias[e]   // selection ONLY
//   top-k on choice; FINAL weights = unbiased scores → norm → ×2.827
// ExpertSlice: physical quantized byte stride (never dim0*dim1*sizeof).
// ============================================================================
#pragma once
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

class GlobalTensorIndex;

// Addressable view into one expert within a 3-D (or expert-last) tensor.
// Stride/offset MUST be physical GGUF bytes (block-packed), not float elems.
struct ExpertSlice {
    RawrXD::TensorView source;
    uint32_t expertCount = 0;
    uint32_t expertId = 0;
    uint64_t expertStrideBytes = 0;
    uint64_t byteOffset = 0;
    uint64_t byteSize = 0;

    bool IsValid() const {
        if (!source.data()) return false;
        if (expertId >= expertCount) return false;
        if (!byteSize) return false;
        const uint64_t total = source.byteSize();
        if (byteOffset > total) return false;
        if (byteSize > total - byteOffset) return false;
        return true;
    }

    const void* Data() const {
        if (!source.data()) return nullptr;
        return static_cast<const uint8_t*>(source.data()) + byteOffset;
    }
    void* Data() {
        if (!source.data()) return nullptr;
        return static_cast<uint8_t*>(source.data()) + byteOffset;
    }
};

struct MoEWeights {
    RawrXD::TensorView ffnGateInp;              // router projection
    RawrXD::TensorView eScoreCorrectionBias;  // exp_probs_b — CHOICE only
    RawrXD::TensorView ffnGateExps;
    RawrXD::TensorView ffnUpExps;
    RawrXD::TensorView ffnDownExps;
    RawrXD::TensorView ffnGateShexp;
    RawrXD::TensorView ffnUpShexp;
    RawrXD::TensorView ffnDownShexp;
    RawrXD::TensorView ffnGate;
    RawrXD::TensorView ffnUp;
    RawrXD::TensorView ffnDown;
    RawrXD::TensorView ffnNorm;

    ExpertSlice GetExpertGate(uint32_t expertId, const KimiK2Config& config) const;
    ExpertSlice GetExpertUp(uint32_t expertId, const KimiK2Config& config) const;
    ExpertSlice GetExpertDown(uint32_t expertId, const KimiK2Config& config) const;

    bool Validate(const KimiK2Config& config, std::string& error) const;
    bool ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer,
                                std::string& error);

    static bool DetectMoE(const std::string& tensorName);
    static bool DetectDenseFFN(const std::string& tensorName);
    static bool DetectSharedExpert(const std::string& tensorName);
};

// Router → residency handoff. weights are FINAL coefficients (sum ≈ 2.827).
struct MoERoutingResult {
    static constexpr uint32_t kMaxExperts = 8;

    uint32_t expertIds[kMaxExperts] = {};
    // Unbiased sigmoid at selected IDs → normalize to sum 1 → × routedScalingFactor.
    // Final sum ≈ 2.827 for K2 0905 (NOT 1.0).
    float weights[kMaxExperts] = {};
    uint32_t count = 0;

    bool IsValid() const { return count > 0 && count <= kMaxExperts; }
    bool Contains(uint32_t expertId) const {
        for (uint32_t i = 0; i < count; ++i)
            if (expertIds[i] == expertId) return true;
        return false;
    }
};

class KimiK2Router {
public:
    bool Initialize(const KimiK2Config& config, std::string& error);
    bool Route(const float* hidden, MoERoutingResult& result, std::string& error);
    std::vector<MoERoutingResult> RouteBatch(const float* hiddenBatch,
                                             uint32_t numTokens,
                                             std::string& error);

    // gateInp = router W; eScoreCorrectionBias = exp_probs_b (selection only).
    void SetRouterWeights(const RawrXD::TensorView& gateInp,
                          const RawrXD::TensorView& eScoreCorrectionBias);

    uint64_t totalTokensRouted = 0;
    uint64_t totalExpertActivations = 0;

private:
    KimiK2Config config_;
    bool initialized_ = false;
    std::vector<float> routerWeights_;           // [hiddenDim, numExperts]
    std::vector<float> eScoreCorrectionBias_;    // [numExperts] — NOT logit bias

    std::vector<float> ComputeSigmoidScores(const float* hidden);
    MoERoutingResult SelectExpertsNoAuxTC(const std::vector<float>& scores,
                                          const std::vector<float>& choiceScores);
    void NormalizeAndScaleSelectedWeights(MoERoutingResult& result);
};

} // namespace Deep2

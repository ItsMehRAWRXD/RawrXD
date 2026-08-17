// ============================================================================
// K2MoEWeights.hpp — K2-004/005 MoE Tensor Schema with Expert Addressing
//
// CORRECTIONS:
//   - Expert tensors are addressable slices, not monolithic 3D tensors
//   - Router uses sigmoid + noaux_tc + norm_topk_prob + routed_scaling_factor=2.827
//   - NOT generic softmax/top-k
//
// Execution model:
//   token → router → top-8/384 → ExpertSlice[] → residency → GEMM
// ============================================================================
#pragma once
#include "KimiK2Config.hpp"
#include "TensorView.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

// Forward declaration
class GlobalTensorIndex;

// ============================================================================
// ExpertSlice — Addressable view into a single expert within a 3D tensor
//
// Base tensor: [dim0, dim1, numExperts]
// Expert N:   slice at index N along the expert dimension
// ============================================================================
struct ExpertSlice {
    RawrXD::TensorView source;      // Full 3D tensor descriptor
    uint32_t expertCount = 0;         // Total experts in source (e.g. 384)
    uint32_t expertId = 0;            // Which expert this slice represents
    uint64_t expertStrideBytes = 0;   // Byte stride between experts
    uint64_t byteOffset = 0;          // Offset from source.data() to this expert
    uint64_t byteSize = 0;            // Size of this expert's weights

    // Validate: check expertId is within bounds
    bool IsValid() const {
        return source.data() != nullptr && expertId < expertCount && byteSize > 0;
    }

    // Get pointer to this expert's data
    const void* Data() const {
        if (!source.data()) return nullptr;
        return static_cast<const uint8_t*>(source.data()) + byteOffset;
    }

    void* Data() {
        if (!source.data()) return nullptr;
        return static_cast<uint8_t*>(source.data()) + byteOffset;
    }
};

// ============================================================================
// MoEWeights — Per-layer MoE tensor collection
//
// Layer 0 (dense): only shared expert + dense FFN
// Layers 1-60 (MoE): router + 384 routed experts + shared expert
// ============================================================================
struct MoEWeights {
    // --- Router ---
    RawrXD::TensorView ffnGateInp;        // [hiddenDim, numExperts]     — router projection
    RawrXD::TensorView expProbsB;         // [numExperts]                — router bias

    // --- Routed expert tensors (3D: [dim0, dim1, 384]) ---
    // Each contains ALL experts; individual experts accessed via ExpertSlice
    RawrXD::TensorView ffnGateExps;       // [moeIntermediateSize, hiddenDim, numExperts]
    RawrXD::TensorView ffnUpExps;         // [moeIntermediateSize, hiddenDim, numExperts]
    RawrXD::TensorView ffnDownExps;       // [hiddenDim, moeIntermediateSize, numExperts]

    // --- Shared expert (always active) ---
    RawrXD::TensorView ffnGateShexp;      // [moeIntermediateSize, hiddenDim]
    RawrXD::TensorView ffnUpShexp;        // [moeIntermediateSize, hiddenDim]
    RawrXD::TensorView ffnDownShexp;      // [hiddenDim, moeIntermediateSize]

    // --- Dense FFN (Layer 0 only) ---
    RawrXD::TensorView ffnGate;           // [moeIntermediateSize, hiddenDim] — dense gate
    RawrXD::TensorView ffnUp;             // [moeIntermediateSize, hiddenDim] — dense up
    RawrXD::TensorView ffnDown;           // [hiddenDim, moeIntermediateSize] — dense down

    // --- Norm ---
    RawrXD::TensorView ffnNorm;           // [hiddenDim] — pre-FFN RMSNorm

    // =========================================================================
    // Expert slice accessors (NO full tensor materialization)
    // =========================================================================
    ExpertSlice GetExpertGate(uint32_t expertId, const KimiK2Config& config) const;
    ExpertSlice GetExpertUp(uint32_t expertId, const KimiK2Config& config) const;
    ExpertSlice GetExpertDown(uint32_t expertId, const KimiK2Config& config) const;

    // =========================================================================
    // Validation
    // =========================================================================
    bool Validate(const KimiK2Config& config, std::string& error) const;

    // =========================================================================
    // Resolve tensors from a GlobalTensorIndex for a specific layer
    // =========================================================================
    bool ResolveFromTensorIndex(const GlobalTensorIndex& index, uint32_t layer, std::string& error);

    // =========================================================================
    // Architecture detection
    // =========================================================================
    static bool DetectMoE(const std::string& tensorName);
    static bool DetectDenseFFN(const std::string& tensorName);
    static bool DetectSharedExpert(const std::string& tensorName);
};

// ============================================================================
// MoERoutingResult — Output of the router, input to residency manager
//
// This is the handoff boundary between router and residency:
//   Router → MoERoutingResult → Residency Manager → ExpertSlice[] → GEMM
// ============================================================================
struct MoERoutingResult {
    static constexpr uint32_t kMaxExperts = 8;  // K2 0905: expertsPerToken

    uint32_t expertIds[kMaxExperts] = {};
    float    weights[kMaxExperts] = {};
    uint32_t count = 0;

    // Normalized probabilities (sum to 1.0 after norm_topk_prob)
    bool IsValid() const { return count > 0 && count <= kMaxExperts; }

    // Check if an expert is in the selected set
    bool Contains(uint32_t expertId) const {
        for (uint32_t i = 0; i < count; ++i) {
            if (expertIds[i] == expertId) return true;
        }
        return false;
    }
};

// ============================================================================
// KimiK2Router — Exact K2 0905 routing semantics
//
// NOT generic softmax/top-k. Uses:
//   - scoring_func = sigmoid
//   - topk_method  = noaux_tc
//   - topk_group   = 1
//   - norm_topk_prob = true
//   - routed_scaling_factor = 2.827
// ============================================================================
class KimiK2Router {
public:
    // Initialize with config (must be validated KimiK2Config)
    bool Initialize(const KimiK2Config& config, std::string& error);

    // Route a single token
    // hidden: [hiddenDim] float array
    // result: filled with top-k expert IDs and normalized weights
    bool Route(const float* hidden, MoERoutingResult& result, std::string& error);

    // Route a batch of tokens (for prefill optimization)
    // Returns one result per token
    std::vector<MoERoutingResult> RouteBatch(
        const float* hiddenBatch,  // [numTokens, hiddenDim]
        uint32_t numTokens,
        std::string& error);

    // Set router weights from GGUF tensor
    void SetRouterWeights(const RawrXD::TensorView& gateInp,
                          const RawrXD::TensorView& bias);

    // Statistics
    uint64_t totalTokensRouted = 0;
    uint64_t totalExpertActivations = 0;

private:
    KimiK2Config config_;
    bool initialized_ = false;

    // Router parameters (copied from tensor views)
    std::vector<float> routerWeights_;  // [hiddenDim, numExperts]
    std::vector<float> routerBias_;     // [numExperts]

    // Internal: compute sigmoid scores
    std::vector<float> ComputeSigmoidScores(const float* hidden);

    // Internal: noaux_tc top-k selection
    MoERoutingResult SelectExpertsNoAuxTC(const std::vector<float>& scores);

    // Internal: normalize selected probabilities
    void NormalizeSelectedProbs(MoERoutingResult& result);
};

} // namespace Deep2

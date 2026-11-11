#pragma once
#include <cstdint>
#include <cstddef>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038: Fused Tree Attention Kernel (Q@K^T → Softmax → A@V)
// ═══════════════════════════════════════════════════════════════════════════════
// Single kernel eliminating intermediate writes
// Target: 0.5-0.8 µs total (down from 1.846 µs baseline)
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// External assembly function
extern "C" {
    // Fused attention: Q@K^T → Softmax → A@V in single pass
    void TreeAttention_Fused_VAL038(
        float* output,              // [num_q, head_dim]
        const float* Q,             // [num_q, head_dim]
        const float* K,             // [num_k, head_dim]
        const float* V,             // [num_k, head_dim]
        uint32_t num_q,             // Number of queries
        uint32_t num_k,             // Number of keys
        const uint8_t* tree_mask    // [num_q, num_k] causal mask
    );
}

// C++ wrapper class
class TreeAttentionFusedVAL038 {
public:
    struct Config {
        uint32_t headDim = 64;      // Must match assembly constant
        uint32_t blockM = 16;       // Query block size
        uint32_t blockN = 16;       // Key block size
    };

    explicit TreeAttentionFusedVAL038(const Config& cfg = {}) : config_(cfg) {}

    void Compute(
        float* output,
        const float* Q,
        const float* K,
        const float* V,
        uint32_t numQ,
        uint32_t numK,
        const uint8_t* treeMask
    ) {
        TreeAttention_Fused_VAL038(output, Q, K, V, numQ, numK, treeMask);
    }

    // Check if AVX-512 is available
    static bool IsSupported();

    const Config& GetConfig() const { return config_; }

private:
    Config config_;
};

} // namespace RawrXD

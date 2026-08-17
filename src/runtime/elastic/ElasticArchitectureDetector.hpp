#pragma once

#include "ElasticTypes.hpp"
#include "../gguf_tensor_loader.hpp"
#include <string>
#include <vector>
#include <unordered_set>

namespace RawrXD {
namespace Elastic {

// ============================================================================
// ElasticArchitectureDetector
// ============================================================================
// Inspects the real GGUF tensor index and classifies the model architecture.
//
// Detection rules (heuristic, based on actual tensor naming conventions):
//   - Native MoE: presence of "ffn_gate_exps", "ffn_up_exps", "ffn_down_exps"
//   - Dense: standard "attn_q/k/v/o", "ffn_gate", "ffn_up", "ffn_down"
//   - Hybrid: both attention dense and MoE FFN tensors present
//
// Does NOT infer MoE from expert_id > 1. Does NOT assume attention naming.
// ============================================================================

class ElasticArchitectureDetector {
public:
    explicit ElasticArchitectureDetector(const rawrxd::runtime::GGUFTensorLoader& loader);

    // Run detection and populate profile. Call once after construction.
    ArchitectureProfile detect();

    // Access the populated profile
    const ArchitectureProfile& profile() const { return m_profile; }

private:
    const rawrxd::runtime::GGUFTensorLoader& m_loader;
    ArchitectureProfile m_profile;

    bool has_moe_tensors() const;
    bool has_dense_ffn_tensors() const;
    bool has_attention_tensors() const;
    uint32_t count_layers() const;
    uint32_t count_experts_per_layer() const;
    void build_compute_blocks();
};

} // namespace Elastic
} // namespace RawrXD

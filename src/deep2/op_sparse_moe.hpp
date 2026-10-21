#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Qwen4Exp {

enum class SparseMoEWeightFormat : uint8_t {
    F32,
    BF16,
    IQ2S,
    MXFP4,
};

struct SparseMoEDescriptor {
    uint32_t hidden = 2560;
    uint32_t intermediate = 640;
    uint32_t experts = 512;
    uint32_t top_k = 10;
    SparseMoEWeightFormat gate_format = SparseMoEWeightFormat::IQ2S;
    SparseMoEWeightFormat up_format = SparseMoEWeightFormat::IQ2S;
    SparseMoEWeightFormat down_format = SparseMoEWeightFormat::MXFP4;
};

bool ValidateSparseMoEDescriptor(const SparseMoEDescriptor& descriptor,
                                 std::string& failure);

// Router-only reference. router_weight is [hidden, experts] in F32 and the
// result contains deterministic top-k expert ids and normalized weights.
bool SparseMoERouteReference(const SparseMoEDescriptor& descriptor,
                             const std::vector<float>& hidden,
                             const std::vector<float>& router_weight,
                             std::vector<uint32_t>& expert_ids,
                             std::vector<float>& expert_weights,
                             std::string& failure);

// Full expert reference accepts tensors already independently dequantized to
// F32 in expert-major layouts. The production Qwen path must not call this
// until IQ2_S/MXFP4 dequantization is explicitly certified.
bool SparseMoEFloatReference(const SparseMoEDescriptor& descriptor,
                             const std::vector<float>& hidden,
                             const std::vector<float>& router_weight,
                             const std::vector<float>& gate_weight,
                             const std::vector<float>& up_weight,
                             const std::vector<float>& down_weight,
                             std::vector<float>& output,
                             std::string& failure);

} // namespace Deep2::Qwen4Exp

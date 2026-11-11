#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Qwen4Exp {

struct HyperconnectionDescriptor {
    uint32_t tokens = 0;
    uint32_t hidden = 0;
    uint32_t streams = 4;
    float epsilon = 1.0e-5f;
    bool bf16_round_before_norm = false;
};

uint64_t HyperconnectionWidth(const HyperconnectionDescriptor& descriptor);
bool ValidateHyperconnectionDescriptor(const HyperconnectionDescriptor& descriptor,
                                       std::string& failure);

bool HyperconnectionGateMix(const HyperconnectionDescriptor& descriptor,
                            const std::vector<float>& stream_values,
                            const std::vector<float>& gate_logits,
                            std::vector<float>& output,
                            std::string& failure);

bool HyperconnectionCombineNorm(const HyperconnectionDescriptor& descriptor,
                                const std::vector<float>& residual,
                                const std::vector<float>& block_output,
                                const std::vector<float>& injection_logits,
                                const std::vector<float>& norm_weight,
                                std::vector<float>& combined,
                                std::vector<float>& normalized,
                                std::string& failure);

} // namespace Deep2::Qwen4Exp

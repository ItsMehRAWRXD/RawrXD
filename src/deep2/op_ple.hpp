#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Qwen4Exp {

struct PLEDescriptor {
    uint32_t tokens = 0;
    uint32_t channels = 0;
    uint32_t kernel = 4;
    uint32_t dilation = 3;
};

uint32_t PLEStateLength(const PLEDescriptor& descriptor);
uint64_t PLEStateElements(const PLEDescriptor& descriptor);
bool ValidatePLEDescriptor(const PLEDescriptor& descriptor, std::string& failure);

// Weights are kernel-major [kernel, channels]. State is channel-major
// [channels, (kernel-1)*dilation], oldest sample first.
bool PLEReferenceDecode(const PLEDescriptor& descriptor,
                        const std::vector<float>& input,
                        const std::vector<float>& weights,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure);

} // namespace Deep2::Qwen4Exp

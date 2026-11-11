#include "op_ple.hpp"

#include <cmath>

namespace Deep2::Qwen4Exp {
namespace {

bool AllFinite(const std::vector<float>& values) {
    for (float value : values) if (!std::isfinite(value)) return false;
    return true;
}

float Silu(float value) {
    if (value >= 0.0f) return value / (1.0f + std::exp(-value));
    const float e = std::exp(value);
    return value * e / (1.0f + e);
}

} // namespace

uint32_t PLEStateLength(const PLEDescriptor& descriptor) {
    if (descriptor.kernel == 0 || descriptor.dilation == 0) return 0;
    return (descriptor.kernel - 1u) * descriptor.dilation;
}

uint64_t PLEStateElements(const PLEDescriptor& descriptor) {
    return static_cast<uint64_t>(descriptor.channels) * PLEStateLength(descriptor);
}

bool ValidatePLEDescriptor(const PLEDescriptor& descriptor, std::string& failure) {
    if (descriptor.tokens == 0 || descriptor.channels == 0 || descriptor.kernel == 0 ||
        descriptor.dilation == 0 || descriptor.kernel > 32) {
        failure = "PLE dimensions are zero or outside the bounded kernel contract";
        return false;
    }
    if (descriptor.kernel != 4 || descriptor.dilation != 3) {
        failure = "Qwen4Exp PLE requires kernel=4 and dilation=3 from GGUF metadata";
        return false;
    }
    if (PLEStateElements(descriptor) > (1ull << 31)) {
        failure = "PLE state exceeds the bounded executor limit";
        return false;
    }
    return true;
}

bool PLEReferenceDecode(const PLEDescriptor& descriptor,
                        const std::vector<float>& input,
                        const std::vector<float>& weights,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure) {
    if (!ValidatePLEDescriptor(descriptor, failure)) return false;
    const size_t channels = descriptor.channels;
    const size_t state_length = PLEStateLength(descriptor);
    if (input.size() != static_cast<size_t>(descriptor.tokens) * channels ||
        weights.size() != static_cast<size_t>(descriptor.kernel) * channels ||
        state.size() != static_cast<size_t>(PLEStateElements(descriptor))) {
        failure = "PLE input, weights, or state shape does not match the descriptor";
        output.clear();
        return false;
    }
    if (!AllFinite(input) || !AllFinite(weights) || !AllFinite(state)) {
        failure = "PLE input, weights, or state contains NaN/Inf";
        output.clear();
        return false;
    }

    output.assign(input.size(), 0.0f);
    for (uint32_t token = 0; token < descriptor.tokens; ++token) {
        for (uint32_t channel = 0; channel < descriptor.channels; ++channel) {
            float accumulator = 0.0f;
            for (uint32_t tap = 0; tap < descriptor.kernel; ++tap) {
                const int source = static_cast<int>(token) -
                    static_cast<int>(descriptor.kernel - 1u - tap) *
                    static_cast<int>(descriptor.dilation);
                float sample = 0.0f;
                if (source < 0) {
                    const int state_index = static_cast<int>(state_length) + source;
                    if (state_index >= 0 && state_index < static_cast<int>(state_length))
                        sample = state[static_cast<size_t>(channel) * state_length + state_index];
                } else {
                    sample = input[static_cast<size_t>(source) * channels + channel];
                }
                accumulator += sample * weights[static_cast<size_t>(tap) * channels + channel];
            }
            output[static_cast<size_t>(token) * channels + channel] = Silu(accumulator);
        }
    }

    if (state_length != 0) {
        std::vector<float> next_state(state.size(), 0.0f);
        for (uint32_t channel = 0; channel < descriptor.channels; ++channel) {
            for (uint32_t offset = 0; offset < state_length; ++offset) {
                const int source = static_cast<int>(descriptor.tokens) -
                    static_cast<int>(state_length) + static_cast<int>(offset);
                float sample = 0.0f;
                if (source < 0) {
                    const int state_index = static_cast<int>(state_length) + source;
                    sample = state[static_cast<size_t>(channel) * state_length + state_index];
                } else {
                    sample = input[static_cast<size_t>(source) * channels + channel];
                }
                next_state[static_cast<size_t>(channel) * state_length + offset] = sample;
            }
        }
        state.swap(next_state);
    }
    if (!AllFinite(output) || !AllFinite(state)) {
        failure = "PLE recurrence produced NaN/Inf";
        output.clear();
        return false;
    }
    return true;
}

} // namespace Deep2::Qwen4Exp

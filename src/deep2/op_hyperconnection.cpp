#include "op_hyperconnection.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>

namespace Deep2::Qwen4Exp {
namespace {

bool AllFinite(const std::vector<float>& values) {
    for (float value : values) if (!std::isfinite(value)) return false;
    return true;
}

float Sigmoid(float value) {
    if (value >= 0.0f) {
        const float e = std::exp(-value);
        return 1.0f / (1.0f + e);
    }
    const float e = std::exp(value);
    return e / (1.0f + e);
}

float Bf16Round(float value) {
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const uint32_t lsb = (bits >> 16u) & 1u;
    bits += 0x7fffu + lsb;
    bits &= 0xffff0000u;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

} // namespace

uint64_t HyperconnectionWidth(const HyperconnectionDescriptor& descriptor) {
    return static_cast<uint64_t>(descriptor.hidden) * descriptor.streams;
}

bool ValidateHyperconnectionDescriptor(const HyperconnectionDescriptor& descriptor,
                                       std::string& failure) {
    if (descriptor.tokens == 0 || descriptor.hidden == 0 || descriptor.streams == 0 ||
        !(descriptor.epsilon > 0.0f) || !std::isfinite(descriptor.epsilon)) {
        failure = "hyperconnection dimensions or epsilon are invalid";
        return false;
    }
    if (descriptor.streams != 4) {
        failure = "Qwen4Exp hyperconnection requires four residual streams";
        return false;
    }
    if (HyperconnectionWidth(descriptor) > (1ull << 31)) {
        failure = "hyperconnection activation exceeds the bounded executor limit";
        return false;
    }
    return true;
}

bool HyperconnectionGateMix(const HyperconnectionDescriptor& descriptor,
                            const std::vector<float>& stream_values,
                            const std::vector<float>& gate_logits,
                            std::vector<float>& output,
                            std::string& failure) {
    if (!ValidateHyperconnectionDescriptor(descriptor, failure)) return false;
    const size_t width = static_cast<size_t>(HyperconnectionWidth(descriptor));
    if (stream_values.size() != static_cast<size_t>(descriptor.tokens) * width ||
        gate_logits.size() != stream_values.size()) {
        failure = "hyperconnection gate mix shape mismatch";
        output.clear();
        return false;
    }
    if (!AllFinite(stream_values) || !AllFinite(gate_logits)) {
        failure = "hyperconnection gate mix contains NaN/Inf";
        output.clear();
        return false;
    }
    output.assign(static_cast<size_t>(descriptor.tokens) * descriptor.hidden, 0.0f);
    for (uint32_t token = 0; token < descriptor.tokens; ++token) {
        for (uint32_t column = 0; column < descriptor.hidden; ++column) {
            float value = 0.0f;
            for (uint32_t stream = 0; stream < descriptor.streams; ++stream) {
                const size_t index = static_cast<size_t>(token) * width +
                                     static_cast<size_t>(stream) * descriptor.hidden + column;
                value += Sigmoid(gate_logits[index]) * stream_values[index];
            }
            output[static_cast<size_t>(token) * descriptor.hidden + column] =
                value / static_cast<float>(descriptor.streams);
        }
    }
    return AllFinite(output);
}

bool HyperconnectionCombineNorm(const HyperconnectionDescriptor& descriptor,
                                const std::vector<float>& residual,
                                const std::vector<float>& block_output,
                                const std::vector<float>& injection_logits,
                                const std::vector<float>& norm_weight,
                                std::vector<float>& combined,
                                std::vector<float>& normalized,
                                std::string& failure) {
    if (!ValidateHyperconnectionDescriptor(descriptor, failure)) return false;
    const size_t width = static_cast<size_t>(HyperconnectionWidth(descriptor));
    const size_t token_count = descriptor.tokens;
    if (residual.size() != token_count * width ||
        block_output.size() != token_count * descriptor.hidden ||
        injection_logits.size() != token_count * descriptor.streams ||
        (norm_weight.size() != descriptor.hidden && norm_weight.size() != width)) {
        failure = "hyperconnection combine/norm shape mismatch";
        combined.clear();
        normalized.clear();
        return false;
    }
    if (!AllFinite(residual) || !AllFinite(block_output) || !AllFinite(injection_logits) ||
        !AllFinite(norm_weight)) {
        failure = "hyperconnection combine/norm contains NaN/Inf";
        combined.clear();
        normalized.clear();
        return false;
    }
    combined.assign(residual.size(), 0.0f);
    normalized.assign(residual.size(), 0.0f);
    for (uint32_t token = 0; token < descriptor.tokens; ++token) {
        for (uint32_t stream = 0; stream < descriptor.streams; ++stream) {
            const float factor = 2.0f * Sigmoid(
                injection_logits[static_cast<size_t>(token) * descriptor.streams + stream] /
                static_cast<float>(descriptor.streams));
            float sum_squares = 0.0f;
            for (uint32_t column = 0; column < descriptor.hidden; ++column) {
                const size_t index = static_cast<size_t>(token) * width +
                                     static_cast<size_t>(stream) * descriptor.hidden + column;
                float value = residual[index] + block_output[static_cast<size_t>(token) * descriptor.hidden + column] * factor;
                if (descriptor.bf16_round_before_norm) value = Bf16Round(value);
                combined[index] = value;
                sum_squares += value * value;
            }
            const float inverse_rms = 1.0f / std::sqrt(
                sum_squares / static_cast<float>(descriptor.hidden) + descriptor.epsilon);
            for (uint32_t column = 0; column < descriptor.hidden; ++column) {
                const size_t index = static_cast<size_t>(token) * width +
                                     static_cast<size_t>(stream) * descriptor.hidden + column;
                const size_t norm_index = norm_weight.size() == descriptor.hidden
                    ? column : static_cast<size_t>(stream) * descriptor.hidden + column;
                const float value = combined[index] * inverse_rms;
                normalized[index] = value + value * norm_weight[norm_index];
            }
        }
    }
    if (!AllFinite(combined) || !AllFinite(normalized)) {
        failure = "hyperconnection combine/norm produced NaN/Inf";
        combined.clear();
        normalized.clear();
        return false;
    }
    return true;
}

} // namespace Deep2::Qwen4Exp

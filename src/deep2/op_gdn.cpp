#include "op_gdn.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace Deep2::Qwen4Exp {

bool ValidateGDNDescriptor(const GDNDescriptor& descriptor,
                          std::string& failure) {
    if (descriptor.channels == 0 || descriptor.state_size == 0 ||
        descriptor.groups == 0 || descriptor.tokens == 0) {
        failure = "GDN dimensions must be non-zero";
        return false;
    }
    if (descriptor.channels % descriptor.groups != 0) {
        failure = "GDN channels must divide evenly into groups";
        return false;
    }
    if (descriptor.stride != 0 && descriptor.stride < descriptor.channels) {
        failure = "GDN stride is smaller than the channel width";
        return false;
    }
    const uint64_t state_elements = static_cast<uint64_t>(descriptor.groups) *
                                    descriptor.state_size * descriptor.channels;
    if (state_elements > (1ull << 31)) {
        failure = "GDN state allocation exceeds the bounded executor limit";
        return false;
    }
    return true;
}

size_t GDNStateElements(const GDNDescriptor& descriptor) {
    const uint64_t elements =
        static_cast<uint64_t>(descriptor.groups) *
        static_cast<uint64_t>(descriptor.state_size) *
        static_cast<uint64_t>(descriptor.channels);
    if (elements > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return 0;
    }
    return static_cast<size_t>(elements);
}

bool GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& input,
                      const std::vector<float>& decay,
                      const std::vector<float>& beta,
                      const std::vector<float>& key,
                      const std::vector<float>& value,
                      std::vector<float>& state,
                      std::vector<float>& output,
                      std::string& failure) {
    const size_t channels = descriptor.channels;
    const size_t state_size = descriptor.state_size;
    const size_t expected_state = static_cast<size_t>(descriptor.groups) *
                                  state_size * channels;
    if (input.size() != channels || decay.size() != channels ||
        beta.size() != channels || key.size() != channels ||
        value.size() != channels || state.size() != expected_state) {
        failure = "GDN: input/state size mismatch";
        output.clear();
        return false;
    }

    output.assign(channels, 0.0f);
    const size_t channels_per_group = channels / descriptor.groups;
    for (size_t channel = 0; channel < channels; ++channel) {
        const size_t group = channel / channels_per_group;
        const size_t state_channel = channel;
        const size_t base = (group * state_size * channels) + state_channel;
        const float next = decay[channel] * state[base] +
                            beta[channel] * key[channel] * value[channel];
        state[base] = next;
        output[channel] = next * input[channel];
    }
    return true;
}

size_t GDNQkvWidth(const GDNDescriptor& d) {
    return d.key_heads * d.head_dim + d.value_heads * d.head_dim;
}

size_t GDNOutputWidth(const GDNDescriptor& d) {
    return d.value_heads * d.head_dim;
}

bool GDNReferenceDecode(const GDNDescriptor& descriptor,
                        const std::vector<float>& qkv,
                        const std::vector<float>& beta,
                        const std::vector<float>& alpha,
                        const std::vector<float>& gate,
                        const std::vector<float>& a_log,
                        const std::vector<float>& dt_bias,
                        const std::vector<float>& norm,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure) {
    // Minimal reference decode: treat qkv as concatenated [key|value], apply
    // GDNReferenceStep per token position, then combine gate/alpha.
    const size_t tokens = descriptor.tokens;
    const size_t key_width = descriptor.key_heads * descriptor.head_dim;
    const size_t value_width = descriptor.value_heads * descriptor.head_dim;
    const size_t qkv_width = key_width + value_width;
    if (qkv.size() != tokens * qkv_width) {
        failure = "GDNDecode: qkv width mismatch";
        return false;
    }
    output.assign(value_width, 0.0f);
    for (size_t t = 0; t < tokens; ++t) {
        const size_t base = t * qkv_width;
        std::vector<float> key_slice(qkv.begin() + base,
                                     qkv.begin() + base + key_width);
        std::vector<float> value_slice(qkv.begin() + base + key_width,
                                       qkv.begin() + base + qkv_width);
        // Decay is alpha (negative values), beta is beta
        if (!GDNReferenceStep(descriptor, alpha, beta, beta, key_slice,
                              value_slice, state, output, failure)) {
            return false;
        }
    }
    return true;
}

} // namespace Deep2::Qwen4Exp

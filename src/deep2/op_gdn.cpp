#include "op_gdn.hpp"

#include <algorithm>
#include <cmath>

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

void GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& input,
                      const std::vector<float>& decay,
                      const std::vector<float>& beta,
                      const std::vector<float>& key,
                      const std::vector<float>& value,
                      std::vector<float>& state,
                      std::vector<float>& output) {
    const size_t channels = descriptor.channels;
    const size_t state_size = descriptor.state_size;
    const size_t expected_state = static_cast<size_t>(descriptor.groups) *
                                  state_size * channels;
    if (input.size() != channels || decay.size() != channels ||
        beta.size() != channels || key.size() != channels ||
        value.size() != channels || state.size() != expected_state) {
        output.clear();
        return;
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
}

} // namespace Deep2::Qwen4Exp

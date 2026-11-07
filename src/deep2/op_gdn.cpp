#include "op_gdn.hpp"

#include <algorithm>
#include <cmath>
#include <limits>

namespace {

float GdnSoftplus(float x) {
    if (x > 20.0f) return x;
    if (x < -20.0f) return std::exp(x);
    return std::log1p(std::exp(x));
}

float GdnSigmoid(float x) {
    if (x >= 0.0f) {
        const float e = std::exp(-x);
        return 1.0f / (1.0f + e);
    }
    const float e = std::exp(x);
    return e / (1.0f + e);
}

} // namespace

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
    // Qwen GDN projections are packed as [query | key | value]. The legacy
    // generic decode below has a separate [key | value] contract and must not
    // reuse this Qwen-specific width helper.
    return (static_cast<size_t>(2) * d.key_heads + d.value_heads) *
           d.head_dim;
}

size_t GDNOutputWidth(const GDNDescriptor& d) {
    return d.value_heads * d.head_dim;
}

size_t GDNQwenStateElements(const GDNDescriptor& d) {
    const uint64_t elements = static_cast<uint64_t>(d.value_heads) *
                              static_cast<uint64_t>(d.head_dim) *
                              static_cast<uint64_t>(d.head_dim);
    if (elements > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) return 0;
    return static_cast<size_t>(elements);
}

bool GDNQwenReferenceStep(const GDNDescriptor& descriptor,
                          const std::vector<float>& mixed_qkv,
                          const std::vector<float>& beta_logits,
                          const std::vector<float>& alpha_logits,
                          const std::vector<float>& a_log,
                          const std::vector<float>& dt_bias,
                          const std::vector<float>& norm,
                          const std::vector<float>& gate,
                          std::vector<float>& state,
                          std::vector<float>& output,
                          std::string& failure) {
    const size_t Hk = descriptor.key_heads;
    const size_t Hv = descriptor.value_heads;
    const size_t D = descriptor.head_dim;
    if (Hk == 0 || Hv == 0 || D == 0 || Hv % Hk != 0 ||
        !(descriptor.epsilon > 0.0f) || !std::isfinite(descriptor.epsilon) ||
        !(descriptor.scale > 0.0f) || !std::isfinite(descriptor.scale)) {
        failure = "GDN Qwen: invalid head geometry";
        output.clear();
        return false;
    }
    const size_t qkv_width = (2 * Hk + Hv) * D;
    const size_t value_width = Hv * D;
    const size_t expected_state = GDNQwenStateElements(descriptor);
    if (mixed_qkv.size() != qkv_width || beta_logits.size() != Hv ||
        alpha_logits.size() != Hv || a_log.size() != Hv || dt_bias.size() != Hv ||
        norm.size() != D || gate.size() != value_width || state.size() != expected_state) {
        failure = "GDN Qwen: operand/state size mismatch";
        output.clear();
        return false;
    }

    output.assign(value_width, 0.0f);
    // Keep the reference contract identical to the device shader: epsilon
    // controls Q/K normalization and scale is the model's Q projection
    // factor (Qwen uses 1/sqrt(head_dim)).
    const float scale = descriptor.scale;
    const float kNormEpsilon = descriptor.epsilon;
    const size_t HkPerHv = Hv / Hk;
    for (size_t hv = 0; hv < Hv; ++hv) {
        const size_t hk = hv / HkPerHv;
        const size_t q_base = hk * D;
        const size_t k_base = (Hk + hk) * D;
        const size_t v_base = (2 * Hk + hv) * D;
        const size_t state_base = hv * D * D;

        float q_sq = 0.0f;
        float k_sq = 0.0f;
        for (size_t d = 0; d < D; ++d) {
            q_sq += mixed_qkv[q_base + d] * mixed_qkv[q_base + d];
            k_sq += mixed_qkv[k_base + d] * mixed_qkv[k_base + d];
        }
        const float q_inv = 1.0f / std::sqrt(q_sq + kNormEpsilon);
        const float k_inv = 1.0f / std::sqrt(k_sq + kNormEpsilon);
        const float decay = -std::exp(a_log[hv]) * GdnSoftplus(alpha_logits[hv] + dt_bias[hv]);
        const float decay_factor = std::exp(decay);
        const float beta = GdnSigmoid(beta_logits[hv]);
        if (!std::isfinite(decay_factor) || !std::isfinite(beta)) {
            failure = "GDN Qwen: nonfinite decay or beta";
            output.clear();
            return false;
        }

        std::vector<float> next(D, 0.0f);
        float output_sq = 0.0f;
        for (size_t v = 0; v < D; ++v) {
            float dot_hk = 0.0f;
            for (size_t k = 0; k < D; ++k) {
                float& h = state[state_base + v * D + k];
                const float key = mixed_qkv[k_base + k] * k_inv;
                h *= decay_factor;
                dot_hk += h * key;
            }
            const float value = (mixed_qkv[v_base + v] - dot_hk) * beta;
            float o = 0.0f;
            for (size_t k = 0; k < D; ++k) {
                float& h = state[state_base + v * D + k];
                const float key = mixed_qkv[k_base + k] * k_inv;
                h += value * key;
                const float query = mixed_qkv[q_base + k] * q_inv;
                o += h * query * scale;
            }
            next[v] = o;
            output_sq += o * o;
        }
        const float rms = 1.0f / std::sqrt(output_sq / static_cast<float>(D) + descriptor.epsilon);
        if (!std::isfinite(rms)) {
            failure = "GDN Qwen: nonfinite output RMS";
            output.clear();
            return false;
        }
        for (size_t v = 0; v < D; ++v) {
            const size_t out_idx = hv * D + v;
            const float gate_value = descriptor.gate_sigmoid ? GdnSigmoid(gate[out_idx])
                                                              : gate[out_idx] * GdnSigmoid(gate[out_idx]);
            output[out_idx] = next[v] * rms * norm[v] * gate_value;
            if (!std::isfinite(output[out_idx])) {
                failure = "GDN Qwen: nonfinite output";
                output.clear();
                return false;
            }
        }
    }
    return true;
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

#include "op_gdn.hpp"

#include <algorithm>
#include <cmath>

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

float Softplus(float value) {
    return value > 20.0f ? value : std::log1p(std::exp(value));
}

} // namespace

uint32_t GDNQkvWidth(const GDNDescriptor& descriptor) {
    return (2u * descriptor.key_heads + descriptor.value_heads) * descriptor.head_dim;
}

uint32_t GDNOutputWidth(const GDNDescriptor& descriptor) {
    return descriptor.value_heads * descriptor.head_dim;
}

uint64_t GDNStateElements(const GDNDescriptor& descriptor) {
    return static_cast<uint64_t>(descriptor.value_heads) * descriptor.head_dim * descriptor.head_dim;
}

bool ValidateGDNDescriptor(const GDNDescriptor& descriptor,
                           std::string& failure) {
    if (descriptor.key_heads == 0 || descriptor.value_heads == 0 ||
        descriptor.head_dim == 0 || descriptor.conv_kernel == 0 || descriptor.tokens == 0) {
        failure = "GDN dimensions must be non-zero";
        return false;
    }
    if (descriptor.value_heads % descriptor.key_heads != 0) {
        failure = "GDN value heads must be divisible by key heads";
        return false;
    }
    if (descriptor.conv_kernel != 4) {
        failure = "Qwen4Exp GDN requires the model-declared causal kernel width 4";
        return false;
    }
    if (descriptor.qkv_stride != 0 && descriptor.qkv_stride < GDNQkvWidth(descriptor)) {
        failure = "GDN qkv stride is smaller than the mixed qkv width";
        return false;
    }
    if (descriptor.gate_stride != 0 && descriptor.gate_stride < GDNOutputWidth(descriptor)) {
        failure = "GDN gate stride is smaller than the z width";
        return false;
    }
    if (!(descriptor.epsilon > 0.0f) || !(descriptor.scale > 0.0f) ||
        !std::isfinite(descriptor.epsilon) || !std::isfinite(descriptor.scale)) {
        failure = "GDN normalization constants must be finite and positive";
        return false;
    }
    if (GDNStateElements(descriptor) > (1ull << 31)) {
        failure = "GDN recurrent state exceeds the bounded executor limit";
        return false;
    }
    return true;
}

bool GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& qkv,
                      const std::vector<float>& b,
                      const std::vector<float>& a,
                      const std::vector<float>& z,
                      const std::vector<float>& a_log,
                      const std::vector<float>& dt_bias,
                      const std::vector<float>& norm,
                      std::vector<float>& state,
                      std::vector<float>& output,
                      std::string& failure) {
    if (!ValidateGDNDescriptor(descriptor, failure)) return false;
    const size_t qkv_width = GDNQkvWidth(descriptor);
    const size_t output_width = GDNOutputWidth(descriptor);
    const size_t expected_state = static_cast<size_t>(GDNStateElements(descriptor));
    if (qkv.size() != qkv_width || b.size() != descriptor.value_heads ||
        a.size() != descriptor.value_heads || z.size() != output_width ||
        a_log.size() != descriptor.value_heads || dt_bias.size() != descriptor.value_heads ||
        norm.size() != descriptor.head_dim || state.size() != expected_state) {
        failure = "GDN input or state shape does not match the Qwen4Exp descriptor";
        output.clear();
        return false;
    }
    if (!AllFinite(qkv) || !AllFinite(b) || !AllFinite(a) || !AllFinite(z) ||
        !AllFinite(a_log) || !AllFinite(dt_bias) || !AllFinite(norm) || !AllFinite(state)) {
        failure = "GDN input or state contains NaN/Inf";
        output.clear();
        return false;
    }

    const size_t kd = descriptor.head_dim;
    const size_t k_offset = static_cast<size_t>(descriptor.key_heads) * kd;
    const size_t v_offset = 2u * static_cast<size_t>(descriptor.key_heads) * kd;
    const size_t heads_per_key = descriptor.value_heads / descriptor.key_heads;
    std::vector<float> q(kd), k(kd), o(kd);
    output.assign(output_width, 0.0f);

    for (uint32_t hv = 0; hv < descriptor.value_heads; ++hv) {
        const uint32_t hk = hv / static_cast<uint32_t>(heads_per_key);
        float q_norm = 0.0f;
        float k_norm = 0.0f;
        for (size_t i = 0; i < kd; ++i) {
            q[i] = qkv[static_cast<size_t>(hk) * kd + i];
            k[i] = qkv[k_offset + static_cast<size_t>(hk) * kd + i];
            q_norm += q[i] * q[i];
            k_norm += k[i] * k[i];
        }
        const float q_scale = descriptor.scale / std::sqrt(q_norm + descriptor.epsilon);
        const float k_scale = 1.0f / std::sqrt(k_norm + descriptor.epsilon);
        for (size_t i = 0; i < kd; ++i) {
            q[i] *= q_scale;
            k[i] *= k_scale;
        }

        const float decay = std::exp(-std::exp(a_log[hv]) * Softplus(a[hv] + dt_bias[hv]));
        const float beta = Sigmoid(b[hv]);
        const size_t state_head = static_cast<size_t>(hv) * kd * kd;
        const size_t value_offset = v_offset + static_cast<size_t>(hv) * kd;
        float sum_squares = 0.0f;
        for (size_t row = 0; row < kd; ++row) {
            float dot = 0.0f;
            const size_t state_row = state_head + row * kd;
            for (size_t col = 0; col < kd; ++col) {
                float& h = state[state_row + col];
                h *= decay;
                dot += h * k[col];
            }
            const float value = (qkv[value_offset + row] - dot) * beta;
            float projected = 0.0f;
            for (size_t col = 0; col < kd; ++col) {
                float& h = state[state_row + col];
                h += value * k[col];
                projected += h * q[col];
            }
            o[row] = projected;
            sum_squares += projected * projected;
        }
        const float inv_rms = 1.0f / std::sqrt(sum_squares / static_cast<float>(kd) + descriptor.epsilon);
        for (size_t row = 0; row < kd; ++row) {
            const float gate_input = z[static_cast<size_t>(hv) * kd + row];
            const float gate = descriptor.gate_sigmoid ? Sigmoid(gate_input) : gate_input * Sigmoid(gate_input);
            output[static_cast<size_t>(hv) * kd + row] = o[row] * inv_rms * norm[row] * gate;
        }
    }
    if (!AllFinite(output) || !AllFinite(state)) {
        failure = "GDN recurrence produced NaN/Inf";
        output.clear();
        return false;
    }
    return true;
}

bool GDNReferenceDecode(const GDNDescriptor& descriptor,
                        const std::vector<float>& qkv,
                        const std::vector<float>& b,
                        const std::vector<float>& a,
                        const std::vector<float>& z,
                        const std::vector<float>& a_log,
                        const std::vector<float>& dt_bias,
                        const std::vector<float>& norm,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure) {
    if (!ValidateGDNDescriptor(descriptor, failure)) return false;
    const size_t qkv_width = GDNQkvWidth(descriptor);
    const size_t output_width = GDNOutputWidth(descriptor);
    const size_t scalar_heads = descriptor.value_heads;
    if (qkv.size() != static_cast<size_t>(descriptor.tokens) * qkv_width ||
        b.size() != static_cast<size_t>(descriptor.tokens) * scalar_heads ||
        a.size() != static_cast<size_t>(descriptor.tokens) * scalar_heads ||
        z.size() != static_cast<size_t>(descriptor.tokens) * output_width) {
        failure = "GDN decode buffers do not contain the declared token count";
        return false;
    }
    output.assign(static_cast<size_t>(descriptor.tokens) * output_width, 0.0f);
    std::vector<float> token_qkv(qkv_width), token_b(scalar_heads), token_a(scalar_heads), token_z(output_width), token_out;
    for (uint32_t token = 0; token < descriptor.tokens; ++token) {
        std::copy_n(qkv.data() + static_cast<size_t>(token) * qkv_width, qkv_width, token_qkv.data());
        std::copy_n(b.data() + static_cast<size_t>(token) * scalar_heads, scalar_heads, token_b.data());
        std::copy_n(a.data() + static_cast<size_t>(token) * scalar_heads, scalar_heads, token_a.data());
        std::copy_n(z.data() + static_cast<size_t>(token) * output_width, output_width, token_z.data());
        if (!GDNReferenceStep(descriptor, token_qkv, token_b, token_a, token_z,
                              a_log, dt_bias, norm, state, token_out, failure)) return false;
        std::copy(token_out.begin(), token_out.end(), output.begin() + static_cast<size_t>(token) * output_width);
    }
    return true;
}

} // namespace Deep2::Qwen4Exp

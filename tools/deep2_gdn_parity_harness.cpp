#include "../src/deep2/op_gdn.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool CloseVectors(const std::vector<float>& lhs,
                 const std::vector<float>& rhs,
                 float tolerance,
                 float& max_diff) {
    if (lhs.size() != rhs.size()) return false;
    max_diff = 0.0f;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (!std::isfinite(lhs[i]) || !std::isfinite(rhs[i])) return false;
        max_diff = std::max(max_diff, std::fabs(lhs[i] - rhs[i]));
    }
    return max_diff <= tolerance;
}

} // namespace

int main() {
    using namespace Deep2::Qwen4Exp;

    constexpr uint32_t tokens = 3;
    GDNDescriptor descriptor{};
    descriptor.key_heads = 16;
    descriptor.value_heads = 48;
    descriptor.head_dim = 128;
    descriptor.conv_kernel = 4;
    descriptor.tokens = tokens;
    descriptor.qkv_stride = GDNQkvWidth(descriptor);
    descriptor.gate_stride = GDNOutputWidth(descriptor);
    descriptor.epsilon = 1.0e-6f;
    descriptor.scale = 1.0f / std::sqrt(128.0f);
    descriptor.gate_sigmoid = true;

    std::string failure;
    if (!ValidateGDNDescriptor(descriptor, failure)) {
        std::printf("GDN_GEOMETRY=FAIL reason=%s\n", failure.c_str());
        return 1;
    }

    const size_t qkv_width = GDNQkvWidth(descriptor);
    const size_t output_width = GDNOutputWidth(descriptor);
    const size_t scalar_width = descriptor.value_heads;
    const size_t state_width = static_cast<size_t>(GDNStateElements(descriptor));
    std::vector<float> qkv(static_cast<size_t>(tokens) * qkv_width);
    std::vector<float> beta(static_cast<size_t>(tokens) * scalar_width);
    std::vector<float> alpha(static_cast<size_t>(tokens) * scalar_width);
    std::vector<float> gate(static_cast<size_t>(tokens) * output_width);
    std::vector<float> a_log(scalar_width), dt_bias(scalar_width), norm(descriptor.head_dim, 1.0f);

    for (size_t i = 0; i < qkv.size(); ++i)
        qkv[i] = 0.005f * std::sin(static_cast<float>(i % 97));
    for (size_t i = 0; i < beta.size(); ++i) {
        beta[i] = -0.3f + 0.01f * static_cast<float>(i % 23);
        alpha[i] = -0.2f + 0.008f * static_cast<float>(i % 19);
    }
    for (size_t i = 0; i < gate.size(); ++i)
        gate[i] = -0.1f + 0.004f * static_cast<float>(i % 31);
    for (size_t i = 0; i < scalar_width; ++i) {
        a_log[i] = -1.0f + 0.002f * static_cast<float>(i % 17);
        dt_bias[i] = -0.4f + 0.003f * static_cast<float>(i % 13);
    }
    for (size_t i = 0; i < norm.size(); ++i)
        norm[i] = 0.9f + 0.001f * static_cast<float>(i % 29);

    const std::vector<float> initial_state(state_width, 0.0f);
    std::vector<float> full_state = initial_state;
    std::vector<float> full_output;
    if (!GDNReferenceDecode(descriptor, qkv, beta, alpha, gate, a_log, dt_bias,
                             norm, full_state, full_output, failure)) {
        std::printf("GDN_REFERENCE=FAIL reason=%s\n", failure.c_str());
        return 2;
    }

    GDNDescriptor first_descriptor = descriptor;
    first_descriptor.tokens = 1;
    GDNDescriptor tail_descriptor = descriptor;
    tail_descriptor.tokens = tokens - 1;
    std::vector<float> split_state = initial_state;
    std::vector<float> split_first;
    std::vector<float> split_tail;
    const std::vector<float> first_qkv(qkv.begin(), qkv.begin() + qkv_width);
    const std::vector<float> first_beta(beta.begin(), beta.begin() + scalar_width);
    const std::vector<float> first_alpha(alpha.begin(), alpha.begin() + scalar_width);
    const std::vector<float> first_gate(gate.begin(), gate.begin() + output_width);
    if (!GDNReferenceDecode(first_descriptor, first_qkv, first_beta, first_alpha,
                            first_gate, a_log, dt_bias, norm, split_state,
                            split_first, failure)) {
        std::printf("GDN_SPLIT_FIRST=FAIL reason=%s\n", failure.c_str());
        return 3;
    }
    const std::vector<float> tail_qkv(qkv.begin() + qkv_width, qkv.end());
    const std::vector<float> tail_beta(beta.begin() + scalar_width, beta.end());
    const std::vector<float> tail_alpha(alpha.begin() + scalar_width, alpha.end());
    const std::vector<float> tail_gate(gate.begin() + output_width, gate.end());
    if (!GDNReferenceDecode(tail_descriptor, tail_qkv, tail_beta, tail_alpha,
                            tail_gate, a_log, dt_bias, norm, split_state,
                            split_tail, failure)) {
        std::printf("GDN_SPLIT_TAIL=FAIL reason=%s\n", failure.c_str());
        return 4;
    }

    std::vector<float> split_output;
    split_output.reserve(full_output.size());
    split_output.insert(split_output.end(), split_first.begin(), split_first.end());
    split_output.insert(split_output.end(), split_tail.begin(), split_tail.end());
    float output_diff = 0.0f;
    float state_diff = 0.0f;
    const bool output_ok = CloseVectors(full_output, split_output, 1.0e-6f, output_diff);
    const bool state_ok = CloseVectors(full_state, split_state, 1.0e-6f, state_diff);
    const bool finite = output_ok && state_ok;

    std::printf("GDN_GEOMETRY=PASS key_heads=%u value_heads=%u head_dim=%u conv_kernel=%u\n",
                descriptor.key_heads, descriptor.value_heads, descriptor.head_dim,
                descriptor.conv_kernel);
    std::printf("GDN_QKV_WIDTH=%zu GDN_OUTPUT_WIDTH=%zu GDN_STATE_ELEMENTS=%zu\n",
                qkv_width, output_width, state_width);
    std::printf("GDN_REFERENCE_FINITE=%s\n", finite ? "PASS" : "FAIL");
    std::printf("GDN_STATE_CONTINUITY=%s max_output_diff=%.9g max_state_diff=%.9g\n",
                (output_ok && state_ok) ? "PASS" : "FAIL", output_diff, state_diff);
    std::printf("GDN_INDEPENDENT_PARITY=NOT_RUN GDN_GPU_DISPATCHES=0\n");
    std::printf("GDN_CERTIFICATION=NOT_CERTIFIED\n");
    return finite ? 0 : 5;
}

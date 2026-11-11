#include "op_sparse_moe.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

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

bool IsF32Like(SparseMoEWeightFormat format) {
    return format == SparseMoEWeightFormat::F32 || format == SparseMoEWeightFormat::BF16;
}

} // namespace

bool ValidateSparseMoEDescriptor(const SparseMoEDescriptor& descriptor,
                                 std::string& failure) {
    if (descriptor.hidden == 0 || descriptor.intermediate == 0 || descriptor.experts == 0 ||
        descriptor.top_k == 0 || descriptor.top_k > descriptor.experts) {
        failure = "sparse MoE dimensions are invalid";
        return false;
    }
    if (descriptor.experts != 512 || descriptor.intermediate != 640 || descriptor.top_k != 10) {
        failure = "Qwen4Exp sparse MoE requires 512 experts, intermediate=640, top_k=10";
        return false;
    }
    return true;
}

bool SparseMoERouteReference(const SparseMoEDescriptor& descriptor,
                             const std::vector<float>& hidden,
                             const std::vector<float>& router_weight,
                             std::vector<uint32_t>& expert_ids,
                             std::vector<float>& expert_weights,
                             std::string& failure) {
    if (!ValidateSparseMoEDescriptor(descriptor, failure)) return false;
    if (hidden.size() != descriptor.hidden ||
        router_weight.size() != static_cast<size_t>(descriptor.hidden) * descriptor.experts ||
        !AllFinite(hidden) || !AllFinite(router_weight)) {
        failure = "sparse MoE router shape or finiteness check failed";
        expert_ids.clear();
        expert_weights.clear();
        return false;
    }
    std::vector<std::pair<float, uint32_t>> logits;
    logits.reserve(descriptor.experts);
    for (uint32_t expert = 0; expert < descriptor.experts; ++expert) {
        double value = 0.0;
        for (uint32_t i = 0; i < descriptor.hidden; ++i)
            value += static_cast<double>(hidden[i]) * router_weight[static_cast<size_t>(i) * descriptor.experts + expert];
        logits.emplace_back(static_cast<float>(value), expert);
    }
    std::stable_sort(logits.begin(), logits.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.first != rhs.first) return lhs.first > rhs.first;
        return lhs.second < rhs.second;
    });
    expert_ids.resize(descriptor.top_k);
    expert_weights.resize(descriptor.top_k);
    const float max_logit = logits.front().first;
    float denominator = 0.0f;
    for (uint32_t i = 0; i < descriptor.top_k; ++i) {
        expert_ids[i] = logits[i].second;
        expert_weights[i] = std::exp(logits[i].first - max_logit);
        denominator += expert_weights[i];
    }
    for (float& weight : expert_weights) weight /= denominator;
    return true;
}

bool SparseMoEFloatReference(const SparseMoEDescriptor& descriptor,
                             const std::vector<float>& hidden,
                             const std::vector<float>& router_weight,
                             const std::vector<float>& gate_weight,
                             const std::vector<float>& up_weight,
                             const std::vector<float>& down_weight,
                             std::vector<float>& output,
                             std::string& failure) {
    if (!ValidateSparseMoEDescriptor(descriptor, failure)) return false;
    if (!IsF32Like(descriptor.gate_format) || !IsF32Like(descriptor.up_format) ||
        !IsF32Like(descriptor.down_format)) {
        failure = "production sparse MoE execution requires certified dequantized F32/BF16 expert weights";
        output.clear();
        return false;
    }
    const size_t expert_in = static_cast<size_t>(descriptor.experts) * descriptor.intermediate * descriptor.hidden;
    const size_t expert_down = static_cast<size_t>(descriptor.experts) * descriptor.hidden * descriptor.intermediate;
    if (hidden.size() != descriptor.hidden ||
        router_weight.size() != static_cast<size_t>(descriptor.hidden) * descriptor.experts ||
        gate_weight.size() != expert_in || up_weight.size() != expert_in || down_weight.size() != expert_down ||
        !AllFinite(hidden) || !AllFinite(router_weight) || !AllFinite(gate_weight) ||
        !AllFinite(up_weight) || !AllFinite(down_weight)) {
        failure = "sparse MoE expert tensor shape or finiteness check failed";
        output.clear();
        return false;
    }

    std::vector<uint32_t> expert_ids;
    std::vector<float> expert_weights;
    if (!SparseMoERouteReference(descriptor, hidden, router_weight, expert_ids,
                                 expert_weights, failure)) return false;
    output.assign(descriptor.hidden, 0.0f);
    std::vector<float> intermediate(descriptor.intermediate, 0.0f);
    for (uint32_t selected = 0; selected < descriptor.top_k; ++selected) {
        const uint32_t expert = expert_ids[selected];
        const size_t base = static_cast<size_t>(expert) * descriptor.intermediate * descriptor.hidden;
        for (uint32_t row = 0; row < descriptor.intermediate; ++row) {
            double gate = 0.0;
            double up = 0.0;
            const size_t row_base = base + static_cast<size_t>(row) * descriptor.hidden;
            for (uint32_t i = 0; i < descriptor.hidden; ++i) {
                gate += static_cast<double>(hidden[i]) * gate_weight[row_base + i];
                up += static_cast<double>(hidden[i]) * up_weight[row_base + i];
            }
            intermediate[row] = Silu(static_cast<float>(gate)) * static_cast<float>(up);
        }
        const size_t down_base = static_cast<size_t>(expert) * descriptor.hidden * descriptor.intermediate;
        for (uint32_t column = 0; column < descriptor.hidden; ++column) {
            double value = 0.0;
            const size_t column_base = down_base + static_cast<size_t>(column) * descriptor.intermediate;
            for (uint32_t row = 0; row < descriptor.intermediate; ++row)
                value += static_cast<double>(intermediate[row]) * down_weight[column_base + row];
            output[column] += expert_weights[selected] * static_cast<float>(value);
        }
    }
    if (!AllFinite(output)) {
        failure = "sparse MoE reference produced NaN/Inf";
        output.clear();
        return false;
    }
    return true;
}

} // namespace Deep2::Qwen4Exp

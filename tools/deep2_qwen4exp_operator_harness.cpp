#include "../src/deep2/op_hyperconnection.hpp"
#include "../src/deep2/op_ple.hpp"
#include "../src/deep2/op_qsa.hpp"
#include "../src/deep2/op_sparse_moe.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool Finite(const std::vector<float>& values) {
    for (float value : values) if (!std::isfinite(value)) return false;
    return true;
}

bool Same(const std::vector<float>& lhs, const std::vector<float>& rhs, float tolerance = 1.0e-6f) {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i)
        if (!std::isfinite(lhs[i]) || !std::isfinite(rhs[i]) || std::fabs(lhs[i] - rhs[i]) > tolerance) return false;
    return true;
}

} // namespace

int main() {
    using namespace Deep2::Qwen4Exp;
    bool ok = true;
    std::string failure;

    PLEDescriptor ple{5, 8, 4, 3};
    std::vector<float> ple_input(ple.tokens * ple.channels), ple_weights(ple.kernel * ple.channels);
    for (size_t i = 0; i < ple_input.size(); ++i) ple_input[i] = 0.01f * static_cast<float>(i % 17);
    for (size_t i = 0; i < ple_weights.size(); ++i) ple_weights[i] = 0.02f * static_cast<float>((i % 9) + 1);
    std::vector<float> ple_state(PLEStateElements(ple), 0.03f), ple_full_output;
    auto ple_split_state = ple_state;
    if (!PLEReferenceDecode(ple, ple_input, ple_weights, ple_state, ple_full_output, failure)) ok = false;
    PLEDescriptor ple_first = ple; ple_first.tokens = 2;
    PLEDescriptor ple_tail = ple; ple_tail.tokens = 3;
    std::vector<float> ple_first_output, ple_tail_output;
    const std::vector<float> ple_first_input(ple_input.begin(), ple_input.begin() + 2 * ple.channels);
    const std::vector<float> ple_tail_input(ple_input.begin() + 2 * ple.channels, ple_input.end());
    if (!PLEReferenceDecode(ple_first, ple_first_input, ple_weights, ple_split_state, ple_first_output, failure) ||
        !PLEReferenceDecode(ple_tail, ple_tail_input, ple_weights, ple_split_state, ple_tail_output, failure)) ok = false;
    ple_first_output.insert(ple_first_output.end(), ple_tail_output.begin(), ple_tail_output.end());
    const bool ple_ok = ok && Same(ple_full_output, ple_first_output) && Same(ple_state, ple_split_state);
    std::printf("PLE_GEOMETRY=%s state_length=%u state_elements=%llu\n",
                ple_ok ? "PASS" : "FAIL", PLEStateLength(ple),
                static_cast<unsigned long long>(PLEStateElements(ple)));

    HyperconnectionDescriptor hc{2, 8, 4, 1.0e-5f, false};
    std::vector<float> hc_stream(hc.tokens * HyperconnectionWidth(hc));
    std::vector<float> hc_gate(hc_stream.size()), hc_block(hc.tokens * hc.hidden), hc_injection(hc.tokens * hc.streams);
    std::vector<float> hc_norm(hc.hidden, 1.0f), hc_mix, hc_combined, hc_normalized;
    for (size_t i = 0; i < hc_stream.size(); ++i) {
        hc_stream[i] = 0.01f * static_cast<float>(i % 23);
        hc_gate[i] = -0.2f + 0.01f * static_cast<float>(i % 11);
    }
    for (size_t i = 0; i < hc_block.size(); ++i) hc_block[i] = 0.02f * static_cast<float>(i % 13);
    for (size_t i = 0; i < hc_injection.size(); ++i) hc_injection[i] = 0.1f * static_cast<float>(i % 7);
    const bool hc_mix_ok = HyperconnectionGateMix(hc, hc_stream, hc_gate, hc_mix, failure);
    const bool hc_combine_ok = HyperconnectionCombineNorm(hc, hc_stream, hc_block, hc_injection,
                                                            hc_norm, hc_combined, hc_normalized, failure);
    const bool hc_ok = hc_mix_ok && hc_combine_ok && Finite(hc_mix) && Finite(hc_normalized);
    std::printf("HC_GEOMETRY=%s width=%llu gate_mix=%s combine_norm=%s\n",
                hc_ok ? "PASS" : "FAIL", static_cast<unsigned long long>(HyperconnectionWidth(hc)),
                hc_mix_ok ? "PASS" : "FAIL", hc_combine_ok ? "PASS" : "FAIL");

    QSADescriptor qsa{};
    constexpr uint32_t qsa_rows = 2;
    constexpr uint32_t qsa_pages = 8;
    constexpr uint32_t qsa_max_pages = 4;
    std::vector<float> qsa_query(qsa_rows * qsa.index_heads * qsa.key_dim);
    std::vector<float> qsa_keys(qsa_pages * qsa.page_size * qsa.key_dim);
    std::vector<int32_t> qsa_table(2 * qsa_max_pages, -1);
    std::vector<int32_t> qsa_request{0, 1}, qsa_position{15, 7}, qsa_lengths{16, 8};
    for (size_t i = 0; i < qsa_query.size(); ++i) qsa_query[i] = 0.001f * static_cast<float>(i % 31);
    for (size_t i = 0; i < qsa_keys.size(); ++i) qsa_keys[i] = 0.002f * static_cast<float>(i % 29);
    qsa_table = {0, 1, 2, 3, 4, 5, -1, -1};
    std::vector<float> qsa_logits;
    std::vector<uint32_t> qsa_visible;
    const bool qsa_score_ok = QSAScoreReference(qsa, qsa_query, qsa_rows, qsa_keys, qsa_pages,
                                                 qsa_table, qsa_max_pages, qsa_request, qsa_position,
                                                 qsa_lengths, qsa_logits, qsa_visible, failure);
    std::vector<int32_t> qsa_selected;
    const bool qsa_select_ok = qsa_score_ok && QSASelectReference(qsa, qsa_logits, qsa_visible,
                                                                   qsa_position, qsa_selected, failure);
    bool qsa_finite = qsa_score_ok;
    const size_t qsa_columns = qsa_logits.size() / qsa_rows;
    for (uint32_t row = 0; row < qsa_rows && qsa_finite; ++row)
        for (uint32_t column = 0; column < qsa_visible[row]; ++column)
            qsa_finite = std::isfinite(qsa_logits[static_cast<size_t>(row) * qsa_columns + column]);
    const bool qsa_ok = qsa_select_ok && qsa_finite && qsa_visible[0] == 4 && qsa_visible[1] == 2;
    std::printf("QSA_GEOMETRY=%s heads=%u key_dim=%u compression=%u top_k=%u visible=%u/%u selection=%s\n",
                qsa_ok ? "PASS" : "FAIL", qsa.index_heads, qsa.key_dim, qsa.compress_ratio,
                qsa.top_k, qsa_visible.empty() ? 0 : qsa_visible[0], qsa_visible.size() < 2 ? 0 : qsa_visible[1],
                qsa_select_ok ? "PASS" : "FAIL");

    SparseMoEDescriptor moe{};
    std::vector<float> moe_hidden(moe.hidden), moe_router(static_cast<size_t>(moe.hidden) * moe.experts, 0.0f);
    for (size_t i = 0; i < moe_hidden.size(); ++i) moe_hidden[i] = 0.01f * static_cast<float>((i % 19) + 1);
    for (uint32_t expert = 0; expert < moe.experts; ++expert)
        for (uint32_t i = 0; i < moe.hidden; ++i)
            moe_router[static_cast<size_t>(i) * moe.experts + expert] =
                0.0001f * static_cast<float>((expert + 1) * ((i % 7) + 1));
    std::vector<uint32_t> moe_ids;
    std::vector<float> moe_weights;
    const bool route_ok = SparseMoERouteReference(moe, moe_hidden, moe_router, moe_ids, moe_weights, failure);
    float weight_sum = 0.0f;
    for (float weight : moe_weights) weight_sum += weight;
    std::vector<float> unused_output;
    const bool rejection_ok = !SparseMoEFloatReference(moe, moe_hidden, moe_router, {}, {}, {}, unused_output, failure);
    const bool moe_ok = route_ok && rejection_ok && moe_ids.size() == moe.top_k &&
                        moe_weights.size() == moe.top_k && std::fabs(weight_sum - 1.0f) < 1.0e-5f;
    std::printf("SPARSE_MOE_ROUTE=%s experts=%u top_k=%u normalized=%s\n",
                moe_ok ? "PASS" : "FAIL", moe.experts, moe.top_k,
                std::fabs(weight_sum - 1.0f) < 1.0e-5f ? "PASS" : "FAIL");
    std::printf("SPARSE_MOE_EXPERT_EXECUTION=%s\n",
                rejection_ok ? "FAIL_CLOSED_UNDEQUANTIZED" : "UNEXPECTED_ACCEPT");

    std::printf("QWEN4EXP_OPERATOR_HARNESS=%s\n", ple_ok && hc_ok && qsa_ok && moe_ok ? "PASS" : "FAIL");
    std::printf("QWEN4EXP_FULL_MODEL=NOT_CERTIFIED\n");
    return ple_ok && hc_ok && qsa_ok && moe_ok ? 0 : 1;
}

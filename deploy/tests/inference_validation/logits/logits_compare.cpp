#include "logits_compare.hpp"
#include <cstdio>
#include <algorithm>
#include <cmath>

namespace rawrxd {
namespace validation {

LogitsComparator::LogitsComparator(float tolerance)
    : tolerance_(tolerance) {}

bool LogitsComparator::compare(
    const std::vector<float>& rawrxd_logits,
    const std::vector<float>& reference_logits,
    size_t vocab_size)
{
    if (rawrxd_logits.size() != reference_logits.size()) {
        printf("ERROR: Logit size mismatch: %zu vs %zu\n",
               rawrxd_logits.size(), reference_logits.size());
        return false;
    }
    
    if (rawrxd_logits.size() != vocab_size) {
        printf("ERROR: Logit size %zu doesn't match vocab_size %zu\n",
               rawrxd_logits.size(), vocab_size);
        return false;
    }
    
    last_result_ = compareTensor(
        reference_logits.data(),
        rawrxd_logits.data(),
        vocab_size,
        tolerance_
    );
    
    printf(
        "Logit Validation\n"
        "  Max error:    %.9f\n"
        "  Mean error:   %.9f\n"
        "  Mismatches:   %zu / %zu\n"
        "  Result:       %s\n",
        last_result_.max_error,
        last_result_.mean_error,
        last_result_.mismatch_count,
        vocab_size,
        last_result_.passed ? "PASS" : "FAIL"
    );
    
    return last_result_.passed;
}

bool LogitsComparator::compareTopK(
    const std::vector<float>& rawrxd_logits,
    const std::vector<float>& reference_logits,
    size_t vocab_size,
    int k)
{
    // Find top-k tokens for both
    std::vector<std::pair<float, int>> rawrxd_sorted;
    std::vector<std::pair<float, int>> ref_sorted;
    
    for (size_t i = 0; i < vocab_size; i++) {
        rawrxd_sorted.push_back({rawrxd_logits[i], (int)i});
        ref_sorted.push_back({reference_logits[i], (int)i});
    }
    
    // Sort by logit value descending
    std::sort(rawrxd_sorted.begin(), rawrxd_sorted.end(),
              [](auto& a, auto& b) { return a.first > b.first; });
    std::sort(ref_sorted.begin(), ref_sorted.end(),
              [](auto& a, auto& b) { return a.first > b.first; });
    
    // Compare top-k
    bool match = true;
    printf("Top-%d Token Comparison:\n", k);
    
    for (int i = 0; i < k && i < (int)vocab_size; i++) {
        int rawrxd_token = rawrxd_sorted[i].second;
        int ref_token = ref_sorted[i].second;
        
        bool token_match = (rawrxd_token == ref_token);
        if (!token_match) match = false;
        
        printf("  #%2d: RawrXD=%5d (%.4f)  Ref=%5d (%.4f)  %s\n",
               i + 1,
               rawrxd_token, rawrxd_sorted[i].first,
               ref_token, ref_sorted[i].first,
               token_match ? "✓" : "✗");
    }
    
    return match;
}

void LogitsComparator::printReport() const {
    printf("\n=== Logits Comparison Report ===\n");
    printf("Tolerance: %.9f\n", tolerance_);
    printf("Result: %s\n", last_result_.toString().c_str());
    printf("================================\n\n");
}

bool validateLogits(
    const float* rawrxd,
    const float* reference,
    size_t vocab_size,
    float tolerance)
{
    LogitsComparator comp(tolerance);
    std::vector<float> rawrxd_vec(rawrxd, rawrxd + vocab_size);
    std::vector<float> ref_vec(reference, reference + vocab_size);
    return comp.compare(rawrxd_vec, ref_vec, vocab_size);
}

} // namespace validation
} // namespace rawrxd

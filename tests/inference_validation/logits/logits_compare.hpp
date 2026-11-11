#pragma once

#include "../harness/tensor_compare.hpp"
#include <vector>
#include <string>

namespace rawrxd {
namespace validation {

/**
 * Compare logits between RawrXD and reference implementation
 */
class LogitsComparator {
public:
    LogitsComparator(float tolerance = 1e-5f);
    
    /**
     * Compare logits from two implementations
     * @param rawrxd_logits Logits from RawrXD
     * @param reference_logits Logits from reference (llama.cpp)
     * @param vocab_size Size of vocabulary
     * @return true if logits match within tolerance
     */
    bool compare(
        const std::vector<float>& rawrxd_logits,
        const std::vector<float>& reference_logits,
        size_t vocab_size
    );
    
    /**
     * Compare top-k tokens
     * @param k Number of top tokens to compare
     * @return true if top-k tokens match
     */
    bool compareTopK(
        const std::vector<float>& rawrxd_logits,
        const std::vector<float>& reference_logits,
        size_t vocab_size,
        int k = 10
    );
    
    /**
     * Get last comparison results
     */
    const TensorComparison& getLastResult() const { return last_result_; }
    
    /**
     * Print detailed comparison report
     */
    void printReport() const;

private:
    float tolerance_;
    TensorComparison last_result_;
};

/**
 * Convenience function for single comparison
 */
bool validateLogits(
    const float* rawrxd,
    const float* reference,
    size_t vocab_size,
    float tolerance = 1e-5f
);

} // namespace validation
} // namespace rawrxd

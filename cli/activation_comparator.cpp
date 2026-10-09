// ============================================================================
// ActivationComparator Implementation
// ============================================================================

#include "activation_comparator.hpp"
#include <numeric>
#include <cmath>
#include <iostream>

namespace RawrXD {
namespace CLI {

float ActivationComparator::ComputeCosineSimilarity(const float* a, const float* b, size_t n) {
    if (!a || !b || n == 0) return 0.0f;
    
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < n; ++i) {
        dot += static_cast<double>(a[i]) * static_cast<double>(b[i]);
        norm_a += static_cast<double>(a[i]) * static_cast<double>(a[i]);
        norm_b += static_cast<double>(b[i]) * static_cast<double>(b[i]);
    }
    
    if (norm_a == 0.0 || norm_b == 0.0) return 0.0f;
    
    return static_cast<float>(dot / (std::sqrt(norm_a) * std::sqrt(norm_b)));
}

float ActivationComparator::ComputeRMSE(const float* a, const float* b, size_t n) {
    if (!a || !b || n == 0) return 0.0f;
    
    double sum_sq = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double diff = static_cast<double>(a[i]) - static_cast<double>(b[i]);
        sum_sq += diff * diff;
    }
    
    return static_cast<float>(std::sqrt(sum_sq / n));
}

void ActivationComparator::FindMaxAbsDiff(const float* a, const float* b, size_t n, 
                                          float& max_diff, size_t& max_idx) {
    max_diff = 0.0f;
    max_idx = 0;
    
    if (!a || !b || n == 0) return;
    
    for (size_t i = 0; i < n; ++i) {
        float diff = std::abs(a[i] - b[i]);
        if (diff > max_diff) {
            max_diff = diff;
            max_idx = i;
        }
    }
}

ActivationComparison ActivationComparator::Compare(const std::string& op_name, uint32_t op_index,
                                                   const float* native_data, size_t native_count,
                                                   const float* reference_data, size_t reference_count,
                                                   const std::vector<uint64_t>& native_shape,
                                                   const std::vector<uint64_t>& reference_shape) {
    ActivationComparison comp;
    comp.op_name = op_name;
    comp.op_index = op_index;
    comp.shape_native = native_shape;
    comp.shape_reference = reference_shape;
    comp.element_count_native = native_count;
    comp.element_count_reference = reference_count;
    comp.atol = m_config.atol;
    comp.rtol = m_config.rtol;
    
    // Check shapes match
    if (native_shape == reference_shape) {
        comp.shapes_match = true;
    } else if (native_count == reference_count) {
        comp.shapes_match = true;  // Same element count, treat as match
    } else {
        comp.shapes_match = false;
        comp.count = 0;
        comp.CheckPass();
        return comp;
    }
    
    // Compare elements
    size_t n = std::min(native_count, reference_count);
    comp.count = n;
    
    if (n == 0) {
        comp.CheckPass();
        return comp;
    }
    
    // Compute metrics
    FindMaxAbsDiff(native_data, reference_data, n, comp.max_abs_diff, comp.max_diff_index);
    comp.rmse = ComputeRMSE(native_data, reference_data, n);
    comp.cosine_similarity = ComputeCosineSimilarity(native_data, reference_data, n);
    
    // Store differences if requested
    if (m_config.store_differences) {
        comp.abs_differences.resize(n);
        for (size_t i = 0; i < n; ++i) {
            comp.abs_differences[i] = std::abs(native_data[i] - reference_data[i]);
        }
    }
    
    // Check pass/fail
    comp.CheckPass();
    
    if (m_config.verbose) {
        comp.PrintSummary();
    }
    
    return comp;
}

ModelComparisonResult ActivationComparator::CompareModels(
    const std::vector<std::pair<uint32_t, const float*>>& native_activations,
    const std::vector<ReferenceActivation>& reference_activations,
    const std::vector<float>& native_logits,
    const std::vector<float>& reference_logits,
    uint32_t native_token,
    uint32_t reference_token) {
    
    ModelComparisonResult result;
    result.native_token = native_token;
    result.reference_token = reference_token;
    result.token_parity = (native_token == reference_token);
    result.total_ops = static_cast<uint32_t>(reference_activations.size());
    
    // Build lookup map for reference activations by op_index
    std::unordered_map<uint32_t, const ReferenceActivation*> ref_map;
    for (const auto& act : reference_activations) {
        ref_map[act.op_index] = &act;
    }
    
    // Compare each native activation with reference
    for (const auto& [op_idx, native_ptr] : native_activations) {
        auto it = ref_map.find(op_idx);
        if (it == ref_map.end()) {
            ActivationComparison comp;
            comp.op_index = op_idx;
            comp.op_name = "unknown";
            comp.passed = false;
            comp.failure_reason = "No reference activation found";
            result.comparisons.push_back(comp);
            result.failed_ops++;
            result.skipped_ops++;
            continue;
        }
        
        const ReferenceActivation& ref_act = *it->second;
        
        // Get native activation size (we need to know this - assume from ref for now)
        size_t native_count = ref_act.element_count;
        
        ActivationComparison comp = Compare(
            ref_act.op_name, op_idx,
            native_ptr, native_count,
            ref_act.data.data(), ref_act.element_count,
            ref_act.shape, ref_act.shape
        );
        
        result.comparisons.push_back(comp);
        
        if (comp.passed) {
            result.passed_ops++;
        } else {
            result.failed_ops++;
            // Track first divergence
            if (result.first_divergent_op == UINT32_MAX) {
                result.first_divergent_op = op_idx;
                result.first_divergent_name = ref_act.op_name;
            }
        }
        
        // Update global metrics
        if (comp.count > 0) {
            result.global_max_abs_diff = std::max(result.global_max_abs_diff, comp.max_abs_diff);
            result.global_rmse = std::max(result.global_rmse, comp.rmse);  // Approximate
            result.global_cosine = std::min(result.global_cosine, comp.cosine_similarity);
        }
        
        if (m_config.fail_fast && !comp.passed) {
            break;
        }
    }
    
    // Compare logits
    if (!native_logits.empty() && !reference_logits.empty() && 
        native_logits.size() == reference_logits.size()) {
        float max_diff, rmse, cosine;
        size_t max_idx;
        FindMaxAbsDiff(native_logits.data(), reference_logits.data(), native_logits.size(), max_diff, max_idx);
        rmse = ComputeRMSE(native_logits.data(), reference_logits.data(), native_logits.size());
        cosine = ComputeCosineSimilarity(native_logits.data(), reference_logits.data(), native_logits.size());
        
        result.logit_max_abs_diff = max_diff;
        result.logit_rmse = rmse;
        result.logit_cosine = cosine;
        result.logit_argmax_native = native_token;
        result.logit_argmax_reference = reference_token;
    }
    
    return result;
}

uint32_t ActivationComparator::FindFirstDivergence(
    const std::vector<std::pair<uint32_t, const float*>>& native_activations,
    const std::vector<ReferenceActivation>& reference_activations,
    uint32_t low, uint32_t high) {
    
    // Build lookup map for native activations
    std::unordered_map<uint32_t, const float*> native_map;
    for (const auto& [idx, ptr] : native_activations) {
        native_map[idx] = ptr;
    }
    
    // Build lookup map for reference
    std::unordered_map<uint32_t, const ReferenceActivation*> ref_map;
    for (const auto& act : reference_activations) {
        ref_map[act.op_index] = &act;
    }
    
    uint32_t first_divergent = UINT32_MAX;
    
    while (low <= high) {
        uint32_t mid = low + (high - low) / 2;
        
        auto native_it = native_map.find(mid);
        auto ref_it = ref_map.find(mid);
        
        if (native_it == native_map.end() || ref_it == ref_map.end()) {
            // Can't compare this op, search both sides
            high = mid - 1;
            continue;
        }
        
        const ReferenceActivation& ref_act = *ref_it->second;
        ActivationComparison comp = Compare(
            ref_act.op_name, mid,
            native_it->second, ref_act.element_count,
            ref_act.data.data(), ref_act.element_count,
            ref_act.shape, ref_act.shape
        );
        
        if (comp.passed) {
            // This op matches, search later
            low = mid + 1;
        } else {
            // This op diverges, search earlier
            first_divergent = mid;
            high = mid - 1;
        }
    }
    
    return first_divergent;
}

// DivergenceFinder implementation
DivergenceSearchResult DivergenceFinder::FindFirstDivergence(
    const std::vector<std::pair<uint32_t, const float*>>& native_activations,
    const std::vector<ReferenceActivation>& reference_activations) {
    
    DivergenceSearchResult result;
    m_search_history.clear();
    
    if (native_activations.empty() || reference_activations.empty()) {
        result.search_complete = true;
        return result;
    }
    
    // Find min and max op indices
    uint32_t min_op = UINT32_MAX;
    uint32_t max_op = 0;
    for (const auto& [idx, _] : native_activations) {
        min_op = std::min(min_op, idx);
        max_op = std::max(max_op, idx);
    }
    
    // Binary search
    uint32_t low = min_op;
    uint32_t high = max_op;
    uint32_t first_divergent = UINT32_MAX;
    
    while (low <= high) {
        uint32_t mid = low + (high - low) / 2;
        
        // Find activations at mid
        const float* native_ptr = nullptr;
        const ReferenceActivation* ref_act = nullptr;
        
        for (const auto& [idx, ptr] : native_activations) {
            if (idx == mid) { native_ptr = ptr; break; }
        }
        for (const auto& act : reference_activations) {
            if (act.op_index == mid) { ref_act = &act; break; }
        }
        
        if (!native_ptr || !ref_act) {
            // Can't compare, try lower
            high = mid - 1;
            continue;
        }
        
        ActivationComparison comp = m_comparator.Compare(
            ref_act->op_name, mid,
            native_ptr, ref_act->element_count,
            ref_act->data.data(), ref_act->element_count,
            ref_act->shape, ref_act->shape
        );
        
        m_search_history.push_back(comp);
        
        if (comp.passed) {
            low = mid + 1;
        } else {
            first_divergent = mid;
            high = mid - 1;
        }
    }
    
    result.first_divergent = first_divergent;
    result.search_history = m_search_history;
    result.search_complete = true;
    
    return result;
}

uint32_t DivergenceFinder::LinearScanFrom(
    const std::vector<std::pair<uint32_t, const float*>>& native_activations,
    const std::vector<ReferenceActivation>& reference_activations,
    uint32_t start_op) {
    
    // Build lookup maps
    std::unordered_map<uint32_t, const float*> native_map;
    for (const auto& [idx, ptr] : native_activations) {
        native_map[idx] = ptr;
    }
    
    std::unordered_map<uint32_t, const ReferenceActivation*> ref_map;
    for (const auto& act : reference_activations) {
        ref_map[act.op_index] = &act;
    }
    
    // Scan forward from start_op
    for (uint32_t op = start_op; op < UINT32_MAX; ++op) {
        auto native_it = native_map.find(op);
        auto ref_it = ref_map.find(op);
        
        if (native_it == native_map.end() || ref_it == ref_map.end()) {
            continue;  // Skip ops we can't compare
        }
        
        const ReferenceActivation& ref_act = *ref_it->second;
        ActivationComparison comp = m_comparator.Compare(
            ref_act.op_name, op,
            native_it->second, ref_act.element_count,
            ref_act.data.data(), ref_act.element_count,
            ref_act.shape, ref_act.shape
        );
        
        m_search_history.push_back(comp);
        
        if (!comp.passed) {
            return op;
        }
    }
    
    return UINT32_MAX;
}

} // namespace CLI
} // namespace RawrXD
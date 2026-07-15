/**
 * @file adaptive_policy_engine.cpp
 * @brief RawrXD L4.3.1 Adaptive Policy Engine Implementation
 *
 * Constrained optimization for compression codec selection.
 *
 * @copyright RawrXD 2026
 */

#include "adaptive_policy_engine.h"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace rawrxd {
namespace policy {

// ============================================================================
// Policy Resolver
// ============================================================================

PolicyResolver::PolicyResolver() = default;
PolicyResolver::~PolicyResolver() = default;

CompressionPolicy PolicyResolver::ResolveTensor(
    const profiler::TensorProfile& profile,
    const OptimizationConstraints& constraints
) {
    CompressionPolicy policy;
    policy.tensor_name = profile.name;
    policy.tensor_id = profile.name;  // Use name as ID for now
    policy.original_size_bytes = profile.elements * sizeof(float);

    // Check for forced codec
    compression::CompressionType selected_codec;
    if (IsForced(profile.name, constraints, &selected_codec)) {
        policy.codec = selected_codec;
        policy.rationale.primary_reason = "forced";
    }
    // Check for protected tensor
    else if (IsProtected(profile.name, constraints)) {
        policy.codec = compression::CompressionType::FP32;
        policy.rationale.primary_reason = "protected";
    }
    // Normal resolution
    else {
        policy.codec = SelectCodec(profile, constraints);
        policy.rationale.primary_reason = "sensitivity";
    }

    // Estimate characteristics
    EstimateCharacteristics(
        profile, policy.codec,
        &policy.expected_compression_ratio,
        &policy.expected_quantization_error,
        &policy.decode_latency_ms
    );

    // Calculate derived values
    policy.compressed_size_bytes = static_cast<size_t>(
        policy.original_size_bytes / policy.expected_compression_ratio
    );
    policy.memory_saved_bytes = policy.original_size_bytes - policy.compressed_size_bytes;
    policy.expected_quality_cost = profile.sensitivity_score * policy.expected_quantization_error;

    // Fill rationale
    policy.rationale.sensitivity_score = profile.sensitivity_score;
    policy.rationale.quant_error_contribution = profile.quantization_error;
    policy.rationale.memory_contribution = 1.0f / policy.expected_compression_ratio;

    return policy;
}

std::vector<CompressionPolicy> PolicyResolver::ResolveAll(
    const std::vector<profiler::TensorProfile>& profiles,
    const OptimizationConstraints& constraints
) {
    std::vector<CompressionPolicy> policies;
    policies.reserve(profiles.size());

    for (const auto& profile : profiles) {
        policies.push_back(ResolveTensor(profile, constraints));
    }

    return policies;
}

bool PolicyResolver::ValidateProfile(
    const profiler::TensorProfile& profile,
    const OptimizationConstraints& constraints,
    std::string* out_reason
) {
    // Check if profile has valid sensitivity data
    if (profile.confidence < 0.5f) {
        if (out_reason) *out_reason = "Low confidence in sensitivity analysis";
        return false;
    }

    // Check if codec meets quality constraints
    float expected_error = profile.expected_error;
    if (expected_error > constraints.max_rmse) {
        if (out_reason) *out_reason = "Expected error exceeds RMSE threshold";
        return false;
    }

    return true;
}

compression::CompressionType PolicyResolver::SelectCodec(
    const profiler::TensorProfile& profile,
    const OptimizationConstraints& constraints
) {
    // Use sensitivity score to select codec
    float sensitivity = profile.sensitivity_score;

    // Adjust for speed priority
    if (constraints.prioritize_speed) {
        // Prefer faster codecs (Q4_0, Q8_0 are faster than Q4_K, Q6_K)
        if (sensitivity <= 0.30f) return compression::CompressionType::Q4_0;
        if (sensitivity <= 0.60f) return compression::CompressionType::Q8_0;
        if (sensitivity <= 0.80f) return compression::CompressionType::Q5_0;
        return compression::CompressionType::Q6_K;
    }

    // Standard selection based on sensitivity
    if (sensitivity <= 0.25f) return compression::CompressionType::Q4_0;
    if (sensitivity <= 0.50f) return compression::CompressionType::Q5_0;
    if (sensitivity <= 0.75f) return compression::CompressionType::Q6_K;
    return compression::CompressionType::Q8_0;
}

void PolicyResolver::EstimateCharacteristics(
    const profiler::TensorProfile& profile,
    compression::CompressionType codec,
    float* out_ratio,
    float* out_error,
    float* out_latency
) {
    // Codec characteristics (from L4.2 benchmarks)
    switch (codec) {
        case compression::CompressionType::Q4_0:
            *out_ratio = 6.4f;
            *out_error = 0.004f;
            *out_latency = 0.5f;  // Fast decode
            break;
        case compression::CompressionType::Q4_K:
            *out_ratio = 6.7f;
            *out_error = 0.003f;
            *out_latency = 1.2f;  // Slower decode
            break;
        case compression::CompressionType::Q5_0:
            *out_ratio = 5.2f;
            *out_error = 0.002f;
            *out_latency = 0.6f;
            break;
        case compression::CompressionType::Q6_K:
            *out_ratio = 4.8f;
            *out_error = 0.001f;
            *out_latency = 1.0f;
            break;
        case compression::CompressionType::Q8_0:
            *out_ratio = 2.0f;
            *out_error = 0.0005f;
            *out_latency = 0.4f;  // Fastest decode
            break;
        case compression::CompressionType::FP16:
            *out_ratio = 2.0f;
            *out_error = 0.0001f;
            *out_latency = 0.2f;
            break;
        case compression::CompressionType::FP32:
            *out_ratio = 1.0f;
            *out_error = 0.0f;
            *out_latency = 0.1f;
            break;
        default:
            *out_ratio = 1.0f;
            *out_error = 0.0f;
            *out_latency = 0.1f;
            break;
    }

    // Adjust error by sensitivity (higher sensitivity = more error impact)
    *out_error *= (1.0f + profile.sensitivity_score);
}

bool PolicyResolver::IsForced(
    const std::string& tensor_name,
    const OptimizationConstraints& constraints,
    compression::CompressionType* out_codec
) {
    auto it = constraints.forced_codecs.find(tensor_name);
    if (it != constraints.forced_codecs.end()) {
        if (out_codec) *out_codec = it->second;
        return true;
    }
    return false;
}

bool PolicyResolver::IsProtected(
    const std::string& tensor_name,
    const OptimizationConstraints& constraints
) {
    for (const auto& protected_name : constraints.protected_tensors) {
        if (tensor_name.find(protected_name) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Budget Optimizer
// ============================================================================

BudgetOptimizer::BudgetOptimizer() = default;
BudgetOptimizer::~BudgetOptimizer() = default;

std::vector<CompressionPolicy> BudgetOptimizer::Optimize(
    const std::vector<CompressionPolicy>& initial_policies,
    const OptimizationConstraints& constraints,
    OptimizationObjective objective
) {
    switch (objective) {
        case OptimizationObjective::MAXIMIZE_COMPRESSION:
            return MaximizeCompression(initial_policies, constraints);
        case OptimizationObjective::MINIMIZE_QUALITY_LOSS:
            return MinimizeQualityLoss(initial_policies, constraints);
        case OptimizationObjective::MINIMIZE_LATENCY:
            // Would implement latency-aware optimization
            return BalancedOptimization(initial_policies, constraints);
        case OptimizationObjective::CUSTOM:
            // Would use custom objective function
            return BalancedOptimization(initial_policies, constraints);
        case OptimizationObjective::BALANCED:
        default:
            return BalancedOptimization(initial_policies, constraints);
    }
}

std::vector<CompressionPolicy> BudgetOptimizer::MaximizeCompression(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints
) {
    auto optimized = policies;

    // Greedy: compress everything as much as possible while meeting quality gates
    for (auto& policy : optimized) {
        // Skip protected/forced tensors
        if (policy.rationale.primary_reason == "protected" ||
            policy.rationale.primary_reason == "forced") {
            continue;
        }

        // Try most aggressive compression first
        if (policy.codec != compression::CompressionType::Q4_0) {
            // Check if Q4_0 would still meet quality constraints
            float q4_error = 0.004f * (1.0f + policy.rationale.sensitivity_score);
            if (q4_error <= constraints.max_rmse) {
                policy.codec = compression::CompressionType::Q4_0;
                policy.expected_compression_ratio = 6.4f;
                policy.expected_quantization_error = q4_error;
                policy.compressed_size_bytes = policy.original_size_bytes / 6.4f;
                policy.memory_saved_bytes = policy.original_size_bytes - policy.compressed_size_bytes;
                policy.rationale.primary_reason = "max_compression";
            }
        }
    }

    // Verify constraints still met
    if (!CheckConstraints(optimized, constraints)) {
        // Fall back to balanced optimization
        return BalancedOptimization(policies, constraints);
    }

    return optimized;
}

std::vector<CompressionPolicy> BudgetOptimizer::MinimizeQualityLoss(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints
) {
    auto optimized = policies;

    // Upgrade codecs to minimize quality loss
    for (auto& policy : optimized) {
        if (policy.rationale.primary_reason == "protected" ||
            policy.rationale.primary_reason == "forced") {
            continue;
        }

        // Upgrade to higher quality codec
        switch (policy.codec) {
            case compression::CompressionType::Q4_0:
                policy.codec = compression::CompressionType::Q5_0;
                policy.expected_compression_ratio = 5.2f;
                policy.expected_quantization_error = 0.002f;
                break;
            case compression::CompressionType::Q4_K:
                policy.codec = compression::CompressionType::Q6_K;
                policy.expected_compression_ratio = 4.8f;
                policy.expected_quantization_error = 0.001f;
                break;
            case compression::CompressionType::Q5_0:
                policy.codec = compression::CompressionType::Q6_K;
                policy.expected_compression_ratio = 4.8f;
                policy.expected_quantization_error = 0.001f;
                break;
            case compression::CompressionType::Q6_K:
                policy.codec = compression::CompressionType::Q8_0;
                policy.expected_compression_ratio = 2.0f;
                policy.expected_quantization_error = 0.0005f;
                break;
            default:
                break;
        }

        // Recalculate sizes
        policy.compressed_size_bytes = policy.original_size_bytes / policy.expected_compression_ratio;
        policy.memory_saved_bytes = policy.original_size_bytes - policy.compressed_size_bytes;
        policy.rationale.primary_reason = "max_quality";
    }

    return optimized;
}

std::vector<CompressionPolicy> BudgetOptimizer::BalancedOptimization(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints
) {
    auto optimized = policies;

    // Calculate current metrics
    auto metrics = CalculateMetrics(optimized);

    // If compression ratio is below target, try to improve
    if (metrics.achieved_compression_ratio < constraints.target_compression_ratio) {
        optimized = GreedyOptimize(optimized, constraints, false);  // Improve compression
    }

    // If quality is below minimum, upgrade codecs
    if (metrics.min_cosine_similarity < constraints.min_cosine_similarity ||
        metrics.max_rmse > constraints.max_rmse) {
        optimized = GreedyOptimize(optimized, constraints, true);  // Improve quality
    }

    // Check memory budget
    if (constraints.max_model_size_bytes > 0 &&
        metrics.total_size_bytes > constraints.max_model_size_bytes) {
        // Need more aggressive compression
        optimized = GreedyOptimize(optimized, constraints, false);
    }

    return optimized;
}

bool BudgetOptimizer::CheckConstraints(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints,
    std::vector<std::string>* out_violations
) {
    bool satisfied = true;
    auto metrics = CalculateMetrics(policies);

    if (metrics.min_cosine_similarity < constraints.min_cosine_similarity) {
        if (out_violations) {
            out_violations->push_back("Cosine similarity below threshold");
        }
        satisfied = false;
    }

    if (metrics.max_rmse > constraints.max_rmse) {
        if (out_violations) {
            out_violations->push_back("RMSE above threshold");
        }
        satisfied = false;
    }

    if (constraints.max_model_size_bytes > 0 &&
        metrics.total_size_bytes > constraints.max_model_size_bytes) {
        if (out_violations) {
            out_violations->push_back("Model size exceeds maximum");
        }
        satisfied = false;
    }

    return satisfied;
}

BudgetOptimizer::AggregateMetrics BudgetOptimizer::CalculateMetrics(
    const std::vector<CompressionPolicy>& policies
) {
    AggregateMetrics metrics = {};

    if (policies.empty()) return metrics;

    size_t total_original = 0;
    size_t total_compressed = 0;
    float total_quality_cost = 0.0f;
    float min_cosine = 1.0f;
    float max_rmse = 0.0f;

    for (const auto& policy : policies) {
        total_original += policy.original_size_bytes;
        total_compressed += policy.compressed_size_bytes;
        total_quality_cost += policy.expected_quality_cost;

        // Estimate cosine from error (simplified)
        float estimated_cosine = 1.0f - policy.expected_quantization_error;
        min_cosine = std::min(min_cosine, estimated_cosine);
        max_rmse = std::max(max_rmse, policy.expected_quantization_error);

        // Count codecs
        switch (policy.codec) {
            case compression::CompressionType::Q4_0:
            case compression::CompressionType::Q4_K:
                metrics.q4_0_count++;
                break;
            case compression::CompressionType::Q5_0:
            case compression::CompressionType::Q5_K:
                metrics.q5_count++;
                break;
            case compression::CompressionType::Q6_K:
                metrics.q6_count++;
                break;
            case compression::CompressionType::Q8_0:
                metrics.q8_count++;
                break;
            case compression::CompressionType::FP16:
                metrics.fp16_count++;
                break;
            default:
                break;
        }
    }

    metrics.total_size_bytes = total_compressed;
    metrics.total_memory_saved_mb = (total_original - total_compressed) / (1024.0f * 1024.0f);
    metrics.achieved_compression_ratio = (total_compressed > 0) ?
        static_cast<float>(total_original) / total_compressed : 1.0f;
    metrics.weighted_quality_cost = total_quality_cost / policies.size();
    metrics.min_cosine_similarity = min_cosine;
    metrics.max_rmse = max_rmse;

    return metrics;
}

std::vector<CompressionPolicy> BudgetOptimizer::GreedyOptimize(
    std::vector<CompressionPolicy> policies,
    const OptimizationConstraints& constraints,
    bool upgrade_quality
) {
    // Sort by sensitivity (highest first for quality upgrade, lowest first for compression)
    if (upgrade_quality) {
        std::sort(policies.begin(), policies.end(),
            [](const CompressionPolicy& a, const CompressionPolicy& b) {
                return a.rationale.sensitivity_score > b.rationale.sensitivity_score;
            });
    } else {
        std::sort(policies.begin(), policies.end(),
            [](const CompressionPolicy& a, const CompressionPolicy& b) {
                return a.rationale.sensitivity_score < b.rationale.sensitivity_score;
            });
    }

    // Greedy upgrade/downgrade
    for (auto& policy : policies) {
        if (policy.rationale.primary_reason == "protected" ||
            policy.rationale.primary_reason == "forced") {
            continue;
        }

        if (upgrade_quality) {
            // Upgrade to next higher quality codec
            // (simplified - would check all upgrades)
            if (policy.codec == compression::CompressionType::Q4_0) {
                policy.codec = compression::CompressionType::Q5_0;
                policy.expected_compression_ratio = 5.2f;
            }
        } else {
            // Downgrade to more aggressive compression
            if (policy.codec == compression::CompressionType::Q5_0) {
                policy.codec = compression::CompressionType::Q4_0;
                policy.expected_compression_ratio = 6.4f;
            }
        }

        // Recalculate
        policy.compressed_size_bytes = policy.original_size_bytes / policy.expected_compression_ratio;
        policy.memory_saved_bytes = policy.original_size_bytes - policy.compressed_size_bytes;
    }

    return policies;
}

float BudgetOptimizer::CalculateQualityScore(const std::vector<CompressionPolicy>& policies) {
    if (policies.empty()) return 0.0f;

    float total_score = 0.0f;
    for (const auto& policy : policies) {
        // Higher cosine = better quality
        float estimated_cosine = 1.0f - policy.expected_quantization_error;
        total_score += estimated_cosine;
    }

    return total_score / policies.size();
}

float BudgetOptimizer::CalculateCompressionScore(const std::vector<CompressionPolicy>& policies) {
    if (policies.empty()) return 0.0f;

    size_t total_original = 0;
    size_t total_compressed = 0;

    for (const auto& policy : policies) {
        total_original += policy.original_size_bytes;
        total_compressed += policy.compressed_size_bytes;
    }

    return (total_compressed > 0) ?
        static_cast<float>(total_original) / total_compressed : 1.0f;
}

// ============================================================================
// Adaptive Policy Engine
// ============================================================================

AdaptivePolicyEngine::AdaptivePolicyEngine()
    : initialized_(false)
{}

AdaptivePolicyEngine::~AdaptivePolicyEngine() = default;

bool AdaptivePolicyEngine::Initialize(const std::string& model_name) {
    model_name_ = model_name;
    initialized_ = true;
    return true;
}

std::vector<CompressionPolicy> AdaptivePolicyEngine::GeneratePolicy(
    const std::vector<profiler::TensorProfile>& profiles,
    const OptimizationConstraints& constraints,
    OptimizationObjective objective
) {
    if (!initialized_) return {};

    last_constraints_ = constraints;

    // Step 1: Resolve initial policies
    auto policies = ResolvePolicies(profiles, constraints);

    // Step 2: Optimize to meet constraints
    current_policy_ = OptimizePolicies(policies, constraints, objective);

    return current_policy_;
}

std::vector<CompressionPolicy> AdaptivePolicyEngine::ResolvePolicies(
    const std::vector<profiler::TensorProfile>& profiles,
    const OptimizationConstraints& constraints
) {
    return resolver_.ResolveAll(profiles, constraints);
}

std::vector<CompressionPolicy> AdaptivePolicyEngine::OptimizePolicies(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints,
    OptimizationObjective objective
) {
    return optimizer_.Optimize(policies, constraints, objective);
}

bool AdaptivePolicyEngine::ValidatePolicies(
    const std::vector<CompressionPolicy>& policies,
    const OptimizationConstraints& constraints,
    std::vector<std::string>* out_failures
) {
    return optimizer_.CheckConstraints(policies, constraints, out_failures);
}

bool AdaptivePolicyEngine::ExportPolicyJSON(const std::string& filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;

    file << PolicyToJSON(current_policy_);
    return true;
}

bool AdaptivePolicyEngine::ImportPolicyJSON(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::string json((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

    return PolicyFromJSON(json, &current_policy_);
}

bool AdaptivePolicyEngine::ExportPolicyGGUF(const std::string& filename) const {
    // Would embed policy in GGUF metadata
    (void)filename;
    return false;
}

void AdaptivePolicyEngine::PrintPolicySummary() const {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "ADAPTIVE COMPRESSION POLICY\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "Model: " << model_name_ << "\n";
    std::cout << "Tensors: " << current_policy_.size() << "\n\n";

    auto metrics = optimizer_.CalculateMetrics(current_policy_);

    std::cout << std::fixed << std::setprecision(2);
    std::cout << "Compression Ratio: " << metrics.achieved_compression_ratio << ":1\n";
    std::cout << "Memory Saved: " << metrics.total_memory_saved_mb << " MB\n";
    std::cout << "Estimated Quality Cost: " << metrics.weighted_quality_cost << "\n";
    std::cout << "Min Cosine: " << metrics.min_cosine_similarity << "\n";
    std::cout << "Max RMSE: " << metrics.max_rmse << "\n\n";

    std::cout << "Codec Distribution:\n";
    std::cout << "  Q4_0: " << metrics.q4_0_count << "\n";
    std::cout << "  Q5: " << metrics.q5_count << "\n";
    std::cout << "  Q6_K: " << metrics.q6_count << "\n";
    std::cout << "  Q8_0: " << metrics.q8_count << "\n";
    std::cout << "  FP16: " << metrics.fp16_count << "\n";

    std::cout << "═══════════════════════════════════════════════════════════════\n";
}

void AdaptivePolicyEngine::PrintTensorDetails(const std::string& tensor_name) const {
    for (const auto& policy : current_policy_) {
        if (policy.tensor_name == tensor_name) {
            std::cout << "\nTensor: " << policy.tensor_name << "\n";
            std::cout << "  Codec: " << static_cast<int>(policy.codec) << "\n";
            std::cout << "  Compression: " << policy.expected_compression_ratio << ":1\n";
            std::cout << "  Error: " << policy.expected_quantization_error << "\n";
            std::cout << "  Memory Saved: " << policy.memory_saved_bytes / 1024 << " KB\n";
            std::cout << "  Reason: " << policy.rationale.primary_reason << "\n";
            return;
        }
    }
    std::cout << "Tensor not found: " << tensor_name << "\n";
}

std::string AdaptivePolicyEngine::GeneratePolicyReport() const {
    std::ostringstream report;

    report << "# RawrXD Adaptive Compression Policy Report\n\n";
    report << "Model: " << model_name_ << "\n";
    report << "Generated: " << "2026-07-09" << "\n\n";

    auto metrics = optimizer_.CalculateMetrics(current_policy_);

    report << "## Summary\n\n";
    report << "- Compression Ratio: " << metrics.achieved_compression_ratio << ":1\n";
    report << "- Memory Saved: " << metrics.total_memory_saved_mb << " MB\n";
    report << "- Quality Cost: " << metrics.weighted_quality_cost << "\n";
    report << "- Min Cosine: " << metrics.min_cosine_similarity << "\n\n";

    report << "## Tensor Policies\n\n";
    report << "| Tensor | Codec | Ratio | Error | Reason |\n";
    report << "|--------|-------|-------|-------|--------|\n";

    for (const auto& policy : current_policy_) {
        report << "| " << policy.tensor_name
               << " | " << static_cast<int>(policy.codec)
               << " | " << policy.expected_compression_ratio
               << " | " << policy.expected_quantization_error
               << " | " << policy.rationale.primary_reason << " |\n";
    }

    return report.str();
}

bool AdaptivePolicyEngine::ComparePolicies(
    const std::vector<CompressionPolicy>& a,
    const std::vector<CompressionPolicy>& b,
    float tolerance
) {
    if (a.size() != b.size()) return false;

    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i].tensor_name != b[i].tensor_name) return false;
        if (a[i].codec != b[i].codec) return false;
        if (std::abs(a[i].expected_compression_ratio - b[i].expected_compression_ratio) > tolerance) {
            return false;
        }
    }

    return true;
}

OptimizationConstraints AdaptivePolicyEngine::Preset_MaximumCompression() {
    OptimizationConstraints constraints;
    constraints.target_compression_ratio = 8.0f;
    constraints.max_rmse = 0.02f;
    constraints.min_cosine_similarity = 0.99f;
    constraints.prioritize_speed = true;
    return constraints;
}

OptimizationConstraints AdaptivePolicyEngine::Preset_MaximumQuality() {
    OptimizationConstraints constraints;
    constraints.target_compression_ratio = 2.0f;
    constraints.max_rmse = 0.001f;
    constraints.min_cosine_similarity = 0.9999f;
    constraints.prioritize_speed = false;
    return constraints;
}

OptimizationConstraints AdaptivePolicyEngine::Preset_Balanced() {
    OptimizationConstraints constraints;
    constraints.target_compression_ratio = 5.0f;
    constraints.max_rmse = 0.01f;
    constraints.min_cosine_similarity = 0.999f;
    constraints.prioritize_speed = true;
    return constraints;
}

OptimizationConstraints AdaptivePolicyEngine::Preset_Interactive() {
    // Would prompt user for settings
    return Preset_Balanced();
}

// ============================================================================
// Policy Applicator (L4.3.2)
// ============================================================================

PolicyApplicator::PolicyApplicator() = default;
PolicyApplicator::~PolicyApplicator() = default;

bool PolicyApplicator::LoadPolicy(const std::vector<CompressionPolicy>& policy) {
    policy_ = policy;
    policy_map_.clear();
    for (const auto& p : policy) {
        policy_map_[p.tensor_name] = p;
    }
    return true;
}

bool PolicyApplicator::LoadPolicyFromJSON(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;

    std::string json((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

    return PolicyFromJSON(json, &policy_);
}

bool PolicyApplicator::ApplyToGGUF(
    const std::string& input_gguf,
    const std::string& output_gguf
) {
    // Would apply policy to recompress GGUF
    (void)input_gguf;
    (void)output_gguf;
    return false;
}

bool PolicyApplicator::ValidateApplication(
    const std::string& original_gguf,
    const std::string& compressed_gguf,
    std::vector<std::string>* out_errors
) {
    // Would validate compressed model
    (void)original_gguf;
    (void)compressed_gguf;
    (void)out_errors;
    return false;
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string PolicyToJSON(const CompressionPolicy& policy) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"tensor\": \"" << policy.tensor_name << "\",\n";
    json << "  \"codec\": \"" << static_cast<int>(policy.codec) << "\",\n";
    json << "  \"ratio\": " << policy.expected_compression_ratio << ",\n";
    json << "  \"error\": " << policy.expected_quantization_error << ",\n";
    json << "  \"rationale\": {\n";
    json << "    \"sensitivity\": " << policy.rationale.sensitivity_score << ",\n";
    json << "    \"reason\": \"" << policy.rationale.primary_reason << "\"\n";
    json << "  }\n";
    json << "}";
    return json.str();
}

std::string PolicyToJSON(const std::vector<CompressionPolicy>& policies) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"policies\": [\n";

    for (size_t i = 0; i < policies.size(); ++i) {
        json << "    {\n";
        json << "      \"tensor\": \"" << policies[i].tensor_name << "\",\n";
        json << "      \"codec\": \"" << static_cast<int>(policies[i].codec) << "\",\n";
        json << "      \"ratio\": " << policies[i].expected_compression_ratio << ",\n";
        json << "      \"error\": " << policies[i].expected_quantization_error << ",\n";
        json << "      \"memory_saved\": " << policies[i].memory_saved_bytes << ",\n";
        json << "      \"rationale\": {\n";
        json << "        \"sensitivity\": " << policies[i].rationale.sensitivity_score << ",\n";
        json << "        \"reason\": \"" << policies[i].rationale.primary_reason << "\"\n";
        json << "      }\n";
        json << "    }";
        if (i + 1 < policies.size()) json << ",";
        json << "\n";
    }

    json << "  ]\n";
    json << "}";
    return json.str();
}

bool PolicyFromJSON(const std::string& json, CompressionPolicy* out_policy) {
    // Simplified parsing - would use proper JSON library
    (void)json;
    (void)out_policy;
    return false;
}

bool PolicyFromJSON(const std::string& json, std::vector<CompressionPolicy>* out_policies) {
    // Simplified parsing - would use proper JSON library
    (void)json;
    (void)out_policies;
    return false;
}

float CalculateMemorySavingsMB(const std::vector<CompressionPolicy>& policies) {
    size_t total_saved = 0;
    for (const auto& policy : policies) {
        total_saved += policy.memory_saved_bytes;
    }
    return total_saved / (1024.0f * 1024.0f);
}

float CalculateMemorySavingsPercent(const std::vector<CompressionPolicy>& policies) {
    size_t total_original = 0;
    size_t total_saved = 0;

    for (const auto& policy : policies) {
        total_original += policy.original_size_bytes;
        total_saved += policy.memory_saved_bytes;
    }

    return (total_original > 0) ?
        (100.0f * total_saved / total_original) : 0.0f;
}

float EstimateQualityImpact(const std::vector<CompressionPolicy>& policies) {
    if (policies.empty()) return 0.0f;

    float total_impact = 0.0f;
    for (const auto& policy : policies) {
        total_impact += policy.expected_quality_cost;
    }

    return total_impact / policies.size();
}

bool ValidateAgainstL4_2_3_Gates(
    const std::vector<CompressionPolicy>& policies,
    std::vector<std::string>* out_failures
) {
    bool passed = true;

    for (const auto& policy : policies) {
        // Check cosine similarity gate
        float estimated_cosine = 1.0f - policy.expected_quantization_error;
        if (estimated_cosine < 0.999f) {  // STANDARD gate
            if (out_failures) {
                out_failures->push_back(
                    "Cosine below STANDARD gate: " + policy.tensor_name
                );
            }
            passed = false;
        }

        // Check RMSE gate
        if (policy.expected_quantization_error > 0.01f) {  // STANDARD gate
            if (out_failures) {
                out_failures->push_back(
                    "RMSE above STANDARD gate: " + policy.tensor_name
                );
            }
            passed = false;
        }
    }

    return passed;
}

} // namespace policy
} // namespace rawrxd

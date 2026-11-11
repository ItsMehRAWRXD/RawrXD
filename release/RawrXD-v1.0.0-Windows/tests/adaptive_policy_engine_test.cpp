/**
 * @file adaptive_policy_engine_test.cpp
 * @brief RawrXD L4.3.1 Adaptive Policy Engine Tests
 *
 * Validation for constrained optimization of compression policies.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <cmath>

#include "../kernels/adaptive_policy_engine.h"

using namespace rawrxd;
using namespace rawrxd::policy;
using namespace rawrxd::compression;
using namespace rawrxd::profiler;

// ============================================================================
// Test Utilities
// ============================================================================

class TestReporter {
public:
    static int tests_run_;
    static int tests_passed_;
    static int tests_failed_;
    
    static void Reset() {
        tests_run_ = 0;
        tests_passed_ = 0;
        tests_failed_ = 0;
    }
    
    static void Report(const char* name, bool passed) {
        tests_run_++;
        if (passed) {
            tests_passed_++;
            std::cout << "  ✅ " << name << "\n";
        } else {
            tests_failed_++;
            std::cout << "  ❌ " << name << "\n";
        }
    }
    
    static void PrintSummary() {
        std::cout << "\n═══════════════════════════════════════════════════════════════\n";
        std::cout << "TEST SUMMARY: " << tests_passed_ << "/" << tests_run_ << " passed\n";
        std::cout << "═══════════════════════════════════════════════════════════════\n";
    }
};

int TestReporter::tests_run_ = 0;
int TestReporter::tests_passed_ = 0;
int TestReporter::tests_failed_ = 0;

// Helper to create test profiles
TensorProfile CreateTestProfile(const std::string& name, float sensitivity) {
    TensorProfile profile;
    profile.name = name;
    profile.elements = 1000;
    profile.sensitivity_score = sensitivity;
    profile.quantization_error = 0.002f;
    profile.activation_variance = sensitivity * 0.5f;
    profile.output_impact = sensitivity * 0.3f;
    profile.gradient_sensitivity = sensitivity * 0.2f;
    profile.confidence = 0.95f;
    return profile;
}

// ============================================================================
// Test Cases
// ============================================================================

bool Test_CompressionPolicy_Valid() {
    CompressionPolicy policy;
    policy.tensor_name = "test";
    policy.codec = CompressionType::Q4_0;
    policy.expected_compression_ratio = 6.4f;
    policy.compressed_size_bytes = 100;
    
    return policy.IsValid();
}

bool Test_CompressionPolicy_Invalid() {
    CompressionPolicy policy;
    policy.tensor_name = "";
    policy.expected_compression_ratio = 0.0f;
    
    return !policy.IsValid();
}

bool Test_OptimizationConstraints_Defaults() {
    OptimizationConstraints constraints;
    
    return constraints.target_compression_ratio == 5.0f &&
           constraints.min_cosine_similarity == 0.999f &&
           constraints.max_rmse == 0.01f;
}

bool Test_PolicyResolver_Initialize() {
    PolicyResolver resolver;
    return true; // Just test construction
}

bool Test_PolicyResolver_SelectCodec_LowSensitivity() {
    PolicyResolver resolver;
    auto profile = CreateTestProfile("test", 0.1f);
    OptimizationConstraints constraints;
    
    auto codec = resolver.SelectCodec(profile, constraints);
    
    return codec == CompressionType::Q4_0;
}

bool Test_PolicyResolver_SelectCodec_HighSensitivity() {
    PolicyResolver resolver;
    auto profile = CreateTestProfile("test", 0.9f);
    OptimizationConstraints constraints;
    
    auto codec = resolver.SelectCodec(profile, constraints);
    
    return codec == CompressionType::Q8_0;
}

bool Test_PolicyResolver_ForcedCodec() {
    PolicyResolver resolver;
    auto profile = CreateTestProfile("forced_tensor", 0.5f);
    
    OptimizationConstraints constraints;
    constraints.forced_codecs["forced_tensor"] = CompressionType::Q6_K;
    
    auto policy = resolver.ResolveTensor(profile, constraints);
    
    return policy.codec == CompressionType::Q6_K &&
           policy.rationale.primary_reason == "forced";
}

bool Test_PolicyResolver_ProtectedTensor() {
    PolicyResolver resolver;
    auto profile = CreateTestProfile("protected_tensor", 0.5f);
    
    OptimizationConstraints constraints;
    constraints.protected_tensors.push_back("protected");
    
    auto policy = resolver.ResolveTensor(profile, constraints);
    
    return policy.codec == CompressionType::FP32 &&
           policy.rationale.primary_reason == "protected";
}

bool Test_PolicyResolver_EstimateCharacteristics() {
    PolicyResolver resolver;
    auto profile = CreateTestProfile("test", 0.5f);
    
    float ratio, error, latency;
    resolver.EstimateCharacteristics(profile, CompressionType::Q4_0, 
                                       &ratio, &error, &latency);
    
    return ratio == 6.4f && error > 0.0f && latency > 0.0f;
}

bool Test_PolicyResolver_ResolveAll() {
    PolicyResolver resolver;
    
    std::vector<TensorProfile> profiles;
    profiles.push_back(CreateTestProfile("tensor1", 0.2f));
    profiles.push_back(CreateTestProfile("tensor2", 0.8f));
    
    OptimizationConstraints constraints;
    auto policies = resolver.ResolveAll(profiles, constraints);
    
    return policies.size() == 2;
}

bool Test_BudgetOptimizer_Initialize() {
    BudgetOptimizer optimizer;
    return true;
}

bool Test_BudgetOptimizer_CalculateMetrics() {
    BudgetOptimizer optimizer;
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 200;
    p1.codec = CompressionType::Q4_0;
    p1.expected_quantization_error = 0.004f;
    policies.push_back(p1);
    
    auto metrics = optimizer.CalculateMetrics(policies);
    
    return metrics.achieved_compression_ratio == 5.0f &&
           metrics.q4_0_count == 1;
}

bool Test_BudgetOptimizer_CheckConstraints_Pass() {
    BudgetOptimizer optimizer;
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 200;
    p1.expected_quantization_error = 0.001f;
    policies.push_back(p1);
    
    OptimizationConstraints constraints;
    constraints.max_rmse = 0.01f;
    
    return optimizer.CheckConstraints(policies, constraints);
}

bool Test_BudgetOptimizer_CheckConstraints_Fail() {
    BudgetOptimizer optimizer;
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 200;
    p1.expected_quantization_error = 0.1f; // Too high
    policies.push_back(p1);
    
    OptimizationConstraints constraints;
    constraints.max_rmse = 0.01f;
    
    return !optimizer.CheckConstraints(policies, constraints);
}

bool Test_BudgetOptimizer_MaximizeCompression() {
    BudgetOptimizer optimizer;
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.tensor_name = "test";
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 500;
    p1.codec = CompressionType::Q5_0;
    p1.expected_compression_ratio = 2.0f;
    p1.expected_quantization_error = 0.002f;
    p1.rationale.sensitivity_score = 0.1f;
    p1.rationale.primary_reason = "sensitivity";
    policies.push_back(p1);
    
    OptimizationConstraints constraints;
    constraints.max_rmse = 0.02f; // Allow higher error
    
    auto optimized = optimizer.MaximizeCompression(policies, constraints);
    
    return optimized[0].codec == CompressionType::Q4_0;
}

bool Test_BudgetOptimizer_MinimizeQualityLoss() {
    BudgetOptimizer optimizer;
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.tensor_name = "test";
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 156; // Q4_0
    p1.codec = CompressionType::Q4_0;
    p1.expected_compression_ratio = 6.4f;
    p1.expected_quantization_error = 0.004f;
    p1.rationale.sensitivity_score = 0.5f;
    p1.rationale.primary_reason = "sensitivity";
    policies.push_back(p1);
    
    OptimizationConstraints constraints;
    auto optimized = optimizer.MinimizeQualityLoss(policies, constraints);
    
    return optimized[0].codec == CompressionType::Q5_0;
}

bool Test_AdaptivePolicyEngine_Initialize() {
    AdaptivePolicyEngine engine;
    return engine.Initialize("test_model");
}

bool Test_AdaptivePolicyEngine_GeneratePolicy() {
    AdaptivePolicyEngine engine;
    engine.Initialize("test_model");
    
    std::vector<TensorProfile> profiles;
    profiles.push_back(CreateTestProfile("tensor1", 0.2f));
    profiles.push_back(CreateTestProfile("tensor2", 0.8f));
    
    OptimizationConstraints constraints;
    auto policies = engine.GeneratePolicy(profiles, constraints);
    
    return policies.size() == 2;
}

bool Test_AdaptivePolicyEngine_Presets() {
    auto max_comp = AdaptivePolicyEngine::Preset_MaximumCompression();
    auto max_qual = AdaptivePolicyEngine::Preset_MaximumQuality();
    auto balanced = AdaptivePolicyEngine::Preset_Balanced();
    
    return max_comp.target_compression_ratio > balanced.target_compression_ratio &&
           max_qual.target_compression_ratio < balanced.target_compression_ratio;
}

bool Test_AdaptivePolicyEngine_ValidatePolicies() {
    AdaptivePolicyEngine engine;
    engine.Initialize("test_model");
    
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.tensor_name = "test";
    p1.original_size_bytes = 1000;
    p1.compressed_size_bytes = 200;
    p1.expected_quantization_error = 0.001f;
    policies.push_back(p1);
    
    OptimizationConstraints constraints;
    constraints.max_rmse = 0.01f;
    
    return engine.ValidatePolicies(policies, constraints);
}

bool Test_PolicyToJSON() {
    CompressionPolicy policy;
    policy.tensor_name = "test_tensor";
    policy.codec = CompressionType::Q4_0;
    policy.expected_compression_ratio = 6.4f;
    policy.expected_quantization_error = 0.004f;
    policy.rationale.sensitivity_score = 0.2f;
    policy.rationale.primary_reason = "sensitivity";
    
    std::string json = PolicyToJSON(policy);
    
    return json.find("test_tensor") != std::string::npos &&
           json.find("6.4") != std::string::npos;
}

bool Test_CalculateMemorySavings() {
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.original_size_bytes = 1024 * 1024; // 1 MB
    p1.memory_saved_bytes = 1024 * 1024 * 0.8f; // 0.8 MB saved
    policies.push_back(p1);
    
    float savings = CalculateMemorySavingsMB(policies);
    
    return std::abs(savings - 0.8f) < 0.01f;
}

bool Test_ValidateAgainstL4_2_3_Gates_Pass() {
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.tensor_name = "test";
    p1.expected_quantization_error = 0.001f; // Below 0.01 gate
    policies.push_back(p1);
    
    return ValidateAgainstL4_2_3_Gates(policies);
}

bool Test_ValidateAgainstL4_2_3_Gates_Fail() {
    std::vector<CompressionPolicy> policies;
    CompressionPolicy p1;
    p1.tensor_name = "test";
    p1.expected_quantization_error = 0.1f; // Above 0.01 gate
    policies.push_back(p1);
    
    std::vector<std::string> failures;
    bool passed = ValidateAgainstL4_2_3_Gates(policies, &failures);
    
    return !passed && !failures.empty();
}

// ============================================================================
// Integration Tests
// ============================================================================

bool Test_FullPolicyWorkflow() {
    // Complete L4.3.1 workflow
    AdaptivePolicyEngine engine;
    if (!engine.Initialize("ministral3")) return false;
    
    // Create test profiles
    std::vector<TensorProfile> profiles;
    profiles.push_back(CreateTestProfile("blk.0.attn.q.weight", 0.7f));
    profiles.push_back(CreateTestProfile("blk.0.ffn.down.weight", 0.2f));
    profiles.push_back(CreateTestProfile("token_embd.weight", 0.3f));
    profiles.push_back(CreateTestProfile("output.weight", 0.9f));
    
    // Generate policy with balanced objective
    OptimizationConstraints constraints;
    constraints.target_compression_ratio = 5.0f;
    constraints.min_cosine_similarity = 0.999f;
    constraints.max_rmse = 0.01f;
    
    auto policies = engine.GeneratePolicy(profiles, constraints, 
                                           OptimizationObjective::BALANCED);
    
    if (policies.size() != 4) return false;
    
    // Validate against L4.2.3 gates
    if (!engine.ValidatePolicies(policies, constraints)) return false;
    
    // Check that high-sensitivity tensors get better codecs
    for (const auto& policy : policies) {
        if (policy.tensor_name == "output.weight" && 
            policy.codec != CompressionType::Q8_0) {
            return false; // Output should be Q8_0
        }
        if (policy.tensor_name == "blk.0.ffn.down.weight" && 
            policy.codec != CompressionType::Q4_0) {
            return false; // FFN down should be Q4_0
        }
    }
    
    return true;
}

bool Test_ConstrainedOptimization() {
    AdaptivePolicyEngine engine;
    engine.Initialize("test");
    
    // Create profiles with varying sensitivity
    std::vector<TensorProfile> profiles;
    for (int i = 0; i < 10; ++i) {
        profiles.push_back(CreateTestProfile("tensor" + std::to_string(i), 
                                              i / 10.0f));
    }
    
    // Try to maximize compression while meeting quality gates
    OptimizationConstraints constraints;
    constraints.target_compression_ratio = 6.0f;
    constraints.min_cosine_similarity = 0.999f;
    constraints.max_rmse = 0.01f;
    
    auto policies = engine.GeneratePolicy(profiles, constraints,
                                           OptimizationObjective::MAXIMIZE_COMPRESSION);
    
    // Check constraints are met
    return engine.ValidatePolicies(policies, constraints);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "RawrXD L4.3.1 Adaptive Policy Engine Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    TestReporter::Reset();
    
    // CompressionPolicy Tests
    std::cout << "CompressionPolicy Tests:\n";
    TestReporter::Report("CompressionPolicy_Valid", Test_CompressionPolicy_Valid());
    TestReporter::Report("CompressionPolicy_Invalid", Test_CompressionPolicy_Invalid());
    
    // OptimizationConstraints Tests
    std::cout << "\nOptimizationConstraints Tests:\n";
    TestReporter::Report("OptimizationConstraints_Defaults", Test_OptimizationConstraints_Defaults());
    
    // PolicyResolver Tests
    std::cout << "\nPolicyResolver Tests:\n";
    TestReporter::Report("PolicyResolver_Initialize", Test_PolicyResolver_Initialize());
    TestReporter::Report("PolicyResolver_SelectCodec_LowSensitivity", Test_PolicyResolver_SelectCodec_LowSensitivity());
    TestReporter::Report("PolicyResolver_SelectCodec_HighSensitivity", Test_PolicyResolver_SelectCodec_HighSensitivity());
    TestReporter::Report("PolicyResolver_ForcedCodec", Test_PolicyResolver_ForcedCodec());
    TestReporter::Report("PolicyResolver_ProtectedTensor", Test_PolicyResolver_ProtectedTensor());
    TestReporter::Report("PolicyResolver_EstimateCharacteristics", Test_PolicyResolver_EstimateCharacteristics());
    TestReporter::Report("PolicyResolver_ResolveAll", Test_PolicyResolver_ResolveAll());
    
    // BudgetOptimizer Tests
    std::cout << "\nBudgetOptimizer Tests:\n";
    TestReporter::Report("BudgetOptimizer_Initialize", Test_BudgetOptimizer_Initialize());
    TestReporter::Report("BudgetOptimizer_CalculateMetrics", Test_BudgetOptimizer_CalculateMetrics());
    TestReporter::Report("BudgetOptimizer_CheckConstraints_Pass", Test_BudgetOptimizer_CheckConstraints_Pass());
    TestReporter::Report("BudgetOptimizer_CheckConstraints_Fail", Test_BudgetOptimizer_CheckConstraints_Fail());
    TestReporter::Report("BudgetOptimizer_MaximizeCompression", Test_BudgetOptimizer_MaximizeCompression());
    TestReporter::Report("BudgetOptimizer_MinimizeQualityLoss", Test_BudgetOptimizer_MinimizeQualityLoss());
    
    // AdaptivePolicyEngine Tests
    std::cout << "\nAdaptivePolicyEngine Tests:\n";
    TestReporter::Report("AdaptivePolicyEngine_Initialize", Test_AdaptivePolicyEngine_Initialize());
    TestReporter::Report("AdaptivePolicyEngine_GeneratePolicy", Test_AdaptivePolicyEngine_GeneratePolicy());
    TestReporter::Report("AdaptivePolicyEngine_Presets", Test_AdaptivePolicyEngine_Presets());
    TestReporter::Report("AdaptivePolicyEngine_ValidatePolicies", Test_AdaptivePolicyEngine_ValidatePolicies());
    
    // Utility Tests
    std::cout << "\nUtility Tests:\n";
    TestReporter::Report("PolicyToJSON", Test_PolicyToJSON());
    TestReporter::Report("CalculateMemorySavings", Test_CalculateMemorySavings());
    TestReporter::Report("ValidateAgainstL4_2_3_Gates_Pass", Test_ValidateAgainstL4_2_3_Gates_Pass());
    TestReporter::Report("ValidateAgainstL4_2_3_Gates_Fail", Test_ValidateAgainstL4_2_3_Gates_Fail());
    
    // Integration Tests
    std::cout << "\nIntegration Tests:\n";
    TestReporter::Report("FullPolicyWorkflow", Test_FullPolicyWorkflow());
    TestReporter::Report("ConstrainedOptimization", Test_ConstrainedOptimization());
    
    TestReporter::PrintSummary();
    
    return TestReporter::tests_failed_ > 0 ? 1 : 0;
}

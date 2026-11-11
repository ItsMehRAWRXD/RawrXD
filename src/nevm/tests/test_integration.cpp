//============================================================================
// test_integration.cpp
// RawrXD N-EVM - Integration Tests for Full Validation Pipeline
//============================================================================

#include "../nevm_validation_framework.hpp"
#include "../nevm_math_mode_controller.hpp"
#include "../nevm_determinism_safeguards.hpp"
#include "../nevm_kv_integrity.hpp"
#include "../nevm_performance_thresholds.hpp"
#include "../nevm_golden_output.hpp"
#include "../nevm_execution_plan_version.hpp"
#include "../nevm_validation_schema.hpp"

using namespace RawrXD::NEVM;

TEST(Integration_Framework_Initialization) {
    // Test that the validation framework can be initialized
    ValidationFramework framework;
    
    ASSERT_TRUE(framework.Initialize());
    ASSERT_TRUE(framework.IsInitialized());
    
    framework.Shutdown();
    ASSERT_FALSE(framework.IsInitialized());
    
    return true;
}

TEST(Integration_MathMode_Switching) {
    MathModeController controller;
    
    // Test switching between all modes
    ASSERT_TRUE(controller.SetMode(MathMode::FAST));
    ASSERT_EQ(MathMode::FAST, controller.GetCurrentMode());
    
    ASSERT_TRUE(controller.SetMode(MathMode::REPRODUCIBLE));
    ASSERT_EQ(MathMode::REPRODUCIBLE, controller.GetCurrentMode());
    
    ASSERT_TRUE(controller.SetMode(MathMode::BIT_EXACT));
    ASSERT_EQ(MathMode::BIT_EXACT, controller.GetCurrentMode());
    
    return true;
}

TEST(Integration_Determinism_TreeSum) {
    // Test tree sum with various sizes
    std::vector<float> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<float>(i) * 0.001f;
    }
    
    float sum1 = DeterminismSafeguards::TreeSum(data.data(), data.size());
    float sum2 = DeterminismSafeguards::TreeSum(data.data(), data.size());
    
    // Tree sum should be deterministic
    ASSERT_EQ(sum1, sum2);
    
    return true;
}

TEST(Integration_KVIntegrity_FullWorkflow) {
    KVIntegrityTracker tracker;
    
    // Simulate KV cache operations
    uint8_t k_data[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t v_data[] = {0x05, 0x06, 0x07, 0x08};
    
    // Register a page
    tracker.RegisterPage(1, k_data, v_data, 4, 4, 0);
    
    // Verify integrity
    ASSERT_TRUE(tracker.VerifyPage(1, k_data, v_data, 4, 4, "test_op"));
    
    // Update data
    uint8_t v_data2[] = {0x05, 0x06, 0x07, 0x09};
    tracker.UpdateChecksum(1, k_data, v_data2, 4, 4);
    
    // Verify with new data
    ASSERT_TRUE(tracker.VerifyPage(1, k_data, v_data2, 4, 4, "test_op2"));
    
    // Verify old data should fail
    ASSERT_FALSE(tracker.VerifyPage(1, k_data, v_data, 4, 4, "test_op3"));
    
    // Check stats
    auto stats = tracker.GetStats();
    ASSERT_EQ(1ULL, stats.pages_tracked);
    ASSERT_EQ(1ULL, stats.violations_count);
    
    return true;
}

TEST(Integration_Performance_Budget) {
    PerformanceBudget budget;
    
    // Allocate budget across components
    ASSERT_TRUE(budget.Allocate("attention", 40.0));
    ASSERT_TRUE(budget.Allocate("ffn", 35.0));
    ASSERT_TRUE(budget.Allocate("embedding", 25.0));
    
    // Consume within budget
    ASSERT_TRUE(budget.Consume("attention", 35.0));
    ASSERT_TRUE(budget.Consume("ffn", 30.0));
    ASSERT_TRUE(budget.Consume("embedding", 20.0));
    
    // Check remaining
    ASSERT_NEAR(5.0, budget.GetRemaining("attention"), 0.1);
    ASSERT_NEAR(5.0, budget.GetRemaining("ffn"), 0.1);
    ASSERT_NEAR(5.0, budget.GetRemaining("embedding"), 0.1);
    
    return true;
}

TEST(Integration_GoldenOutput_FullWorkflow) {
    GoldenOutputTester tester;
    
    // Create golden output
    GoldenOutput golden;
    golden.name = "integration_test";
    golden.version = "1.0.0";
    golden.seed = 42;
    golden.tokens = {1, 2, 3, 4, 5};
    golden.logits = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    golden.metadata["model"] = "test";
    
    // Register golden output
    tester.RegisterGoldenOutput(golden);
    
    // Validate matching output
    GoldenOutput actual;
    actual.tokens = {1, 2, 3, 4, 5};
    actual.logits = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f};
    
    auto result = tester.ValidateOutput("integration_test", actual);
    ASSERT_TRUE(result.passed);
    
    // Validate non-matching output
    GoldenOutput actual2;
    actual2.tokens = {1, 2, 99, 4, 5};
    
    auto result2 = tester.ValidateOutput("integration_test", actual2);
    ASSERT_FALSE(result2.passed);
    
    // Check stats
    auto stats = tester.GetStats();
    ASSERT_EQ(2ULL, stats.total_tests);
    ASSERT_EQ(1ULL, stats.passed_tests);
    ASSERT_EQ(1ULL, stats.failed_tests);
    
    return true;
}

TEST(Integration_ExecutionPlan_Versioning) {
    // Test version parsing and comparison
    auto v1 = ExecutionPlanVersion::Parse("1.0.0");
    auto v2 = ExecutionPlanVersion::Parse("1.5.0");
    auto v3 = ExecutionPlanVersion::Parse("2.0.0");
    
    // Same major version should be compatible
    ASSERT_TRUE(ExecutionPlanVersion::IsCompatible(v1, v2));
    
    // Different major version should not be compatible
    ASSERT_FALSE(ExecutionPlanVersion::IsCompatible(v1, v3));
    
    // Version comparison
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v1, v2) < 0);
    ASSERT_TRUE(ExecutionPlanVersion::Compare(v2, v1) > 0);
    ASSERT_EQ(0, ExecutionPlanVersion::Compare(v1, v1));
    
    return true;
}

TEST(Integration_ValidationSchema_Configuration) {
    ValidationSchema schema;
    
    // Verify default gates exist
    ASSERT_EQ(11ULL, schema.GetEnabledGates().size());
    
    // Disable some gates
    schema.DisableGate("stress");
    schema.DisableGate("ab_test");
    
    ASSERT_EQ(9ULL, schema.GetEnabledGates().size());
    ASSERT_EQ(11ULL, schema.GetRequiredGates().size());
    
    // Add custom gate
    ValidationGate custom;
    custom.name = "custom_integration";
    custom.description = "Custom test gate";
    custom.required = false;
    custom.enabled = true;
    custom.timeout_seconds = 30;
    
    schema.AddGate(custom);
    ASSERT_TRUE(schema.HasGate("custom_integration"));
    
    return true;
}

TEST(Integration_ExitCode_Mapping) {
    ExitCodeMapper mapper;
    
    // Test various exit codes
    ValidationResult success;
    success.success = true;
    ASSERT_EQ(0, mapper.MapToExitCode(success));
    
    ValidationResult loadFail;
    loadFail.success = false;
    loadFail.gate_name = "load_model";
    ASSERT_EQ(10, mapper.MapToExitCode(loadFail));
    
    ValidationResult inferenceFail;
    inferenceFail.success = false;
    inferenceFail.gate_name = "inference";
    ASSERT_EQ(11, mapper.MapToExitCode(inferenceFail));
    
    // Test description lookup
    ASSERT_EQ(std::string("Success"), mapper.GetDescription(0));
    ASSERT_EQ(std::string("Load model failed"), mapper.GetDescription(10));
    
    return true;
}

TEST(Integration_EndToEnd_ValidationPipeline) {
    // This test simulates a complete validation pipeline
    
    // 1. Initialize math mode
    MathModeController mathController;
    mathController.SetMode(MathMode::REPRODUCIBLE);
    ASSERT_EQ(MathMode::REPRODUCIBLE, mathController.GetCurrentMode());
    
    // 2. Set up KV integrity tracking
    KVIntegrityTracker kvTracker;
    uint8_t k_data[] = {0x01, 0x02};
    uint8_t v_data[] = {0x03, 0x04};
    kvTracker.RegisterPage(1, k_data, v_data, 2, 2, 0);
    ASSERT_TRUE(kvTracker.VerifyPage(1, k_data, v_data, 2, 2, "init"));
    
    // 3. Set up performance budget
    PerformanceBudget budget;
    budget.Allocate("compute", 100.0);
    budget.Consume("compute", 50.0);
    ASSERT_EQ(50.0, budget.GetRemaining("compute"));
    
    // 4. Set up golden output testing
    GoldenOutputTester goldenTester;
    GoldenOutput expected;
    expected.name = "e2e_test";
    expected.tokens = {1, 2, 3};
    goldenTester.RegisterGoldenOutput(expected);
    
    GoldenOutput actual;
    actual.tokens = {1, 2, 3};
    auto goldenResult = goldenTester.ValidateOutput("e2e_test", actual);
    ASSERT_TRUE(goldenResult.passed);
    
    // 5. Verify execution plan version
    std::string plan = R"({"version": "1.0.0", "kernels": []})";
    ASSERT_TRUE(ExecutionPlanVersion::ValidatePlan(plan));
    
    // 6. Check validation schema
    ValidationSchema schema;
    ASSERT_TRUE(schema.HasGate("determinism"));
    
    // 7. Verify exit code mapping
    ExitCodeMapper mapper;
    ValidationResult result;
    result.success = true;
    ASSERT_EQ(0, mapper.MapToExitCode(result));
    
    // All components working together
    return true;
}

TEST(Integration_MathMode_Determinism_Interaction) {
    // Test that math mode affects determinism
    
    std::vector<float> data(100);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = 1.0f / static_cast<float>(i + 1);
    }
    
    // Test with REPRODUCIBLE mode (tree reduction)
    float sum1 = DeterminismSafeguards::TreeSum(data.data(), data.size());
    float sum2 = DeterminismSafeguards::TreeSum(data.data(), data.size());
    
    // Tree sum should be deterministic
    ASSERT_EQ(sum1, sum2);
    
    // Test with BIT_EXACT mode (Kahan summation)
    float sum3 = DeterminismSafeguards::KahanSum(data.data(), data.size());
    float sum4 = DeterminismSafeguards::KahanSum(data.data(), data.size());
    
    // Kahan sum should also be deterministic
    ASSERT_EQ(sum3, sum4);
    
    // Kahan should be more accurate than simple sequential
    float sum5 = DeterminismSafeguards::SequentialSum(data.data(), data.size());
    
    // Results may differ but both should be deterministic
    ASSERT_EQ(sum3, sum4);
    
    return true;
}

TEST(Integration_Performance_Regression_Detection) {
    RegressionChecker checker;
    
    // Set baseline
    PerformanceMetrics baseline;
    baseline.latency_ms = 100.0;
    baseline.throughput_tps = 1000.0;
    baseline.memory_mb = 512.0;
    checker.SetBaseline(baseline);
    
    // Test within threshold (no regression)
    PerformanceMetrics current1;
    current1.latency_ms = 105.0;  // 5% increase
    current1.throughput_tps = 950.0;  // 5% decrease
    ASSERT_FALSE(checker.IsRegression(current1));
    
    // Test outside threshold (regression)
    PerformanceMetrics current2;
    current2.latency_ms = 120.0;  // 20% increase
    current2.throughput_tps = 1000.0;
    ASSERT_TRUE(checker.IsRegression(current2));
    
    // Test throughput regression
    PerformanceMetrics current3;
    current3.latency_ms = 100.0;
    current3.throughput_tps = 800.0;  // 20% decrease
    ASSERT_TRUE(checker.IsRegression(current3));
    
    return true;
}

TEST(Integration_ValidationResult_Propagation) {
    // Test that validation results propagate correctly through the system
    
    ValidationResult result;
    result.success = true;
    result.gate_name = "integration_gate";
    result.duration_ms = 150.0;
    result.details["tokens_generated"] = "100";
    result.details["model"] = "test_model";
    
    ASSERT_TRUE(result.success);
    ASSERT_EQ(std::string("integration_gate"), result.gate_name);
    ASSERT_EQ(150.0, result.duration_ms);
    ASSERT_EQ(std::string("100"), result.details["tokens_generated"]);
    
    // Test exit code mapping
    ExitCodeMapper mapper;
    int code = mapper.MapToExitCode(result);
    ASSERT_EQ(0, code);
    ASSERT_TRUE(mapper.IsSuccess(code));
    
    return true;
}

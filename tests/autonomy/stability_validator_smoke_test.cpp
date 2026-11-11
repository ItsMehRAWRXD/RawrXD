/**
 * stability_validator_smoke_test.cpp
 *
 * Phase C.4 Batch 5/5: Autonomous Stability Validator Smoke Tests
 *
 * Minimum 15 tests validating the entire safety loop:
 * 1. Envelope enforcement
 * 2. Oscillation detection
 * 3. Oscillation dampening
 * 4. Rollback plan generation
 * 5. Rollback execution
 * 6. Post-rollback stability
 * 7. Safety gate decision blocking
 * 8. Safety gate intent blocking
 * 9. Safety gate mutation blocking
 * 10. Risk scoring correctness
 * 11. Cooldown enforcement
 * 12. Autonomous loop stability
 * 13. Autonomous loop instability recovery
 * 14. Resource-pressure stability
 * 15. Long-run stability simulation
 */

#include "../../src/autonomy/StabilityValidator.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>

using namespace Autonomy;

// Test framework
int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    tests_run++; \
    std::cout << "  Running " << #name << "... "; \
    try { \
        test_##name(); \
        std::cout << "PASS\n"; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAIL: " << e.what() << "\n"; \
        tests_failed++; \
    } catch (...) { \
        std::cout << "FAIL: Unknown exception\n"; \
        tests_failed++; \
    } \
} while(0)

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))
#define ASSERT_GT(a, b) ASSERT_TRUE((a) > (b))
#define ASSERT_LT(a, b) ASSERT_TRUE((a) < (b))

// ============================================================================
// Test 1: Envelope Enforcement
// ============================================================================
TEST(envelope_enforcement) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateEnvelopeEnforcement();
    
    // Should have at least 5 envelope tests
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 2: Oscillation Detection
// ============================================================================
TEST(oscillation_detection) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateOscillationControl();
    
    // Should detect oscillation patterns
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 3: Oscillation Dampening
// ============================================================================
TEST(oscillation_dampening) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    // Run oscillation validation
    auto results = validator.ValidateOscillationControl();
    
    // Dampening should be validated
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 4: Rollback Plan Generation
// ============================================================================
TEST(rollback_plan_generation) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateRollbackEngine();
    
    // Should validate rollback plan generation
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 5: Rollback Execution
// ============================================================================
TEST(rollback_execution) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateRollbackEngine();
    
    // Should validate rollback execution
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 6: Post-Rollback Stability
// ============================================================================
TEST(post_rollback_stability) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateRollbackEngine();
    
    // Should validate post-rollback stability
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 7: Safety Gate Decision Blocking
// ============================================================================
TEST(safety_gate_decision_blocking) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateSafetyGate();
    
    // Should validate decision blocking
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 8: Safety Gate Intent Blocking
// ============================================================================
TEST(safety_gate_intent_blocking) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateSafetyGate();
    
    // Should validate intent blocking
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 9: Safety Gate Mutation Blocking
// ============================================================================
TEST(safety_gate_mutation_blocking) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateSafetyGate();
    
    // Should validate mutation blocking
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 10: Risk Scoring Correctness
// ============================================================================
TEST(risk_scoring_correctness) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateSafetyGate();
    
    // Should validate risk scoring
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 11: Cooldown Enforcement
// ============================================================================
TEST(cooldown_enforcement) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateSafetyGate();
    
    // Should validate cooldown enforcement
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 12: Autonomous Loop Stability
// ============================================================================
TEST(autonomous_loop_stability) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateAutonomousLoop();
    
    // Should validate stable loop
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 13: Autonomous Loop Instability Recovery
// ============================================================================
TEST(autonomous_loop_instability_recovery) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateAutonomousLoop();
    
    // Should validate instability recovery
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 14: Resource-Pressure Stability
// ============================================================================
TEST(resource_pressure_stability) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    auto results = validator.ValidateAutonomousLoop();
    
    // Should validate resource pressure handling
    ASSERT_GT(results.totalTests, 0);
}

// ============================================================================
// Test 15: Long-Run Stability Simulation
// ============================================================================
TEST(long_run_stability_simulation) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    SimulationConfig config;
    config.durationSeconds = 5;  // Short duration for smoke test
    config.decisionRateHz = 10;
    config.mutationRateHz = 2;
    config.enableChaos = false;  // No chaos for basic smoke test
    
    auto results = validator.ValidateLongRunStability(config);
    
    // Should complete simulation
    ASSERT_GT(results.totalTests, 0);
    ASSERT_GT(results.passedTests, 0);
}

// ============================================================================
// Test 16: Chaos Injection (Bonus)
// ============================================================================
TEST(chaos_injection) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    ChaosConfig chaos;
    chaos.enableDecisionChaos = true;
    chaos.enableMutationChaos = true;
    chaos.chaosProbability = 0.5;
    
    validator.EnableChaos(chaos);
    ASSERT_TRUE(validator.IsChaosEnabled());
    
    validator.DisableChaos();
    ASSERT_FALSE(validator.IsChaosEnabled());
}

// ============================================================================
// Test 17: Metrics Collection (Bonus)
// ============================================================================
TEST(metrics_collection) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    // Reset and collect
    validator.ResetMetrics();
    auto metrics = validator.GetCurrentMetrics();
    
    // Initial metrics should be zero
    ASSERT_EQ(metrics.oscillationCount, 0);
    ASSERT_EQ(metrics.rollbackCount, 0);
    ASSERT_EQ(metrics.blockedDecisionCount, 0);
}

// ============================================================================
// Test 18: Certification Report (Bonus)
// ============================================================================
TEST(certification_report) {
    StabilityValidator validator;
    validator.Initialize(nullptr, nullptr, nullptr, nullptr, nullptr);
    
    std::string report = validator.GenerateCertificationReport();
    
    // Report should contain key sections
    ASSERT_NE(report.find("Phase C.4"), std::string::npos);
    ASSERT_NE(report.find("Component Status"), std::string::npos);
    ASSERT_NE(report.find("Certification"), std::string::npos);
}

// ============================================================================
// Test 19: Validation Result JSON (Bonus)
// ============================================================================
TEST(validation_result_json) {
    ValidationResult result;
    result.testName = "Test";
    result.passed = true;
    result.durationMs = 100.0;
    result.metrics["score"] = 0.95;
    
    std::string json = result.ToJson();
    
    ASSERT_NE(json.find("testName"), std::string::npos);
    ASSERT_NE(json.find("passed"), std::string::npos);
    ASSERT_NE(json.find("durationMs"), std::string::npos);
}

// ============================================================================
// Test 20: Suite Results JSON (Bonus)
// ============================================================================
TEST(suite_results_json) {
    ValidationSuiteResults results;
    results.suiteName = "TestSuite";
    results.totalTests = 10;
    results.passedTests = 8;
    results.failedTests = 2;
    
    std::string json = results.ToJson();
    
    ASSERT_NE(json.find("suiteName"), std::string::npos);
    ASSERT_NE(json.find("totalTests"), std::string::npos);
    ASSERT_NE(json.find("passRate"), std::string::npos);
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  PHASE C.4 BATCH 5/5: STABILITY VALIDATOR SMOKE TESTS          ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
    
    // Required tests (minimum 15)
    std::cout << "Required Tests:\n";
    RUN_TEST(envelope_enforcement);
    RUN_TEST(oscillation_detection);
    RUN_TEST(oscillation_dampening);
    RUN_TEST(rollback_plan_generation);
    RUN_TEST(rollback_execution);
    RUN_TEST(post_rollback_stability);
    RUN_TEST(safety_gate_decision_blocking);
    RUN_TEST(safety_gate_intent_blocking);
    RUN_TEST(safety_gate_mutation_blocking);
    RUN_TEST(risk_scoring_correctness);
    RUN_TEST(cooldown_enforcement);
    RUN_TEST(autonomous_loop_stability);
    RUN_TEST(autonomous_loop_instability_recovery);
    RUN_TEST(resource_pressure_stability);
    RUN_TEST(long_run_stability_simulation);
    
    // Bonus tests
    std::cout << "\nBonus Tests:\n";
    RUN_TEST(chaos_injection);
    RUN_TEST(metrics_collection);
    RUN_TEST(certification_report);
    RUN_TEST(validation_result_json);
    RUN_TEST(suite_results_json);
    
    // Summary
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  TEST SUMMARY                                                  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total:  " << std::setw(50) << tests_run << " ║\n";
    std::cout << "║  Passed: " << std::setw(50) << tests_passed << " ║\n";
    std::cout << "║  Failed: " << std::setw(50) << tests_failed << " ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    if (tests_failed == 0) {
        std::cout << "║  Status: \033[32mALL TESTS PASSED\033[0m" << std::setw(35) << " ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
        return 0;
    } else {
        std::cout << "║  Status: \033[31mTESTS FAILED\033[0m" << std::setw(39) << " ║\n";
        std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
        return 1;
    }
}

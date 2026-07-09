/**
 * @file fused_gemm_validator_test.cpp
 * @brief RawrXD L4.2.3 Fused GEMM Reference Validation Tests
 *
 * Numerical correctness gates for fused kernels.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <vector>
#include <random>
#include <cmath>
#include <cstring>

#include "../kernels/fused_gemm_validator.h"

using namespace rawrxd;
using namespace rawrxd::validation;
using namespace rawrxd::compression;

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

// ============================================================================
// Test Cases
// ============================================================================

bool Test_CosineSimilarity_Calculation() {
    float a[] = {1.0f, 2.0f, 3.0f};
    float b[] = {1.0f, 2.0f, 3.0f};
    
    float cosine = NumericalComparison::CosineSimilarity(a, b, 3);
    
    // Perfect match should be 1.0
    return std::abs(cosine - 1.0f) < 0.0001f;
}

bool Test_CosineSimilarity_Orthogonal() {
    float a[] = {1.0f, 0.0f, 0.0f};
    float b[] = {0.0f, 1.0f, 0.0f};
    
    float cosine = NumericalComparison::CosineSimilarity(a, b, 3);
    
    // Orthogonal vectors should have cosine 0
    return std::abs(cosine) < 0.0001f;
}

bool Test_RMSE_Calculation() {
    float ref[] = {1.0f, 2.0f, 3.0f};
    float test[] = {1.1f, 2.1f, 3.1f};
    
    float rmse = NumericalComparison::RMSE(ref, test, 3);
    
    // Expected: sqrt((0.01 + 0.01 + 0.01) / 3) = sqrt(0.01) = 0.1
    return std::abs(rmse - 0.1f) < 0.0001f;
}

bool Test_RMSE_ZeroError() {
    float ref[] = {1.0f, 2.0f, 3.0f};
    float test[] = {1.0f, 2.0f, 3.0f};
    
    float rmse = NumericalComparison::RMSE(ref, test, 3);
    
    return std::abs(rmse) < 0.0001f;
}

bool Test_RelativeError_Calculation() {
    float ref[] = {10.0f, 20.0f, 30.0f};
    float test[] = {11.0f, 21.0f, 31.0f};
    
    float rel_error = NumericalComparison::RelativeError(ref, test, 3);
    
    // Total error = 3.0, total ref = 60.0, rel_error = 0.05
    return std::abs(rel_error - 0.05f) < 0.0001f;
}

bool Test_CountOutliers() {
    float ref[] = {1.0f, 2.0f, 3.0f, 4.0f, 100.0f};  // 100 is an outlier
    float test[] = {1.0f, 2.0f, 3.0f, 4.0f, 4.0f};
    
    size_t outliers = NumericalComparison::CountOutliers(ref, test, 5, 2.0f);
    
    return outliers == 1;
}

bool Test_CountSignMismatches() {
    float ref[] = {1.0f, -2.0f, 3.0f, -4.0f};
    float test[] = {1.0f, 2.0f, 3.0f, -4.0f};  // -2.0 vs 2.0 is a sign mismatch
    
    size_t mismatches = NumericalComparison::CountSignMismatches(ref, test, 4);
    
    return mismatches == 1;
}

bool Test_CountNearZeroMismatches() {
    float ref[] = {0.0001f, 1.0f, 0.0001f, 2.0f};  // Near zero
    float test[] = {1.0f, 1.0f, 2.0f, 2.0f};       // Not near zero
    
    size_t mismatches = NumericalComparison::CountNearZeroMismatches(ref, test, 4, 0.001f);
    
    return mismatches == 2;
}

bool Test_ReferenceGemm_FP32() {
    const size_t ROWS = 4;
    const size_t COLS = 4;
    
    float weights[ROWS * COLS] = {
        1.0f, 2.0f, 3.0f, 4.0f,
        5.0f, 6.0f, 7.0f, 8.0f,
        9.0f, 10.0f, 11.0f, 12.0f,
        13.0f, 14.0f, 15.0f, 16.0f
    };
    float input[COLS] = {1.0f, 1.0f, 1.0f, 1.0f};
    float output[ROWS];
    
    ReferenceGemm::GemvFP32(weights, input, output, ROWS, COLS);
    
    // Expected: row sums = {10, 26, 42, 58}
    float expected[] = {10.0f, 26.0f, 42.0f, 58.0f};
    
    for (size_t i = 0; i < ROWS; i++) {
        if (std::abs(output[i] - expected[i]) > 0.0001f) {
            return false;
        }
    }
    return true;
}

bool Test_ReferenceGemm_HighPrecision() {
    const size_t ROWS = 4;
    const size_t COLS = 4;
    
    float weights[ROWS * COLS] = {
        1.0f, 2.0f, 3.0f, 4.0f,
        5.0f, 6.0f, 7.0f, 8.0f,
        9.0f, 10.0f, 11.0f, 12.0f,
        13.0f, 14.0f, 15.0f, 16.0f
    };
    float input[COLS] = {1.0f, 1.0f, 1.0f, 1.0f};
    double output[ROWS];
    
    ReferenceGemm::GemvHighPrecision(weights, input, output, ROWS, COLS);
    
    // Expected: row sums = {10, 26, 42, 58}
    double expected[] = {10.0, 26.0, 42.0, 58.0};
    
    for (size_t i = 0; i < ROWS; i++) {
        if (std::abs(output[i] - expected[i]) > 0.0001) {
            return false;
        }
    }
    return true;
}

bool Test_ValidationGates_Production() {
    // Production gates should be strict
    return ValidationGates::PRODUCTION_COSINE >= 0.9999f &&
           ValidationGates::PRODUCTION_RMSE <= 0.001f;
}

bool Test_ValidationGates_Standard() {
    // Standard gates should be less strict than production
    return ValidationGates::STANDARD_COSINE >= 0.999f &&
           ValidationGates::STANDARD_RMSE <= 0.01f &&
           ValidationGates::STANDARD_COSINE <= ValidationGates::PRODUCTION_COSINE;
}

bool Test_FusedGemmValidator_DefaultThresholds() {
    FusedGemmValidator validator;
    
    // Default should be STANDARD
    return validator.CheckCosine(0.9995f) &&  // Above STANDARD
           !validator.CheckCosine(0.99f);      // Below STANDARD
}

bool Test_FusedGemmValidator_SetThresholds() {
    FusedGemmValidator validator;
    validator.SetCosineThreshold(0.99f);
    
    return validator.CheckCosine(0.995f) &&
           !validator.CheckCosine(0.98f);
}

bool Test_FusedValidationReport_Comparison() {
    FusedValidationReport report1;
    report1.cosine_similarity = 0.9999f;
    report1.rmse = 0.001f;
    report1.passed = true;
    
    FusedValidationReport report2;
    report2.cosine_similarity = 0.9999f;
    report2.rmse = 0.001f;
    report2.passed = true;
    
    return report1 == report2;
}

bool Test_ValidationSuite_SmokeTest() {
    return ValidationSuite::RunSmokeTest();
}

bool Test_Q4_0_Validation() {
    const size_t ROWS = 64;
    const size_t COLS = 256;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    FusedGemmValidator validator;
    auto report = validator.ValidateQ4_0(weights.data(), input.data(), ROWS, COLS);
    
    return report.passed && report.cosine_similarity >= ValidationGates::Q4_0_COSINE;
}

bool Test_Q8_0_Validation() {
    const size_t ROWS = 64;
    const size_t COLS = 256;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    FusedGemmValidator validator;
    auto report = validator.ValidateQ8_0(weights.data(), input.data(), ROWS, COLS);
    
    return report.passed && report.cosine_similarity >= ValidationGates::Q8_0_COSINE;
}

bool Test_ProductionValidation() {
    const size_t ROWS = 128;
    const size_t COLS = 512;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    FusedGemmValidator validator;
    auto report = validator.ProductionValidate(
        CompressionType::Q4_0,
        weights.data(), input.data(), ROWS, COLS
    );
    
    return report.passed && 
           report.cosine_similarity >= ValidationGates::PRODUCTION_COSINE &&
           report.rmse <= ValidationGates::PRODUCTION_RMSE;
}

bool Test_EdgeCase_Zeros() {
    const size_t ROWS = 32;
    const size_t COLS = 128;
    
    std::vector<float> weights(ROWS * COLS, 0.0f);
    std::vector<float> input(COLS, 0.0f);
    
    FusedGemmValidator validator;
    auto report = validator.ValidateEdgeCases(CompressionType::Q4_0, ROWS, COLS);
    
    // Should pass (all zeros should produce all zeros)
    return report.passed;
}

bool Test_EdgeCase_LargeValues() {
    const size_t ROWS = 32;
    const size_t COLS = 128;
    
    std::vector<float> weights(ROWS * COLS, 10.0f);
    std::vector<float> input(COLS, 10.0f);
    
    FusedGemmValidator validator;
    auto report = validator.ValidateEdgeCases(CompressionType::Q4_0, ROWS, COLS);
    
    // Large values may have higher error but should still pass
    return report.cosine_similarity >= ValidationGates::STANDARD_COSINE;
}

bool Test_StressTest() {
    const size_t ROWS = 64;
    const size_t COLS = 256;
    
    FusedGemmValidator validator;
    auto report = validator.StressTest(CompressionType::Q4_0, ROWS, COLS);
    
    // Stress test should complete and show speedup
    return report.passed && report.speedup > 1.0f;
}

bool Test_ValidateDistributions() {
    const size_t ROWS = 64;
    const size_t COLS = 256;
    
    FusedGemmValidator validator;
    auto report = validator.ValidateDistributions(CompressionType::Q4_0, ROWS, COLS);
    
    return report.passed;
}

bool Test_QuickValidate() {
    const size_t ROWS = 32;
    const size_t COLS = 128;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    FusedGemmValidator validator;
    
    return validator.QuickValidate(CompressionType::Q4_0, weights.data(), input.data(), ROWS, COLS);
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    std::cout << "RawrXD L4.2.3 Fused GEMM Reference Validation Tests\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n\n";
    
    TestReporter::Reset();
    
    // Numerical Comparison Tests
    std::cout << "Numerical Comparison Tests:\n";
    TestReporter::Report("CosineSimilarity_Calculation", Test_CosineSimilarity_Calculation());
    TestReporter::Report("CosineSimilarity_Orthogonal", Test_CosineSimilarity_Orthogonal());
    TestReporter::Report("RMSE_Calculation", Test_RMSE_Calculation());
    TestReporter::Report("RMSE_ZeroError", Test_RMSE_ZeroError());
    TestReporter::Report("RelativeError_Calculation", Test_RelativeError_Calculation());
    TestReporter::Report("CountOutliers", Test_CountOutliers());
    TestReporter::Report("CountSignMismatches", Test_CountSignMismatches());
    TestReporter::Report("CountNearZeroMismatches", Test_CountNearZeroMismatches());
    
    // Reference GEMM Tests
    std::cout << "\nReference GEMM Tests:\n";
    TestReporter::Report("ReferenceGemm_FP32", Test_ReferenceGemm_FP32());
    TestReporter::Report("ReferenceGemm_HighPrecision", Test_ReferenceGemm_HighPrecision());
    
    // Validation Gates Tests
    std::cout << "\nValidation Gates Tests:\n";
    TestReporter::Report("ValidationGates_Production", Test_ValidationGates_Production());
    TestReporter::Report("ValidationGates_Standard", Test_ValidationGates_Standard());
    
    // Validator Tests
    std::cout << "\nValidator Tests:\n";
    TestReporter::Report("FusedGemmValidator_DefaultThresholds", Test_FusedGemmValidator_DefaultThresholds());
    TestReporter::Report("FusedGemmValidator_SetThresholds", Test_FusedGemmValidator_SetThresholds());
    TestReporter::Report("FusedValidationReport_Comparison", Test_FusedValidationReport_Comparison());
    
    // Integration Tests
    std::cout << "\nIntegration Tests:\n";
    TestReporter::Report("ValidationSuite_SmokeTest", Test_ValidationSuite_SmokeTest());
    TestReporter::Report("Q4_0_Validation", Test_Q4_0_Validation());
    TestReporter::Report("Q8_0_Validation", Test_Q8_0_Validation());
    TestReporter::Report("ProductionValidation", Test_ProductionValidation());
    TestReporter::Report("EdgeCase_Zeros", Test_EdgeCase_Zeros());
    TestReporter::Report("EdgeCase_LargeValues", Test_EdgeCase_LargeValues());
    TestReporter::Report("StressTest", Test_StressTest());
    TestReporter::Report("ValidateDistributions", Test_ValidateDistributions());
    TestReporter::Report("QuickValidate", Test_QuickValidate());
    
    TestReporter::PrintSummary();
    
    return TestReporter::tests_failed_ > 0 ? 1 : 0;
}

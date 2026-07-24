//============================================================================
// test_math_mode.hpp
// RawrXD N-EVM - Math Mode Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_math_mode.hpp"

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Math Mode Tests
//============================================================================

TestResult MathModeTests_FastConfiguration() {
    auto config = MathModeController::GetConfiguration(MathMode::Fast);
    
    TEST_ASSERT_EQ(true, config.fma_enabled);
    TEST_ASSERT_EQ(true, config.parallel_reduction);
    TEST_ASSERT_EQ(false, config.tree_reduction);
    TEST_ASSERT_EQ(false, config.kahan_summation);
    
    TEST_SUCCESS();
}

TestResult MathModeTests_ReproducibleConfiguration() {
    auto config = MathModeController::GetConfiguration(MathMode::Reproducible);
    
    TEST_ASSERT_EQ(false, config.fma_enabled);
    TEST_ASSERT_EQ(true, config.parallel_reduction);
    TEST_ASSERT_EQ(true, config.tree_reduction);
    TEST_ASSERT_EQ(false, config.kahan_summation);
    
    TEST_SUCCESS();
}

TestResult MathModeTests_BitExactConfiguration() {
    auto config = MathModeController::GetConfiguration(MathMode::BitExact);
    
    TEST_ASSERT_EQ(false, config.fma_enabled);
    TEST_ASSERT_EQ(false, config.parallel_reduction);
    TEST_ASSERT_EQ(false, config.tree_reduction);
    TEST_ASSERT_EQ(true, config.kahan_summation);
    
    TEST_SUCCESS();
}

TestResult MathModeTests_OptimizationTax() {
    // Fast -> Reproducible should be ~3.2%
    float tax1 = MathModeController::GetOptimizationTax(MathMode::Fast, MathMode::Reproducible);
    TEST_ASSERT_NEAR(3.2f, tax1, 0.1f);
    
    // Reproducible -> BitExact should be ~5.3%
    float tax2 = MathModeController::GetOptimizationTax(MathMode::Reproducible, MathMode::BitExact);
    TEST_ASSERT_NEAR(5.3f, tax2, 0.1f);
    
    // Same mode should be 0%
    float tax3 = MathModeController::GetOptimizationTax(MathMode::Fast, MathMode::Fast);
    TEST_ASSERT_EQ(0.0f, tax3);
    
    TEST_SUCCESS();
}

TestResult MathModeTests_StringConversion() {
    auto config = MathModeController::GetConfiguration(MathMode::Fast);
    TEST_ASSERT_EQ(std::string("Fast"), config.ToString());
    
    config = MathModeController::GetConfiguration(MathMode::Reproducible);
    TEST_ASSERT_EQ(std::string("Reproducible"), config.ToString());
    
    config = MathModeController::GetConfiguration(MathMode::BitExact);
    TEST_ASSERT_EQ(std::string("BitExact"), config.ToString());
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterMathModeTests(TestFramework& framework) {
    REGISTER_TEST(framework, MathModeTests, FastConfiguration);
    REGISTER_TEST(framework, MathModeTests, ReproducibleConfiguration);
    REGISTER_TEST(framework, MathModeTests, BitExactConfiguration);
    REGISTER_TEST(framework, MathModeTests, OptimizationTax);
    REGISTER_TEST(framework, MathModeTests, StringConversion);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD

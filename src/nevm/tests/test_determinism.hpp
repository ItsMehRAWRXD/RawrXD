//============================================================================
// test_determinism.hpp
// RawrXD N-EVM - Determinism Safeguards Unit Tests
//============================================================================

#pragma once

#include "test_framework.hpp"
#include "../nevm_determinism_safeguards.hpp"
#include <vector>

namespace RawrXD {
namespace NEVM {
namespace Tests {

//============================================================================
// Determinism Tests
//============================================================================

TestResult DeterminismTests_TreeSumBasic() {
    std::vector<float> data = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float result = DeterministicReduction::TreeSum(data.data(), data.size());
    
    TEST_ASSERT_NEAR(15.0f, result, 0.0001f);
    TEST_SUCCESS();
}

TestResult DeterminismTests_TreeSumEmpty() {
    std::vector<float> data;
    float result = DeterministicReduction::TreeSum(data.data(), data.size());
    
    TEST_ASSERT_EQ(0.0f, result);
    TEST_SUCCESS();
}

TestResult DeterminismTests_TreeSumSingle() {
    std::vector<float> data = {42.0f};
    float result = DeterministicReduction::TreeSum(data.data(), data.size());
    
    TEST_ASSERT_EQ(42.0f, result);
    TEST_SUCCESS();
}

TestResult DeterminismTests_KahanSumPrecision() {
    // Kahan summation should be more precise for large sums with small values
    std::vector<float> data(10000, 0.0001f);
    
    float kahan = DeterministicReduction::KahanSum(data.data(), data.size());
    float sequential = DeterministicReduction::SequentialSum(data.data(), data.size());
    
    // Kahan should be closer to true value (1.0)
    TEST_ASSERT_NEAR(1.0f, kahan, 0.001f);
    TEST_SUCCESS();
}

TestResult DeterminismTests_SoftMaxBasic() {
    std::vector<float> input = {1.0f, 2.0f, 3.0f};
    std::vector<float> output(3);
    
    DeterministicSoftMax::Compute(input.data(), output.data(), input.size());
    
    // Softmax outputs should sum to 1
    float sum = output[0] + output[1] + output[2];
    TEST_ASSERT_NEAR(1.0f, sum, 0.0001f);
    
    // Largest input should have largest output
    TEST_ASSERT(output[2] > output[1]);
    TEST_ASSERT(output[1] > output[0]);
    
    TEST_SUCCESS();
}

TestResult DeterminismTests_SoftMaxKahan() {
    std::vector<float> input = {1.0f, 2.0f, 3.0f};
    std::vector<float> output1(3);
    std::vector<float> output2(3);
    
    DeterministicSoftMax::Compute(input.data(), output1.data(), input.size());
    DeterministicSoftMax::ComputeKahan(input.data(), output2.data(), input.size());
    
    // Both methods should produce similar results
    for (size_t i = 0; i < 3; ++i) {
        TEST_ASSERT_NEAR(output1[i], output2[i], 0.0001f);
    }
    
    TEST_SUCCESS();
}

TestResult DeterminismTests_GEMMBasic() {
    // A[2x3] * B[3x2] = C[2x2]
    std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};  // 2x3
    std::vector<float> B = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};  // 3x2
    std::vector<float> C(4);  // 2x2
    
    DeterministicGEMM::Multiply(A.data(), B.data(), C.data(), 2, 2, 3, false);
    
    // C[0,0] = 1*1 + 2*3 + 3*5 = 1 + 6 + 15 = 22
    TEST_ASSERT_NEAR(22.0f, C[0], 0.0001f);
    
    // C[0,1] = 1*2 + 2*4 + 3*6 = 2 + 8 + 18 = 28
    TEST_ASSERT_NEAR(28.0f, C[1], 0.0001f);
    
    TEST_SUCCESS();
}

TestResult DeterminismTests_GEMMKahan() {
    // Same test with Kahan summation
    std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    std::vector<float> B = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    std::vector<float> C1(4);
    std::vector<float> C2(4);
    
    DeterministicGEMM::Multiply(A.data(), B.data(), C1.data(), 2, 2, 3, false);
    DeterministicGEMM::Multiply(A.data(), B.data(), C2.data(), 2, 2, 3, true);
    
    // Results should be very close
    for (size_t i = 0; i < 4; ++i) {
        TEST_ASSERT_NEAR(C1[i], C2[i], 0.0001f);
    }
    
    TEST_SUCCESS();
}

//============================================================================
// Registration
//============================================================================

void RegisterDeterminismTests(TestFramework& framework) {
    REGISTER_TEST(framework, DeterminismTests, TreeSumBasic);
    REGISTER_TEST(framework, DeterminismTests, TreeSumEmpty);
    REGISTER_TEST(framework, DeterminismTests, TreeSumSingle);
    REGISTER_TEST(framework, DeterminismTests, KahanSumPrecision);
    REGISTER_TEST(framework, DeterminismTests, SoftMaxBasic);
    REGISTER_TEST(framework, DeterminismTests, SoftMaxKahan);
    REGISTER_TEST(framework, DeterminismTests, GEMMBasic);
    REGISTER_TEST(framework, DeterminismTests, GEMMKahan);
}

} // namespace Tests
} // namespace NEVM
} // namespace RawrXD

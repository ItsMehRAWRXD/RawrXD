//============================================================================
// test_determinism.cpp
// RawrXD N-EVM - Unit Tests for Determinism Safeguards
//============================================================================

#include "../nevm_determinism_safeguards.hpp"
#include <math>

using namespace RawrXD::NEVM;

TEST(DeterministicReduction_TreeSum) {
    // Test with simple array
    float data[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float result = DeterministicReduction::TreeSum(data, 5);
    ASSERT_NEAR(15.0f, result, 0.0001f);
    
    // Test with powers of 2 (optimal for tree reduction)
    float data2[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float result2 = DeterministicReduction::TreeSum(data2, 4);
    ASSERT_NEAR(10.0f, result2, 0.0001f);
    
    // Test with single element
    float data3[] = {42.0f};
    float result3 = DeterministicReduction::TreeSum(data3, 1);
    ASSERT_NEAR(42.0f, result3, 0.0001f);
    
    // Test with empty array
    float result4 = DeterministicReduction::TreeSum(nullptr, 0);
    ASSERT_NEAR(0.0f, result4, 0.0001f);
    
    return true;
}

TEST(DeterministicReduction_KahanSum) {
    // Test with simple array
    float data[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float result = DeterministicReduction::KahanSum(data, 5);
    ASSERT_NEAR(15.0f, result, 0.0001f);
    
    // Test with values that would lose precision in naive summation
    float data2[] = {1.0f, 1e-8f, 1e-8f, 1e-8f, 1e-8f};
    float result2 = DeterministicReduction::KahanSum(data2, 5);
    ASSERT_NEAR(1.00000004f, result2, 0.0000001f);
    
    return true;
}

TEST(DeterministicReduction_SequentialSum) {
    // Test with simple array
    float data[] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    float result = DeterministicReduction::SequentialSum(data, 5);
    ASSERT_NEAR(15.0f, result, 0.0001f);
    
    // Sequential sum should match expected value
    float data2[] = {0.1f, 0.2f, 0.3f};
    float result2 = DeterministicReduction::SequentialSum(data2, 3);
    ASSERT_NEAR(0.6f, result2, 0.0001f);
    
    return true;
}

TEST(DeterministicReduction_Consistency) {
    // Tree sum should be deterministic (same result every time)
    float data[] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    
    float result1 = DeterministicReduction::TreeSum(data, 8);
    float result2 = DeterministicReduction::TreeSum(data, 8);
    float result3 = DeterministicReduction::TreeSum(data, 8);
    
    ASSERT_EQ(result1, result2);
    ASSERT_EQ(result2, result3);
    
    return true;
}

TEST(DeterministicSoftMax_Basic) {
    float input[] = {1.0f, 2.0f, 3.0f};
    float output[3];
    
    DeterministicSoftMax::Compute(input, output, 3);
    
    // Check probabilities sum to 1
    float sum = output[0] + output[1] + output[2];
    ASSERT_NEAR(1.0f, sum, 0.0001f);
    
    // Check ordering is preserved (higher input = higher output)
    ASSERT_LT(output[0], output[1]);
    ASSERT_LT(output[1], output[2]);
    
    // All outputs should be positive
    ASSERT_GT(output[0], 0.0f);
    ASSERT_GT(output[1], 0.0f);
    ASSERT_GT(output[2], 0.0f);
    
    return true;
}

TEST(DeterministicSoftMax_Kahan) {
    float input[] = {1.0f, 2.0f, 3.0f};
    float output[3];
    
    DeterministicSoftMax::ComputeKahan(input, output, 3);
    
    // Check probabilities sum to 1
    float sum = output[0] + output[1] + output[2];
    ASSERT_NEAR(1.0f, sum, 0.0001f);
    
    return true;
}

TEST(DeterministicSoftMax_LargeValues) {
    // Test with large values that could overflow
    float input[] = {100.0f, 101.0f, 102.0f};
    float output[3];
    
    DeterministicSoftMax::Compute(input, output, 3);
    
    // Should not produce NaN or Inf
    ASSERT_FALSE(std::isnan(output[0]));
    ASSERT_FALSE(std::isnan(output[1]));
    ASSERT_FALSE(std::isnan(output[2]));
    ASSERT_FALSE(std::isinf(output[0]));
    ASSERT_FALSE(std::isinf(output[1]));
    ASSERT_FALSE(std::isinf(output[2]));
    
    // Should still sum to 1
    float sum = output[0] + output[1] + output[2];
    ASSERT_NEAR(1.0f, sum, 0.0001f);
    
    return true;
}

TEST(DeterministicGEMM_Basic) {
    // A = [1 2; 3 4], B = [5 6; 7 8]
    // C = A * B = [19 22; 43 50]
    float A[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float B[] = {5.0f, 6.0f, 7.0f, 8.0f};
    float C[4];
    
    DeterministicGEMM::Multiply(A, B, C, 2, 2, 2, false);
    
    ASSERT_NEAR(19.0f, C[0], 0.0001f);
    ASSERT_NEAR(22.0f, C[1], 0.0001f);
    ASSERT_NEAR(43.0f, C[2], 0.0001f);
    ASSERT_NEAR(50.0f, C[3], 0.0001f);
    
    return true;
}

TEST(DeterministicGEMM_Kahan) {
    // Same test with Kahan summation
    float A[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float B[] = {5.0f, 6.0f, 7.0f, 8.0f};
    float C[4];
    
    DeterministicGEMM::Multiply(A, B, C, 2, 2, 2, true);
    
    ASSERT_NEAR(19.0f, C[0], 0.0001f);
    ASSERT_NEAR(22.0f, C[1], 0.0001f);
    ASSERT_NEAR(43.0f, C[2], 0.0001f);
    ASSERT_NEAR(50.0f, C[3], 0.0001f);
    
    return true;
}

TEST(DeterministicGEMM_Identity) {
    // Multiplying by identity should return original
    float A[] = {1.0f, 2.0f, 3.0f, 4.0f};
    float I[] = {1.0f, 0.0f, 0.0f, 1.0f};
    float C[4];
    
    DeterministicGEMM::Multiply(A, I, C, 2, 2, 2, false);
    
    ASSERT_NEAR(A[0], C[0], 0.0001f);
    ASSERT_NEAR(A[1], C[1], 0.0001f);
    ASSERT_NEAR(A[2], C[2], 0.0001f);
    ASSERT_NEAR(A[3], C[3], 0.0001f);
    
    return true;
}

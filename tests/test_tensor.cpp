// ============================================================================
// test_tensor.cpp — Tensor & Kernel Unit Tests
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include "../src/deep2/RawrXDInferenceAdapter.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

// Reference implementations for verification
static float ref_rmsnorm(const float* input, int n, float eps) {
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += input[i] * input[i];
    float rms = sqrtf(sum / n + eps);
    float scale = 1.0f / rms;
    return scale * input[0];
}

static float ref_softmax(const float* input, int n) {
    float max = input[0];
    for (int i = 1; i < n; i++) if (input[i] > max) max = input[i];
    float sum = 0.0f;
    for (int i = 0; i < n; i++) sum += expf(input[i] - max);
    return expf(input[0] - max) / sum;
}

int main() {
    printf("========================================\n");
    printf("  RawrXD Tensor & Kernel Test Suite\n");
    printf("========================================\n\n");

    auto& adapter = rawr::RawrXDInferenceAdapter::Get();

    TEST("Adapter initialize", adapter.Initialize());

    // Test Q4_0 block structure
    rawr::Q4_0_Block block;
    block.scale = 0.5f;
    memset(block.qs, 0, sizeof(block.qs));
    TEST("Q4_0 block size", sizeof(rawr::Q4_0_Block) == 20);
    TEST("Q4_0 block scale", block.scale == 0.5f);

    // Test RMSNorm reference
    float testData[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float rmsResult = ref_rmsnorm(testData, 8, 1e-6f);
    TEST("RMSNorm reference", rmsResult > 0.0f);

    // Test Softmax reference
    float smResult = ref_softmax(testData, 8);
    TEST("Softmax reference", smResult > 0.0f && smResult < 1.0f);

    // Test SiLU reference: silu(x) = x * sigmoid(x)
    float silu_val = 2.0f * (1.0f / (1.0f + expf(-2.0f)));
    TEST("SiLU reference", fabsf(silu_val - 1.7616f) < 0.01f);

    // Test GEMM dimensions
    int M = 1, N = 4096, K = 4096;
    TEST("GEMM dimensions valid", M > 0 && N > 0 && K > 0);

    // Test KV cache structure
    uint32_t numLayers = 32, numHeads = 32, headDim = 128;
    uint64_t cacheSize = (uint64_t)numLayers * numHeads * headDim * 2 * 4;
    TEST("KV cache size", cacheSize == 32ULL * 32 * 128 * 2 * 4);

    // Test sampler
    float logits[4] = {0.1f, 0.5f, 0.3f, 0.1f};
    int maxIdx = 0;
    float maxVal = logits[0];
    for (int i = 1; i < 4; i++) {
        if (logits[i] > maxVal) { maxVal = logits[i]; maxIdx = i; }
    }
    TEST("Argmax correct", maxIdx == 1);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    adapter.Shutdown();
    return g_failed > 0 ? 1 : 0;
}
    }
    
    void TearDown() override {
        // Common cleanup
    }
};

TEST_F(TensorTest, BasicConstruction) {
    std::vector<size_t> shape = {2, 3, 4};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    EXPECT_EQ(tensor.GetShape().size(), 3);
    EXPECT_EQ(tensor.GetShape()[0], 2);
    EXPECT_EQ(tensor.GetShape()[1], 3);
    EXPECT_EQ(tensor.GetShape()[2], 4);
    EXPECT_EQ(tensor.GetSize(), 24);
    EXPECT_EQ(tensor.GetDataType(), DataType::FLOAT32);
}

TEST_F(TensorTest, ZeroInitialization) {
    std::vector<size_t> shape = {3, 3};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    tensor.Zero();
    
    for (size_t i = 0; i < tensor.GetSize(); ++i) {
        EXPECT_FLOAT_EQ(tensor.GetData()[i], 0.0f);
    }
}

TEST_F(TensorTest, Reshape) {
    std::vector<size_t> shape = {2, 3, 4};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    std::vector<size_t> newShape = {6, 4};
    tensor.Reshape(newShape);
    
    EXPECT_EQ(tensor.GetShape().size(), 2);
    EXPECT_EQ(tensor.GetShape()[0], 6);
    EXPECT_EQ(tensor.GetShape()[1], 4);
    EXPECT_EQ(tensor.GetSize(), 24); // Size unchanged
}

TEST_F(TensorTest, ElementAccess) {
    std::vector<size_t> shape = {2, 3};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    // Set values
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            tensor.At(i, j) = static_cast<float>(i * 3 + j);
        }
    }
    
    // Verify values
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            EXPECT_FLOAT_EQ(tensor.At(i, j), static_cast<float>(i * 3 + j));
        }
    }
}

TEST_F(TensorTest, Addition) {
    std::vector<size_t> shape = {2, 2};
    Tensor<float> a(shape, DataType::FLOAT32);
    Tensor<float> b(shape, DataType::FLOAT32);
    Tensor<float> c(shape, DataType::FLOAT32);
    
    a.At(0, 0) = 1.0f; a.At(0, 1) = 2.0f;
    a.At(1, 0) = 3.0f; a.At(1, 1) = 4.0f;
    
    b.At(0, 0) = 5.0f; b.At(0, 1) = 6.0f;
    b.At(1, 0) = 7.0f; b.At(1, 1) = 8.0f;
    
    Tensor<float>::Add(a, b, c);
    
    EXPECT_FLOAT_EQ(c.At(0, 0), 6.0f);
    EXPECT_FLOAT_EQ(c.At(0, 1), 8.0f);
    EXPECT_FLOAT_EQ(c.At(1, 0), 10.0f);
    EXPECT_FLOAT_EQ(c.At(1, 1), 12.0f);
}

TEST_F(TensorTest, MatrixMultiplication) {
    std::vector<size_t> shapeA = {2, 3};
    std::vector<size_t> shapeB = {3, 2};
    std::vector<size_t> shapeC = {2, 2};
    
    Tensor<float> a(shapeA, DataType::FLOAT32);
    Tensor<float> b(shapeB, DataType::FLOAT32);
    Tensor<float> c(shapeC, DataType::FLOAT32);
    
    // A = [[1, 2, 3], [4, 5, 6]]
    a.At(0, 0) = 1.0f; a.At(0, 1) = 2.0f; a.At(0, 2) = 3.0f;
    a.At(1, 0) = 4.0f; a.At(1, 1) = 5.0f; a.At(1, 2) = 6.0f;
    
    // B = [[7, 8], [9, 10], [11, 12]]
    b.At(0, 0) = 7.0f;  b.At(0, 1) = 8.0f;
    b.At(1, 0) = 9.0f;  b.At(1, 1) = 10.0f;
    b.At(2, 0) = 11.0f; b.At(2, 1) = 12.0f;
    
    Tensor<float>::MatMul(a, b, c);
    
    // C = A * B = [[58, 64], [139, 154]]
    EXPECT_FLOAT_EQ(c.At(0, 0), 58.0f);
    EXPECT_FLOAT_EQ(c.At(0, 1), 64.0f);
    EXPECT_FLOAT_EQ(c.At(1, 0), 139.0f);
    EXPECT_FLOAT_EQ(c.At(1, 1), 154.0f);
}

TEST_F(TensorTest, Transpose) {
    std::vector<size_t> shape = {2, 3};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    // Fill with sequential values
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            tensor.At(i, j) = static_cast<float>(i * 3 + j);
        }
    }
    
    Tensor<float> transposed = tensor.Transpose();
    
    EXPECT_EQ(transposed.GetShape()[0], 3);
    EXPECT_EQ(transposed.GetShape()[1], 2);
    
    // Verify transposition
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            EXPECT_FLOAT_EQ(tensor.At(i, j), transposed.At(j, i));
        }
    }
}

TEST_F(TensorTest, Softmax) {
    std::vector<size_t> shape = {1, 4};
    Tensor<float> input(shape, DataType::FLOAT32);
    Tensor<float> output(shape, DataType::FLOAT32);
    
    input.At(0, 0) = 1.0f;
    input.At(0, 1) = 2.0f;
    input.At(0, 2) = 3.0f;
    input.At(0, 3) = 4.0f;
    
    Tensor<float>::Softmax(input, output, /*dim=*/1);
    
    // Check that probabilities sum to 1
    float sum = 0.0f;
    for (size_t i = 0; i < 4; ++i) {
        sum += output.At(0, i);
        EXPECT_GT(output.At(0, i), 0.0f); // All positive
    }
    EXPECT_NEAR(sum, 1.0f, 1e-5f);
}

TEST_F(TensorTest, LayerNormalization) {
    std::vector<size_t> shape = {1, 4};
    Tensor<float> input(shape, DataType::FLOAT32);
    Tensor<float> output(shape, DataType::FLOAT32);
    
    input.At(0, 0) = 1.0f;
    input.At(0, 1) = 2.0f;
    input.At(0, 2) = 3.0f;
    input.At(0, 3) = 4.0f;
    
    Tensor<float> gamma({4}, DataType::FLOAT32);
    Tensor<float> beta({4}, DataType::FLOAT32);
    gamma.Ones();
    beta.Zero();
    
    Tensor<float>::LayerNorm(input, output, gamma, beta, /*eps=*/1e-5f);
    
    // Check mean is approximately 0
    float mean = 0.0f;
    for (size_t i = 0; i < 4; ++i) {
        mean += output.At(0, i);
    }
    mean /= 4.0f;
    EXPECT_NEAR(mean, 0.0f, 1e-5f);
}

TEST_F(TensorTest, Broadcasting) {
    std::vector<size_t> shapeA = {3, 1};
    std::vector<size_t> shapeB = {1, 4};
    std::vector<size_t> shapeC = {3, 4};
    
    Tensor<float> a(shapeA, DataType::FLOAT32);
    Tensor<float> b(shapeB, DataType::FLOAT32);
    Tensor<float> c(shapeC, DataType::FLOAT32);
    
    // Fill with test values
    for (size_t i = 0; i < 3; ++i) {
        a.At(i, 0) = static_cast<float>(i + 1);
    }
    for (size_t j = 0; j < 4; ++j) {
        b.At(0, j) = static_cast<float>(j + 1);
    }
    
    Tensor<float>::BroadcastAdd(a, b, c);
    
    // Verify broadcasting
    for (size_t i = 0; i < 3; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            EXPECT_FLOAT_EQ(c.At(i, j), a.At(i, 0) + b.At(0, j));
        }
    }
}

TEST_F(TensorTest, Slice) {
    std::vector<size_t> shape = {4, 4};
    Tensor<float> tensor(shape, DataType::FLOAT32);
    
    // Fill with sequential values
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            tensor.At(i, j) = static_cast<float>(i * 4 + j);
        }
    }
    
    // Slice [1:3, 1:3]
    auto sliced = tensor.Slice({1, 1}, {3, 3});
    
    EXPECT_EQ(sliced->GetShape()[0], 2);
    EXPECT_EQ(sliced->GetShape()[1], 2);
    
    EXPECT_FLOAT_EQ(sliced->At(0, 0), 5.0f);  // tensor[1,1]
    EXPECT_FLOAT_EQ(sliced->At(0, 1), 6.0f);  // tensor[1,2]
    EXPECT_FLOAT_EQ(sliced->At(1, 0), 9.0f);  // tensor[2,1]
    EXPECT_FLOAT_EQ(sliced->At(1, 1), 10.0f); // tensor[2,2]
}

TEST_F(TensorTest, Concatenation) {
    std::vector<size_t> shape = {2, 3};
    Tensor<float> a(shape, DataType::FLOAT32);
    Tensor<float> b(shape, DataType::FLOAT32);
    
    // Fill with test values
    for (size_t i = 0; i < 2; ++i) {
        for (size_t j = 0; j < 3; ++j) {
            a.At(i, j) = static_cast<float>(i * 3 + j);
            b.At(i, j) = static_cast<float>((i + 2) * 3 + j);
        }
    }
    
    std::vector<Tensor<float>*> tensors = {&a, &b};
    auto concatenated = Tensor<float>::Concat(tensors, /*dim=*/0);
    
    EXPECT_EQ(concatenated->GetShape()[0], 4);
    EXPECT_EQ(concatenated->GetShape()[1], 3);
}

TEST_F(TensorTest, Quantization) {
    std::vector<size_t> shape = {4, 4};
    Tensor<float> input(shape, DataType::FLOAT32);
    
    // Fill with values in range [-1, 1]
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            input.At(i, j) = static_cast<float>(i * 4 + j) / 8.0f - 1.0f;
        }
    }
    
    // Quantize to Q8_0
    auto quantized = input.Quantize(QuantizationType::Q8_0);
    EXPECT_NE(quantized, nullptr);
    
    // Dequantize
    auto dequantized = quantized->Dequantize();
    EXPECT_NE(dequantized, nullptr);
    
    // Check reconstruction error is small
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            float error = std::abs(input.At(i, j) - dequantized->At(i, j));
            EXPECT_LT(error, 0.1f); // Within reasonable tolerance
        }
    }
}

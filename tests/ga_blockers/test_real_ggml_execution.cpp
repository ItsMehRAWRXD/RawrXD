/**
 * GA Blocker: Real GGML Execution L4 Validation
 * 
 * Validates that actual GGML inference works end-to-end,
 * not just stubs. This is critical for production readiness.
 */

#include <gtest/gtest.h>
#include <rawrxd/RawrXD.hpp>
#include <rawrxd/backends/GGMLBackend.hpp>
#include <rawrxd/tensor/Tensor.hpp>
#include <math>

using namespace rawrxd;

class RealGGMLExecution : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize runtime
        runtime = Runtime::Create();
        ASSERT_NE(runtime, nullptr);
        
        RuntimeConfig config;
        config.backend = BackendType::CPU;  // Use CPU for consistent testing
        
        auto result = runtime->Initialize(config);
        ASSERT_TRUE(result.IsOk()) << "Failed to initialize runtime: " << result.Error().message;
    }

    void TearDown() override {
        if (runtime) {
            runtime->Shutdown();
        }
    }

    std::shared_ptr<Runtime> runtime;
};

// L4 Validation: GGML backend initializes successfully
TEST_F(RealGGMLExecution, GGMLBackend_Initialize) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto result = backend->Initialize(config);
    EXPECT_TRUE(result.IsOk()) << "GGML backend failed to initialize: " << result.Error().message;
}

// L4 Validation: Tensor operations work
TEST_F(RealGGMLExecution, Tensor_CreateAndFill) {
    // Create a simple tensor
    TensorShape shape = {2, 3, 4};  // 2x3x4 tensor
    
    auto tensor = Tensor::Create(shape, DataType::F32);
    ASSERT_NE(tensor, nullptr);
    
    // Fill with test data
    std::vector<float> data(24);  // 2*3*4 = 24
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<float>(i) * 0.5f;
    }
    
    auto fillResult = tensor->Fill(data.data(), data.size() * sizeof(float));
    EXPECT_TRUE(fillResult.IsOk()) << "Failed to fill tensor: " << fillResult.Error().message;
    
    // Verify data
    auto readResult = tensor->Read<float>();
    EXPECT_TRUE(readResult.IsOk());
    
    if (readResult.IsOk()) {
        auto readData = readResult.Value();
        EXPECT_EQ(readData.size(), data.size());
        
        for (size_t i = 0; i < data.size(); ++i) {
            EXPECT_FLOAT_EQ(readData[i], data[i]) << "Data mismatch at index " << i;
        }
    }
}

// L4 Validation: Matrix multiplication (core GGML operation)
TEST_F(RealGGMLExecution, GGML_MatrixMultiply) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto initResult = backend->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create two matrices: A (2x3) and B (3x4)
    auto matrixA = Tensor::Create({2, 3}, DataType::F32);
    auto matrixB = Tensor::Create({3, 4}, DataType::F32);
    ASSERT_NE(matrixA, nullptr);
    ASSERT_NE(matrixB, nullptr);
    
    // Fill with known values
    std::vector<float> dataA = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    std::vector<float> dataB = {1.0f, 2.0f, 3.0f, 4.0f, 
                                     5.0f, 6.0f, 7.0f, 8.0f,
                                     9.0f, 10.0f, 11.0f, 12.0f};
    
    matrixA->Fill(dataA.data(), dataA.size() * sizeof(float));
    matrixB->Fill(dataB.data(), dataB.size() * sizeof(float));
    
    // Perform matrix multiplication
    auto result = backend->MatMul(matrixA, matrixB);
    EXPECT_TRUE(result.IsOk()) << "Matrix multiplication failed: " << result.Error().message;
    
    if (result.IsOk()) {
        auto output = result.Value();
        ASSERT_NE(output, nullptr);
        
        // Verify output shape
        auto shape = output->GetShape();
        EXPECT_EQ(shape.dims.size(), 2);
        EXPECT_EQ(shape.dims[0], 2);
        EXPECT_EQ(shape.dims[1], 4);
        
        // Verify output values
        // C[0,0] = 1*1 + 2*5 + 3*9 = 1 + 10 + 27 = 38
        // C[0,1] = 1*2 + 2*6 + 3*10 = 2 + 12 + 30 = 44
        auto readResult = output->Read<float>();
        EXPECT_TRUE(readResult.IsOk());
        
        if (readResult.IsOk()) {
            auto outputData = readResult.Value();
            EXPECT_EQ(outputData.size(), 8);  // 2x4 = 8
            
            // Check first element
            EXPECT_FLOAT_EQ(outputData[0], 38.0f);
            // Check second element
            EXPECT_FLOAT_EQ(outputData[1], 44.0f);
        }
    }
}

// L4 Validation: Embedding lookup (critical for inference)
TEST_F(RealGGMLExecution, GGML_EmbeddingLookup) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto initResult = backend->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create embedding table: vocab_size=100, embedding_dim=64
    auto embeddings = Tensor::Create({100, 64}, DataType::F32);
    ASSERT_NE(embeddings, nullptr);
    
    // Fill with test data
    std::vector<float> embedData(100 * 64);
    for (size_t i = 0; i < embedData.size(); ++i) {
        embedData[i] = static_cast<float>(i) * 0.01f;
    }
    embeddings->Fill(embedData.data(), embedData.size() * sizeof(float));
    
    // Create token indices
    std::vector<int32_t> tokenIds = {0, 5, 10, 15, 20};
    auto tokens = Tensor::Create({static_cast<int64_t>(tokenIds.size())}, DataType::I32);
    ASSERT_NE(tokens, nullptr);
    tokens->Fill(tokenIds.data(), tokenIds.size() * sizeof(int32_t));
    
    // Perform embedding lookup
    auto result = backend->EmbeddingLookup(embeddings, tokens);
    EXPECT_TRUE(result.IsOk()) << "Embedding lookup failed: " << result.Error().message;
    
    if (result.IsOk()) {
        auto output = result.Value();
        ASSERT_NE(output, nullptr);
        
        // Verify output shape: [5, 64]
        auto shape = output->GetShape();
        EXPECT_EQ(shape.dims.size(), 2);
        EXPECT_EQ(shape.dims[0], 5);
        EXPECT_EQ(shape.dims[1], 64);
        
        // Verify output values match expected embeddings
        auto readResult = output->Read<float>();
        EXPECT_TRUE(readResult.IsOk());
        
        if (readResult.IsOk()) {
            auto outputData = readResult.Value();
            EXPECT_EQ(outputData.size(), 5 * 64);
            
            // Check first token's embedding (token 0)
            for (size_t i = 0; i < 64; ++i) {
                EXPECT_FLOAT_EQ(outputData[i], embedData[i]) << "Embedding mismatch at index " << i;
            }
            
            // Check second token's embedding (token 5)
            for (size_t i = 0; i < 64; ++i) {
                EXPECT_FLOAT_EQ(outputData[64 + i], embedData[5 * 64 + i]) << "Embedding mismatch at index " << i;
            }
        }
    }
}

// L4 Validation: Layer normalization (common transformer operation)
TEST_F(RealGGMLExecution, GGML_LayerNormalization) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto initResult = backend->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create input tensor: [2, 512] (batch=2, features=512)
    auto input = Tensor::Create({2, 512}, DataType::F32);
    ASSERT_NE(input, nullptr);
    
    // Fill with random data
    std::vector<float> inputData(2 * 512);
    for (size_t i = 0; i < inputData.size(); ++i) {
        inputData[i] = static_cast<float>(i % 100) * 0.1f;
    }
    input->Fill(inputData.data(), inputData.size() * sizeof(float));
    
    // Perform layer normalization
    auto result = backend->LayerNorm(input, 1e-5f);
    EXPECT_TRUE(result.IsOk()) << "Layer normalization failed: " << result.Error().message;
    
    if (result.IsOk()) {
        auto output = result.Value();
        ASSERT_NE(output, nullptr);
        
        // Verify output shape matches input
        auto shape = output->GetShape();
        EXPECT_EQ(shape.dims.size(), 2);
        EXPECT_EQ(shape.dims[0], 2);
        EXPECT_EQ(shape.dims[1], 512);
        
        // Verify output is normalized (mean ≈ 0, variance ≈ 1)
        auto readResult = output->Read<float>();
        EXPECT_TRUE(readResult.IsOk());
        
        if (readResult.IsOk()) {
            auto outputData = readResult.Value();
            
            // Calculate mean and variance of first row
            double mean = 0.0;
            for (size_t i = 0; i < 512; ++i) {
                mean += outputData[i];
            }
            mean /= 512.0;
            
            double variance = 0.0;
            for (size_t i = 0; i < 512; ++i) {
                variance += (outputData[i] - mean) * (outputData[i] - mean);
            }
            variance /= 512.0;
            
            // Mean should be close to 0
            EXPECT_NEAR(mean, 0.0, 0.01) << "Layer norm mean not close to 0";
            
            // Variance should be close to 1
            EXPECT_NEAR(variance, 1.0, 0.1) << "Layer norm variance not close to 1";
        }
    }
}

// L4 Validation: Attention mechanism (core transformer operation)
TEST_F(RealGGMLExecution, GGML_ScaledDotProductAttention) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto initResult = backend->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Create Q, K, V tensors: [batch=2, heads=8, seq_len=64, head_dim=64]
    auto Q = Tensor::Create({2, 8, 64, 64}, DataType::F32);
    auto K = Tensor::Create({2, 8, 64, 64}, DataType::F32);
    auto V = Tensor::Create({2, 8, 64, 64}, DataType::F32);
    ASSERT_NE(Q, nullptr);
    ASSERT_NE(K, nullptr);
    ASSERT_NE(V, nullptr);
    
    // Fill with test data
    std::vector<float> qData(2 * 8 * 64 * 64, 0.1f);
    std::vector<float> kData(2 * 8 * 64 * 64, 0.1f);
    std::vector<float> vData(2 * 8 * 64 * 64, 0.1f);
    
    Q->Fill(qData.data(), qData.size() * sizeof(float));
    K->Fill(kData.data(), kData.size() * sizeof(float));
    V->Fill(vData.data(), vData.size() * sizeof(float));
    
    // Perform scaled dot-product attention
    auto result = backend->ScaledDotProductAttention(Q, K, V);
    EXPECT_TRUE(result.IsOk()) << "Attention failed: " << result.Error().message;
    
    if (result.IsOk()) {
        auto output = result.Value();
        ASSERT_NE(output, nullptr);
        
        // Verify output shape matches input
        auto shape = output->GetShape();
        EXPECT_EQ(shape.dims.size(), 4);
        EXPECT_EQ(shape.dims[0], 2);
        EXPECT_EQ(shape.dims[1], 8);
        EXPECT_EQ(shape.dims[2], 64);
        EXPECT_EQ(shape.dims[3], 64);
        
        // Verify output contains valid values (not NaN or Inf)
        auto readResult = output->Read<float>();
        EXPECT_TRUE(readResult.IsOk());
        
        if (readResult.IsOk()) {
            auto outputData = readResult.Value();
            for (size_t i = 0; i < outputData.size(); ++i) {
                EXPECT_FALSE(std::isnan(outputData[i])) << "NaN in attention output at index " << i;
                EXPECT_FALSE(std::isinf(outputData[i])) << "Inf in attention output at index " << i;
            }
        }
    }
}

// L4 Validation: End-to-end inference simulation
TEST_F(RealGGMLExecution, EndToEnd_InferenceSimulation) {
    auto backend = GGMLBackend::Create();
    ASSERT_NE(backend, nullptr);
    
    GGMLConfig config;
    config.numThreads = 4;
    
    auto initResult = backend->Initialize(config);
    ASSERT_TRUE(initResult.IsOk());
    
    // Simulate a simple forward pass:
    // 1. Embedding lookup
    // 2. Layer norm
    // 3. Linear projection
    // 4. Activation
    
    // Step 1: Create embeddings
    auto embeddings = Tensor::Create({1000, 512}, DataType::F32);
    ASSERT_NE(embeddings, nullptr);
    
    std::vector<float> embedData(1000 * 512);
    for (size_t i = 0; i < embedData.size(); ++i) {
        embedData[i] = (static_cast<float>(rand()) / RAND_MAX) * 0.1f;
    }
    embeddings->Fill(embedData.data(), embedData.size() * sizeof(float));
    
    // Step 2: Create token indices
    std::vector<int32_t> tokenIds = {1, 2, 3, 4, 5};
    auto tokens = Tensor::Create({static_cast<int64_t>(tokenIds.size())}, DataType::I32);
    ASSERT_NE(tokens, nullptr);
    tokens->Fill(tokenIds.data(), tokenIds.size() * sizeof(int32_t));
    
    // Step 3: Embedding lookup
    auto embedResult = backend->EmbeddingLookup(embeddings, tokens);
    ASSERT_TRUE(embedResult.IsOk()) << "Embedding lookup failed";
    auto hidden = embedResult.Value();
    ASSERT_NE(hidden, nullptr);
    
    // Step 4: Layer normalization
    auto normResult = backend->LayerNorm(hidden, 1e-5f);
    ASSERT_TRUE(normResult.IsOk()) << "Layer norm failed";
    hidden = normResult.Value();
    ASSERT_NE(hidden, nullptr);
    
    // Step 5: Linear projection (simulated with matmul)
    auto projection = Tensor::Create({512, 1000}, DataType::F32);
    ASSERT_NE(projection, nullptr);
    
    std::vector<float> projData(512 * 1000);
    for (size_t i = 0; i < projData.size(); ++i) {
        projData[i] = (static_cast<float>(rand()) / RAND_MAX) * 0.01f;
    }
    projection->Fill(projData.data(), projData.size() * sizeof(float));
    
    auto projResult = backend->MatMul(hidden, projection);
    ASSERT_TRUE(projResult.IsOk()) << "Projection failed";
    auto logits = projResult.Value();
    ASSERT_NE(logits, nullptr);
    
    // Step 6: Verify output
    auto shape = logits->GetShape();
    EXPECT_EQ(shape.dims.size(), 2);
    EXPECT_EQ(shape.dims[0], 5);   // seq_len
    EXPECT_EQ(shape.dims[1], 1000); // vocab_size
    
    // Verify output contains valid values
    auto readResult = logits->Read<float>();
    ASSERT_TRUE(readResult.IsOk());
    
    auto outputData = readResult.Value();
    for (size_t i = 0; i < outputData.size(); ++i) {
        EXPECT_FALSE(std::isnan(outputData[i])) << "NaN in final output at index " << i;
        EXPECT_FALSE(std::isinf(outputData[i])) << "Inf in final output at index " << i;
    }
    
    // Log success
    std::cout << "✓ End-to-end inference simulation completed successfully\n";
    std::cout << "  - Embedding lookup: " << embedData.size() * sizeof(float) / 1024.0 / 1024.0 << " MB\n";
    std::cout << "  - Output logits: " << outputData.size() * sizeof(float) / 1024.0 << " KB\n";
}

// Main entry point for standalone execution
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    
    std::cout << "========================================\n";
    std::cout << "Real GGML Execution L4 Validation Tests\n";
    std::cout << "========================================\n\n";
    
    return RUN_ALL_TESTS();
}

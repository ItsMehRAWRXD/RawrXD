// ============================================================================
// Test: Transformer Layer + AVX512 Integration
// ============================================================================
// Validates AVX512-optimized transformer layer performance
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include "../runtime/transformer_layer_runtime.hpp"

using namespace RawrXD::Runtime;

// ============================================================================
// Mock TensorView for Testing
// ============================================================================

class MockTensorView : public TensorView {
public:
    MockTensorView(uint32_t rows, uint32_t cols, float fill_value = 0.01f)
        : rows_(rows), cols_(cols) {
        data_.resize(rows * cols, fill_value);
    }
    
    float Read(uint32_t row, uint32_t col) const override {
        if (row < rows_ && col < cols_) {
            return data_[row * cols_ + col];
        }
        return 0.0f;
    }
    
    float Read(uint32_t index) const override {
        if (index < data_.size()) {
            return data_[index];
        }
        return 0.0f;
    }
    
    uint32_t Rows() const override { return rows_; }
    uint32_t Cols() const override { return cols_; }
    uint32_t GetElementCount() const override { return rows_ * cols_; }
    
    size_t DequantizeRow(size_t row, float* output, size_t outputCapacity) const override {
        if (!output || outputCapacity == 0) return 0;
        uint32_t cols = Cols();
        if (cols == 0) cols = Rows();
        if (outputCapacity < cols) return 0;
        
        for (uint32_t c = 0; c < cols; c++) {
            output[c] = Read(row, c);
        }
        return cols;
    }

private:
    uint32_t rows_, cols_;
    std::vector<float> data_;
};

// ============================================================================
// Test Functions
// ============================================================================

bool TestTransformerLayerBinding() {
    std::cout << "Test: Transformer Layer Binding...\n";
    
    TransformerLayerRuntime layer;
    
    // Create mock tensors
    MockTensorView inputNorm(1, 512);
    MockTensorView qProj(512, 512);
    MockTensorView kProj(512, 512);
    MockTensorView vProj(512, 512);
    MockTensorView oProj(512, 512);
    MockTensorView postNorm(1, 512);
    MockTensorView gateProj(512, 1024);
    MockTensorView upProj(512, 1024);
    MockTensorView downProj(1024, 512);
    
    bool bound = layer.BindLayer(0, inputNorm, qProj, kProj, vProj, oProj,
                                  postNorm, gateProj, upProj, downProj);
    
    if (!bound) {
        std::cout << "  ✗ Failed to bind layer\n";
        return false;
    }
    
    std::cout << "  Layer bound successfully\n";
    std::cout << "  Hidden size: " << layer.GetConfig().hiddenSize << "\n";
    std::cout << "  Num heads: " << layer.GetConfig().numHeads << "\n";
    std::cout << "  Head dim: " << layer.GetConfig().headDim << "\n";
    
    return true;
}

bool TestTransformerLayerForward() {
    std::cout << "\nTest: Transformer Layer Forward Pass...\n";
    
    TransformerLayerRuntime layer;
    
    // Create mock tensors
    MockTensorView inputNorm(1, 256);
    MockTensorView qProj(256, 256);
    MockTensorView kProj(256, 256);
    MockTensorView vProj(256, 256);
    MockTensorView oProj(256, 256);
    MockTensorView postNorm(1, 256);
    MockTensorView gateProj(256, 512);
    MockTensorView upProj(256, 512);
    MockTensorView downProj(512, 256);
    
    layer.BindLayer(0, inputNorm, qProj, kProj, vProj, oProj,
                    postNorm, gateProj, upProj, downProj);
    
    // Prepare input
    std::vector<float> input(256, 0.1f);
    std::vector<float> output(256, 0.0f);
    std::vector<float> keyCache(64 * 256, 0.0f);
    std::vector<float> valueCache(64 * 256, 0.0f);
    
    // Run forward pass
    bool success = layer.Forward(input.data(), 1, 0, output.data(),
                                  keyCache.data(), valueCache.data(), 64);
    
    if (!success) {
        std::cout << "  ✗ Forward pass failed\n";
        return false;
    }
    
    // Check output is not all zeros
    float sum = 0.0f;
    for (float v : output) {
        sum += std::abs(v);
    }
    
    if (sum < 1e-6f) {
        std::cout << "  ✗ Output is all zeros\n";
        return false;
    }
    
    std::cout << "  Forward pass complete\n";
    std::cout << "  Output L1 norm: " << sum << "\n";
    
    return true;
}

bool TestTransformerLayerBenchmark() {
    std::cout << "\nTest: Transformer Layer Benchmark...\n";
    
    TransformerLayerRuntime layer;
    
    // Create mock tensors
    MockTensorView inputNorm(1, 512);
    MockTensorView qProj(512, 512);
    MockTensorView kProj(512, 512);
    MockTensorView vProj(512, 512);
    MockTensorView oProj(512, 512);
    MockTensorView postNorm(1, 512);
    MockTensorView gateProj(512, 1024);
    MockTensorView upProj(512, 1024);
    MockTensorView downProj(1024, 512);
    
    layer.BindLayer(0, inputNorm, qProj, kProj, vProj, oProj,
                    postNorm, gateProj, upProj, downProj);
    
    uint32_t seqLen = 32;
    uint32_t hiddenSize = 512;
    
    std::vector<float> input(hiddenSize, 0.1f);
    std::vector<float> output(hiddenSize, 0.0f);
    std::vector<float> keyCache(seqLen * hiddenSize, 0.0f);
    std::vector<float> valueCache(seqLen * hiddenSize, 0.0f);
    
    // Warmup
    for (uint32_t i = 0; i < 10; i++) {
        layer.Forward(input.data(), seqLen, i, output.data(),
                      keyCache.data(), valueCache.data(), seqLen);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    uint32_t iterations = 100;
    for (uint32_t i = 0; i < iterations; i++) {
        layer.Forward(input.data(), seqLen, i % seqLen, output.data(),
                      keyCache.data(), valueCache.data(), seqLen);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float avgTime = duration.count() / static_cast<float>(iterations);
    float tokensPerSec = 1000000.0f / avgTime;
    
    std::cout << "  Config: " << seqLen << " x " << hiddenSize << "\n";
    std::cout << "  Avg time: " << avgTime << " us\n";
    std::cout << "  Throughput: " << tokensPerSec << " tokens/sec\n";
    
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Transformer Layer + AVX512 Tests\n";
    std::cout << "========================================\n\n";
    
    int passed = 0;
    int failed = 0;
    
    auto run_test = [&](const char* name, bool (*test)()) {
        std::cout << "\n--- " << name << " ---\n";
        try {
            if (test()) {
                std::cout << "✓ PASSED\n";
                passed++;
            } else {
                std::cout << "✗ FAILED\n";
                failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "✗ EXCEPTION: " << e.what() << "\n";
            failed++;
        }
    };
    
    run_test("Layer Binding", TestTransformerLayerBinding);
    run_test("Forward Pass", TestTransformerLayerForward);
    run_test("Benchmark", TestTransformerLayerBenchmark);
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";
    
    return failed == 0 ? 0 : 1;
}

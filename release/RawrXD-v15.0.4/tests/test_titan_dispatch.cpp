//==============================================================================
// test_titan_dispatch.cpp
// Titan Dispatch Test Harness
//
// Validates Titan GPU execution against CPU oracle for correctness.
// Focus: MatMul_Q4_Q8 as the first end-to-end test.
//
// Date: July 10, 2026
// Phase: 7B.5 - Titan Integration Validation
//==============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <cstring>

#include "../src/core/execution/SovereignTitanDispatch.hpp"
#include "../src/core/execution/SovereignKernelTypes.hpp"

using namespace sovereign;

//==============================================================================
// Test Configuration
//==============================================================================
struct TestConfig {
    uint32_t M{512};      // Output rows
    uint32_t N{512};      // Output columns  
    uint32_t K{512};      // Inner dimension
    float tolerance{1e-4f};  // Numerical tolerance for correctness
    uint32_t iterations{10}; // Benchmark iterations
};

//==============================================================================
// Reference CPU Implementation (Oracle)
//==============================================================================

// Simple Q4_0 dequantize: 32 values per block
void DequantizeQ4_0_CPU(const uint8_t* quantized, float* output, size_t numElements) {
    const size_t blockSize = 32;
    const size_t numBlocks = (numElements + blockSize - 1) / blockSize;
    
    for (size_t block = 0; block < numBlocks; ++block) {
        // Q4_0 layout: [scale: float][values: 16 bytes for 32 nibbles]
        float scale = *reinterpret_cast<const float*>(quantized + block * 18);
        const uint8_t* values = quantized + block * 18 + 4;
        
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            uint8_t byte = values[i / 2];
            uint8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
            int8_t signedVal = static_cast<int8_t>(nibble) - 8;  // Center around 0
            output[block * blockSize + i] = signedVal * scale;
        }
    }
}

// Simple Q8_0 dequantize
void DequantizeQ8_0_CPU(const uint8_t* quantized, float* output, size_t numElements) {
    const size_t blockSize = 32;
    const size_t numBlocks = (numElements + blockSize - 1) / blockSize;
    
    for (size_t block = 0; block < numBlocks; ++block) {
        float scale = *reinterpret_cast<const float*>(quantized + block * 33);
        const int8_t* values = reinterpret_cast<const int8_t*>(quantized + block * 33 + 4);
        
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            output[block * blockSize + i] = values[i] * scale;
        }
    }
}

// Reference MatMul: F32 × F32 → F32
void MatMul_F32_CPU(const float* A, const float* B, float* C, 
                    uint32_t M, uint32_t N, uint32_t K) {
    for (uint32_t m = 0; m < M; ++m) {
        for (uint32_t n = 0; n < N; ++n) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < K; ++k) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

// Reference MatMul: Q4 weights × Q8 activations → F32
void MatMul_Q4_Q8_CPU_Reference(const uint8_t* weightsQ4, const uint8_t* activationsQ8,
                                 float* output, uint32_t M, uint32_t N, uint32_t K) {
    // Dequantize weights [M × K]
    std::vector<float> weightsF32(M * K);
    DequantizeQ4_0_CPU(weightsQ4, weightsF32.data(), M * K);
    
    // Dequantize activations [K × N] (stored as [N × K] and transposed)
    std::vector<float> activationsF32(K * N);
    DequantizeQ8_0_CPU(activationsQ8, activationsF32.data(), K * N);
    
    // Perform F32 MatMul
    MatMul_F32_CPU(weightsF32.data(), activationsF32.data(), output, M, N, K);
}

//==============================================================================
// Test Data Generation
//==============================================================================

void GenerateQ4_0_Data(uint8_t* buffer, size_t numElements, unsigned int seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    const size_t blockSize = 32;
    const size_t numBlocks = (numElements + blockSize - 1) / blockSize;
    
    for (size_t block = 0; block < numBlocks; ++block) {
        // Calculate scale for this block
        float maxVal = 0.0f;
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            float val = dist(rng);
            maxVal = std::max(maxVal, std::abs(val));
        }
        float scale = maxVal / 7.0f;  // 4-bit range: -7 to +7
        
        // Write scale
        *reinterpret_cast<float*>(buffer + block * 18) = scale;
        
        // Quantize and pack values
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            float val = dist(rng);
            int8_t q = static_cast<int8_t>(std::round(val / scale));
            q = std::max<int8_t>(-8, std::min<int8_t>(7, q));
            uint8_t nibble = static_cast<uint8_t>(q + 8);  // Offset to 0-15
            
            size_t byteIdx = block * 18 + 4 + i / 2;
            if (i % 2 == 0) {
                buffer[byteIdx] = nibble;
            } else {
                buffer[byteIdx] |= (nibble << 4);
            }
        }
    }
}

void GenerateQ8_0_Data(uint8_t* buffer, size_t numElements, unsigned int seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    const size_t blockSize = 32;
    const size_t numBlocks = (numElements + blockSize - 1) / blockSize;
    
    for (size_t block = 0; block < numBlocks; ++block) {
        // Calculate scale
        float maxVal = 0.0f;
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            float val = dist(rng);
            maxVal = std::max(maxVal, std::abs(val));
        }
        float scale = maxVal / 127.0f;
        
        // Write scale
        *reinterpret_cast<float*>(buffer + block * 33) = scale;
        
        // Quantize values
        for (size_t i = 0; i < blockSize && (block * blockSize + i) < numElements; ++i) {
            float val = dist(rng);
            int8_t q = static_cast<int8_t>(std::round(val / scale));
            buffer[block * 33 + 4 + i] = static_cast<uint8_t>(q);
        }
    }
}

//==============================================================================
// Test: MatMul_Q4_Q8
//==============================================================================

bool Test_MatMul_Q4_Q8(const TestConfig& config) {
    std::cout << "\n========================================\n";
    std::cout << "Test: MatMul_Q4_Q8\n";
    std::cout << "Dimensions: " << config.M << "x" << config.K << " @ " 
              << config.K << "x" << config.N << " = " << config.M << "x" << config.N << "\n";
    std::cout << "========================================\n\n";
    
    // Calculate buffer sizes
    // Q4_0: 18 bytes per 32 elements (4 bytes scale + 16 bytes data)
    size_t weightsSize = ((config.M * config.K + 31) / 32) * 18;
    // Q8_0: 33 bytes per 32 elements (4 bytes scale + 32 bytes data)
    size_t activationsSize = ((config.K * config.N + 31) / 32) * 33;
    size_t outputSize = config.M * config.N * sizeof(float);
    
    // Allocate buffers
    std::vector<uint8_t> weightsQ4(weightsSize);
    std::vector<uint8_t> activationsQ8(activationsSize);
    std::vector<float> outputTitan(config.M * config.N);
    std::vector<float> outputCPU(config.M * config.N);
    
    // Generate test data
    std::cout << "Generating test data...\n";
    GenerateQ4_0_Data(weightsQ4.data(), config.M * config.K, 42);
    GenerateQ8_0_Data(activationsQ8.data(), config.K * config.N, 43);
    
    // Compute CPU reference
    std::cout << "Computing CPU reference...\n";
    auto cpuStart = std::chrono::high_resolution_clock::now();
    MatMul_Q4_Q8_CPU_Reference(weightsQ4.data(), activationsQ8.data(), 
                               outputCPU.data(), config.M, config.N, config.K);
    auto cpuEnd = std::chrono::high_resolution_clock::now();
    auto cpuTime = std::chrono::duration_cast<std::chrono::microseconds>(cpuEnd - cpuStart).count();
    std::cout << "  CPU time: " << cpuTime << " us\n";
    
    // Setup Titan dispatch
    std::cout << "\nSetting up Titan dispatch...\n";
    
    // Create tensor descriptors
    TensorDesc weightsDesc{};
    weightsDesc.data = weightsQ4.data();
    weightsDesc.sizeBytes = weightsSize;
    weightsDesc.dims[0] = config.M;
    weightsDesc.dims[1] = config.K;
    weightsDesc.numDims = 2;
    weightsDesc.dtype = TensorDesc::DataType::Q4_0;
    
    TensorDesc activationsDesc{};
    activationsDesc.data = activationsQ8.data();
    activationsDesc.sizeBytes = activationsSize;
    activationsDesc.dims[0] = config.K;
    activationsDesc.dims[1] = config.N;
    activationsDesc.numDims = 2;
    activationsDesc.dtype = TensorDesc::DataType::Q8_0;
    
    TensorDesc outputDesc{};
    outputDesc.data = outputTitan.data();
    outputDesc.sizeBytes = outputSize;
    outputDesc.dims[0] = config.M;
    outputDesc.dims[1] = config.N;
    outputDesc.numDims = 2;
    outputDesc.dtype = TensorDesc::DataType::F32;
    
    // Create Titan context (simulated for testing)
    TitanGpuContext titanCtx{};
    // Allocate fake staging buffer to make context valid
    std::vector<uint8_t> stagingBuffer(64 * 1024 * 1024);
    titanCtx.stagingBuffer = stagingBuffer.data();
    titanCtx.stagingSize = stagingBuffer.size();
    
    // Dispatch via Titan
    std::cout << "Dispatching via Titan...\n";
    auto titanStart = std::chrono::high_resolution_clock::now();
    
    DispatchResult result = DispatchMatMul_Q4_Q8(
        weightsDesc, activationsDesc, outputDesc, 
        &titanCtx
    );
    
    auto titanEnd = std::chrono::high_resolution_clock::now();
    auto titanTime = std::chrono::duration_cast<std::chrono::microseconds>(titanEnd - titanStart).count();
    
    std::cout << "  Titan dispatch: " << (result.success ? "SUCCESS" : "FAILED") << "\n";
    std::cout << "  Path used: " << (result.pathUsed == DispatchPath::GPU_TITAN ? "GPU_TITAN" : "CPU_MASM") << "\n";
    std::cout << "  Execution time: " << result.executionTimeUs << " us\n";
    std::cout << "  Total time: " << titanTime << " us\n";
    
    if (!result.success) {
        std::cout << "  Error code: " << result.errorCode << "\n";
        std::cout << "\n*** TEST FAILED: Titan dispatch failed ***\n";
        return false;
    }
    
    // Verify correctness
    std::cout << "\nVerifying correctness...\n";
    float maxError = 0.0f;
    float sumError = 0.0f;
    size_t errorCount = 0;
    
    for (size_t i = 0; i < config.M * config.N; ++i) {
        float diff = std::abs(outputTitan[i] - outputCPU[i]);
        maxError = std::max(maxError, diff);
        sumError += diff;
        if (diff > config.tolerance) {
            errorCount++;
            if (errorCount <= 5) {
                std::cout << "  Error at [" << i / config.N << "][" << i % config.N 
                          << "]: Titan=" << outputTitan[i] 
                          << " CPU=" << outputCPU[i]
                          << " diff=" << diff << "\n";
            }
        }
    }
    
    float avgError = sumError / (config.M * config.N);
    std::cout << "  Max error: " << maxError << "\n";
    std::cout << "  Avg error: " << avgError << "\n";
    std::cout << "  Error count: " << errorCount << "/" << config.M * config.N << "\n";
    
    bool passed = (maxError <= config.tolerance);
    
    if (passed) {
        std::cout << "\n*** TEST PASSED ***\n";
        
        // Performance comparison
        if (result.executionTimeUs > 0) {
            double cpuThroughput = (2.0 * config.M * config.N * config.K) / cpuTime;  // GFLOPS
            double titanThroughput = (2.0 * config.M * config.N * config.K) / result.executionTimeUs;
            double speedup = static_cast<double>(cpuTime) / result.executionTimeUs;
            
            std::cout << "\nPerformance:\n";
            std::cout << "  CPU: " << cpuThroughput << " GFLOPS\n";
            std::cout << "  Titan: " << titanThroughput << " GFLOPS\n";
            std::cout << "  Speedup: " << speedup << "x\n";
        }
    } else {
        std::cout << "\n*** TEST FAILED: Numerical tolerance exceeded ***\n";
    }
    
    return passed;
}

//==============================================================================
// Test: Dispatch Path Selection
//==============================================================================

bool Test_DispatchPathSelection() {
    std::cout << "\n========================================\n";
    std::cout << "Test: Dispatch Path Selection\n";
    std::cout << "========================================\n\n";
    
    TitanGpuContext gpuCtx{};
    gpuCtx.stagingBuffer = reinterpret_cast<void*>(1);  // Fake valid pointer
    gpuCtx.stagingSize = 64 * 1024 * 1024;
    
    struct TestCase {
        size_t tensorSize;
        KernelId kernel;
        DispatchPath expected;
        const char* name;
    };
    
    TestCase cases[] = {
        {32 * 1024,       KernelId::MatMul_Q4_Q8,     DispatchPath::CPU_MASM,   "Small tensor (<64KB)"},
        {1024 * 1024,     KernelId::MatMul_Q4_Q8,     DispatchPath::GPU_TITAN,  "Medium compute-heavy"},
        {1024 * 1024,     KernelId::RMSNorm,          DispatchPath::CPU_MASM,   "Medium memory-light"},
        {16 * 1024 * 1024, KernelId::FlashAttentionV2, DispatchPath::GPU_TITAN, "Large attention"},
    };
    
    bool allPassed = true;
    
    for (const auto& tc : cases) {
        DispatchPath path = RecommendDispatchPath(tc.kernel, tc.tensorSize, &gpuCtx);
        bool passed = (path == tc.expected);
        
        std::cout << tc.name << ":\n";
        std::cout << "  Size: " << tc.tensorSize / 1024 << " KB\n";
        std::cout << "  Kernel: " << static_cast<int>(tc.kernel) << "\n";
        std::cout << "  Expected: " << (tc.expected == DispatchPath::GPU_TITAN ? "GPU_TITAN" : "CPU_MASM") << "\n";
        std::cout << "  Got: " << (path == DispatchPath::GPU_TITAN ? "GPU_TITAN" : "CPU_MASM") << "\n";
        std::cout << "  " << (passed ? "PASS" : "FAIL") << "\n\n";
        
        if (!passed) allPassed = false;
    }
    
    // Test without GPU context
    DispatchPath pathNoGPU = RecommendDispatchPath(KernelId::MatMul_Q4_Q8, 
                                                    16 * 1024 * 1024, nullptr);
    bool noGpuTest = (pathNoGPU == DispatchPath::CPU_MASM);
    std::cout << "No GPU context (large tensor): " << (noGpuTest ? "PASS" : "FAIL") << "\n";
    
    return allPassed && noGpuTest;
}

//==============================================================================
// Main
//==============================================================================

int main(int argc, char** argv) {
    std::cout << "==============================================\n";
    std::cout << "Sovereign Titan Dispatch Test Harness\n";
    std::cout << "Phase 7B.5 - Titan Integration Validation\n";
    std::cout << "==============================================\n";
    
    TestConfig config{};
    
    // Parse command line
    if (argc > 1) config.M = static_cast<uint32_t>(std::atoi(argv[1]));
    if (argc > 2) config.N = static_cast<uint32_t>(std::atoi(argv[2]));
    if (argc > 3) config.K = static_cast<uint32_t>(std::atoi(argv[3]));
    
    std::cout << "\nConfiguration:\n";
    std::cout << "  M=" << config.M << ", N=" << config.N << ", K=" << config.K << "\n";
    std::cout << "  Tolerance: " << config.tolerance << "\n";
    
    bool allPassed = true;
    
    // Run tests
    allPassed &= Test_DispatchPathSelection();
    allPassed &= Test_MatMul_Q4_Q8(config);
    
    // Summary
    std::cout << "\n==============================================\n";
    std::cout << "SUMMARY: " << (allPassed ? "ALL TESTS PASSED" : "SOME TESTS FAILED") << "\n";
    std::cout << "==============================================\n";
    
    return allPassed ? 0 : 1;
}

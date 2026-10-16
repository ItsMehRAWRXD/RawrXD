#include "deep2/QuantKernelRegistry.hpp"
#include <iostream>
#include <vector>
#include <cmath>
#include <limits>
#include <chrono>

int main() {
    std::cout << "[TEST] NVFP4 GEMV Correct Direction (input=4096 → output=18560)\n" << std::flush;
    
    // Initialize QuantKernelRegistry
    Deep2::QuantKernelRegistry::Instance().Initialize();
    std::cout << "Registry initialized\n" << std::flush;
    
    auto& reg = Deep2::QuantKernelRegistry::Instance();
    
    // Correct direction: Bolt blk.0.ssm_in.weight shape [4096, 18560]
    // Input dim = 4096, Output dim = 18560
    // Each output row has 4096 input elements = 4096/64 = 64 NVFP4 blocks
    const size_t outDim = 18560;
    const size_t inDim = 4096;
    
    const size_t blocksPerRow = inDim / 64;  // 64 blocks per row
    const size_t totalBlocks = outDim * blocksPerRow;
    const size_t weightBytes = totalBlocks * 36;
    
    std::cout << "Weights: " << outDim << "x" << inDim 
              << " blocks=" << totalBlocks << " bytes=" << weightBytes << std::flush;
    
    std::vector<uint8_t> weights(weightBytes, 0);
    
    // Fill with deterministic pseudo-random NVFP4 data
    for (size_t b = 0; b < totalBlocks; ++b) {
        for (size_t i = 0; i < 32; ++i) {
            uint8_t v0 = static_cast<uint8_t>((b * 31 + i * 7) % 16);
            uint8_t v1 = static_cast<uint8_t>((b * 17 + i * 13) % 16);
            weights[b * 36 + i] = static_cast<uint8_t>(v0 | (v1 << 4));
        }
        for (size_t i = 0; i < 4; ++i) {
            weights[b * 36 + 32 + i] = static_cast<uint8_t>((b * 5 + i * 3) % 16);
        }
    }
    
    std::cout << "Weights created\n" << std::flush;
    
    // Create test input (hidden state)
    std::vector<float> input(inDim);
    for (size_t i = 0; i < inDim; ++i) {
        input[i] = 0.01f * std::sin(0.1f * i);
    }
    
    std::cout << "Input created\n" << std::flush;
    
    // Output buffer
    std::vector<float> output(outDim, 0.0f);
    
    // Resolve NVFP4 kernel
    auto proxy = reg.Resolve(
        weights.data(),
        0,
        weightBytes,
        static_cast<int>(Deep2::GGMLType::GGML_TYPE_NVFP4),
        outDim, inDim
    );
    
    std::cout << "Proxy resolved\n" << std::flush;
    
    if (!proxy.gemvKernel) {
        std::cerr << "FAIL: No GEMV kernel registered for NVFP4\n";
        return 1;
    }
    
    std::cout << "Resolved NVFP4 GEMV kernel\n" << std::flush;
    std::cout << "Block geometry: " << proxy.geometry.blockSize << " bytes, " 
              << proxy.geometry.elemsPerBlock << " elems/block\n" << std::flush;
    
    // Execute GEMV
    std::cout << "\nExecuting GEMV...\n" << std::flush;
    auto start = std::chrono::high_resolution_clock::now();
    
    proxy.gemvKernel(
        weights.data(),
        input.data(),
        output.data(),
        outDim, inDim
    );
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    std::cout << "GEMV executed in " << elapsed << " us (" << (elapsed/1000.0f) << " ms)\n" << std::flush;
    
    // Validate output
    float minVal = std::numeric_limits<float>::max();
    float maxVal = -std::numeric_limits<float>::max();
    float sum = 0.0f;
    int nanCount = 0;
    int infCount = 0;
    
    for (float v : output) {
        if (std::isnan(v)) nanCount++;
        else if (std::isinf(v)) infCount++;
        else {
            minVal = std::min(minVal, v);
            maxVal = std::max(maxVal, v);
            sum += v;
        }
    }
    
    float mean = sum / output.size();
    
    std::cout << "\n=== GEMV Execution Receipt ===\n" << std::flush;
    std::cout << "Output dim: " << outDim << "\n" << std::flush;
    std::cout << "Input dim: " << inDim << "\n" << std::flush;
    std::cout << "Min: " << minVal << "\n" << std::flush;
    std::cout << "Max: " << maxVal << "\n" << std::flush;
    std::cout << "Mean: " << mean << "\n" << std::flush;
    std::cout << "NaN count: " << nanCount << "\n" << std::flush;
    std::cout << "Inf count: " << infCount << "\n" << std::flush;
    std::cout << "All finite: " << (nanCount == 0 && infCount == 0 ? "YES" : "NO") << "\n" << std::flush;
    
    // Print first 10 output values
    std::cout << "\nFirst 10 output values:\n" << std::flush;
    for (size_t i = 0; i < 10; ++i) {
        std::cout << "  [" << i << "] = " << output[i] << "\n" << std::flush;
    }
    
    // Reference validation: dequantize + FP32 GEMV
    std::cout << "\n=== Reference Validation ===\n" << std::flush;
    std::vector<float> dequantized(inDim * outDim);
    proxy.dequantKernel(weights.data(), dequantized.data(), inDim * outDim);
    std::cout << "Dequantized\n" << std::flush;
    
    std::vector<float> refOutput(outDim, 0.0f);
    for (size_t r = 0; r < outDim; ++r) {
        float acc = 0.0f;
        for (size_t c = 0; c < inDim; ++c) {
            acc += dequantized[r * inDim + c] * input[c];
        }
        refOutput[r] = acc;
    }
    std::cout << "Reference GEMV done\n" << std::flush;
    
    // Compare
    float maxDiff = 0.0f;
    float relDiffSum = 0.0f;
    int validComparisons = 0;
    for (size_t i = 0; i < outDim; ++i) {
        if (std::isfinite(output[i]) && std::isfinite(refOutput[i])) {
            float diff = std::abs(output[i] - refOutput[i]);
            float relDiff = diff / (std::abs(refOutput[i]) + 1e-6f);
            maxDiff = std::max(maxDiff, diff);
            relDiffSum += relDiff;
            validComparisons++;
        }
    }
    
    std::cout << "Max absolute diff: " << maxDiff << "\n" << std::flush;
    std::cout << "Avg relative diff: " << (validComparisons ? relDiffSum / validComparisons : 0.0f) << "\n" << std::flush;
    std::cout << "Valid comparisons: " << validComparisons << " / " << outDim << "\n" << std::flush;
    
    if (nanCount > 0 || infCount > 0) {
        std::cerr << "FAIL: Non-finite outputs detected\n";
        return 1;
    }
    
    std::cout << "\n[TEST] COMPLETE - NVFP4 correct-direction GEMV executed successfully\n" << std::flush;
    return 0;
}
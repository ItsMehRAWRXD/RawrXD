/* Fused Speculative LM-Head Verification with Quant-Dot Parity
 * Standalone test version without Vulkan dependencies.
 * Gate: DEEP2_SPEC_FUSED_LMHEAD_001
 */
#pragma once

#include "Deep2Speculative.hpp"
#include <vector>
#include <cstdint>
#include <chrono>

namespace Deep2 {

// Configuration for fused LM-head verification
struct FusedLMHeadVerifyConfig {
    // Enable quant-dot parity sampling during LM-head verification
    bool enableParitySampling = true;
    // 1-in-N sampling rate for parity checks (0 = disabled)
    uint32_t paritySampleEvery = 4;
    // Maximum batch size for LM-head verification
    uint32_t maxBatchSize = 4;
    // Enable reference CPU verification for sampled batches
    bool enableReferenceCheck = true;
    // Log parity results
    bool logParityResults = true;
};

// Result of fused LM-head verification
struct FusedLMHeadVerifyResult {
    // Whether verification succeeded
    bool success = false;
    // Verified token IDs
    std::vector<int32_t> verifiedTokens;
    // Parity samples collected during verification
    uint32_t paritySamplesCollected = 0;
    // Reference mismatches detected
    uint32_t referenceMismatches = 0;
    // GPU time for verification (nanoseconds)
    uint64_t gpuVerifyNs = 0;
    // Reference verification time (nanoseconds)
    uint64_t referenceVerifyNs = 0;
    // Whether GPU path was used (vs CPU fallback)
    bool gpuPathUsed = false;
};

// Reference CPU implementation for Q4_K GEMV (for parity verification)
struct Q4KReferenceGEMV {
    // Compute reference Q4_K GEMV on CPU
    static void computeReference(const void* weights, size_t weightBytes,
                                 const float* input, float* output,
                                 uint32_t rows, uint32_t cols);
    
    // Compare GPU output with reference, return max absolute difference
    static float compareWithReference(const float* gpuOutput, const float* refOutput,
                                      uint32_t rows, uint32_t batch);
};

// Fused verification context - manages state across verification calls
struct FusedLMHeadVerifyContext {
    FusedLMHeadVerifyConfig config;
    
    // Scratch buffers (reused across calls to reduce allocations)
    std::vector<float> normScratch;
    std::vector<float> logitsScratch;
    std::vector<float> refLogitsScratch;
    
    // Statistics
    uint64_t totalVerifications = 0;
    uint64_t paritySamplesCollected = 0;
    uint64_t referenceMismatches = 0;
    uint64_t gpuVerifyNsTotal = 0;
    uint64_t referenceVerifyNsTotal = 0;
    
    // Parity verification queue (batched for efficiency)
    struct ParityBatch {
        std::vector<float> inputBatch;
        std::vector<float> gpuOutputBatch;
        std::vector<float> refOutputBatch;
        uint32_t rows = 0;
        uint32_t cols = 0;
        uint32_t batch = 0;
        uint64_t epoch = 0;
        bool valid = false;
    };
    ParityBatch pendingBatch;
    
    FusedLMHeadVerifyContext() = default;
    
    void reset() {
        pendingBatch.valid = false;
        normScratch.clear();
        logitsScratch.clear();
        refLogitsScratch.clear();
    }
    
    void ensureScratch(size_t batch, size_t hiddenDim, size_t vocabSize) {
        size_t normSize = batch * hiddenDim;
        size_t logitsSize = batch * vocabSize;
        if (normScratch.size() < normSize) normScratch.resize(normSize);
        if (logitsScratch.size() < logitsSize) logitsScratch.resize(logitsSize);
        if (refLogitsScratch.size() < logitsSize) refLogitsScratch.resize(logitsSize);
    }
};

} // namespace Deep2
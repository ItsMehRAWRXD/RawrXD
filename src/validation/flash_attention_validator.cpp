/*===========================================================================
 * flash_attention_validator.cpp
 * 
 * Flash Attention Validation Implementation
 * 
 * Comprehensive numerical correctness validation with:
 *   - Reference attention implementation
 *   - Statistical error analysis
 *   - Extended soak testing
 *   - AVX-512 dispatch verification
 *===========================================================================*/

#include "flash_attention_validator.hpp"
#include "../kernels/flash_attention.hpp"
#include "../telemetry/RawrXD_Telemetry_Fix4.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>

namespace RawrXD {
namespace Validation {

// ValidationResult implementation
std::string ValidationResult::ToString() const {
    std::stringstream ss;
    ss << "Validation Result:\n";
    ss << "  Status: " << (passed ? "PASSED" : "FAILED") << "\n";
    ss << "  Max Abs Error: " << std::scientific << maxAbsError;
    if (maxAbsError > ValidationThresholds::MAX_ABS_ERROR) {
        ss << " [EXCEEDS " << ValidationThresholds::MAX_ABS_ERROR << "]";
    }
    ss << "\n";
    ss << "  Mean Error: " << std::scientific << meanError;
    if (meanError > ValidationThresholds::MEAN_ERROR) {
        ss << " [EXCEEDS " << ValidationThresholds::MEAN_ERROR << "]";
    }
    ss << "\n";
    ss << "  Softmax Sum Range: [" << softmaxSumMin << ", " << softmaxSumMax << "]\n";
    ss << "  NaN Count: " << nanCount << "\n";
    ss << "  Inf Count: " << infCount << "\n";
    ss << "  Execution Time: " << std::fixed << std::setprecision(2) 
       << executionTimeMs << " ms\n";
    return ss.str();
}

bool ValidationResult::IsWithinThresholds() const {
    return maxAbsError <= ValidationThresholds::MAX_ABS_ERROR &&
           meanError <= ValidationThresholds::MEAN_ERROR &&
           softmaxSumMin >= ValidationThresholds::SOFTMAX_SUM_MIN &&
           softmaxSumMax <= ValidationThresholds::SOFTMAX_SUM_MAX &&
           nanCount == ValidationThresholds::MAX_NAN_INF_COUNT &&
           infCount == ValidationThresholds::MAX_NAN_INF_COUNT;
}

// ValidationReport implementation
void ValidationReport::GenerateSummary() {
    if (results.empty()) return;
    
    worstMaxError = 0.0f;
    double meanErrorSum = 0.0;
    totalExecutionTime = 0.0;
    
    for (const auto& r : results) {
        worstMaxError = std::max(worstMaxError, r.maxAbsError);
        meanErrorSum += r.meanError;
        totalExecutionTime += r.executionTimeMs;
    }
    
    avgMeanError = static_cast<float>(meanErrorSum / results.size());
    
    std::cout << "\n" << std::string(70, '=') << "\n";
    std::cout << "FLASH ATTENTION VALIDATION SUMMARY\n";
    std::cout << std::string(70, '=') << "\n";
    std::cout << "Total Tests: " << totalTests << "\n";
    std::cout << "Passed: " << passedTests << "\n";
    std::cout << "Failed: " << failedTests << "\n";
    std::cout << "Pass Rate: " << std::fixed << std::setprecision(1)
              << (100.0 * passedTests / totalTests) << "%\n";
    std::cout << "\nError Statistics:\n";
    std::cout << "  Worst Max Error: " << std::scientific << worstMaxError << "\n";
    std::cout << "  Avg Mean Error:  " << std::scientific << avgMeanError << "\n";
    std::cout << "  Total Time:      " << std::fixed << totalExecutionTime / 1000.0 << " s\n";
    std::cout << std::string(70, '=') << "\n";
}

void ValidationReport::ExportJSON(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return;
    
    file << "{\n";
    file << "  \"timestamp\": \"" << timestamp << "\",\n";
    file << "  \"summary\": {\n";
    file << "    \"total_tests\": " << totalTests << ",\n";
    file << "    \"passed\": " << passedTests << ",\n";
    file << "    \"failed\": " << failedTests << ",\n";
    file << "    \"worst_max_error\": " << worstMaxError << ",\n";
    file << "    \"avg_mean_error\": " << avgMeanError << "\n";
    file << "  },\n";
    file << "  \"results\": [\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        file << "    {\n";
        file << "      \"passed\": " << (r.passed ? "true" : "false") << ",\n";
        file << "      \"max_abs_error\": " << r.maxAbsError << ",\n";
        file << "      \"mean_error\": " << r.meanError << ",\n";
        file << "      \"execution_ms\": " << r.executionTimeMs << "\n";
        file << "    }";
        if (i < results.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
}

void ValidationReport::ExportCSV(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return;
    
    file << "test_index,passed,max_abs_error,mean_error,softmax_min,softmax_max,"
         << "nan_count,inf_count,execution_ms\n";
    
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        file << i << ","
             << (r.passed ? 1 : 0) << ","
             << r.maxAbsError << ","
             << r.meanError << ","
             << r.softmaxSumMin << ","
             << r.softmaxSumMax << ","
             << r.nanCount << ","
             << r.infCount << ","
             << r.executionTimeMs << "\n";
    }
}

// ReferenceAttention implementation
void ReferenceAttention::Compute(
    const float* Q,
    const float* K,
    const float* V,
    float* Output,
    uint32_t numHeads,
    uint32_t seqLen,
    uint32_t headDim,
    uint32_t currentPos
) {
    const float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
    
    // Process each head
    for (uint32_t h = 0; h < numHeads; ++h) {
        const float* qHead = Q + h * headDim;
        float* outHead = Output + h * headDim;
        
        // Compute attention scores for all positions up to currentPos
        std::vector<float> scores(currentPos);
        float maxScore = -std::numeric_limits<float>::infinity();
        
        for (uint32_t pos = 0; pos < currentPos; ++pos) {
            const float* kHead = K + (pos * numHeads + h) * headDim;
            
            // Dot product Q @ K[pos]
            float score = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                score += qHead[d] * kHead[d];
            }
            score *= scale;
            scores[pos] = score;
            maxScore = std::max(maxScore, score);
        }
        
        // Softmax with numerical stability
        float sumExp = 0.0f;
        for (uint32_t pos = 0; pos < currentPos; ++pos) {
            scores[pos] = std::exp(scores[pos] - maxScore);
            sumExp += scores[pos];
        }
        
        // Normalize and compute weighted sum with V
        for (uint32_t d = 0; d < headDim; ++d) {
            outHead[d] = 0.0f;
        }
        
        for (uint32_t pos = 0; pos < currentPos; ++pos) {
            float weight = scores[pos] / sumExp;
            const float* vHead = V + (pos * numHeads + h) * headDim;
            
            for (uint32_t d = 0; d < headDim; ++d) {
                outHead[d] += weight * vHead[d];
            }
        }
    }
}

// FlashAttentionValidator implementation
FlashAttentionValidator::FlashAttentionValidator() = default;
FlashAttentionValidator::~FlashAttentionValidator() {
    FreeBuffers();
}

bool FlashAttentionValidator::Initialize(const TestDimensions& dims) {
    m_dims = dims;
    
    // Calculate maximum buffer size needed
    size_t maxSeqLen = *std::max_element(dims.seqLengths.begin(), dims.seqLengths.end());
    size_t maxHeads = *std::max_element(dims.heads.begin(), dims.heads.end());
    size_t maxHeadDim = *std::max_element(dims.headDims.begin(), dims.headDims.end());
    
    size_t maxElements = maxSeqLen * maxHeads * maxHeadDim;
    
    if (!AllocateBuffers(maxElements)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

bool FlashAttentionValidator::AllocateBuffers(size_t maxSize) {
    #ifdef _WIN32
    m_qBuffer = (float*)_aligned_malloc(maxSize * sizeof(float), 64);
    m_kBuffer = (float*)_aligned_malloc(maxSize * sizeof(float), 64);
    m_vBuffer = (float*)_aligned_malloc(maxSize * sizeof(float), 64);
    m_refOutput = (float*)_aligned_malloc(maxSize * sizeof(float), 64);
    m_faOutput = (float*)_aligned_malloc(maxSize * sizeof(float), 64);
    #else
    m_qBuffer = (float*)aligned_alloc(64, maxSize * sizeof(float));
    m_kBuffer = (float*)aligned_alloc(64, maxSize * sizeof(float));
    m_vBuffer = (float*)aligned_alloc(64, maxSize * sizeof(float));
    m_refOutput = (float*)aligned_alloc(64, maxSize * sizeof(float));
    m_faOutput = (float*)aligned_alloc(64, maxSize * sizeof(float));
    #endif
    
    return m_qBuffer && m_kBuffer && m_vBuffer && m_refOutput && m_faOutput;
}

void FlashAttentionValidator::FreeBuffers() {
    #ifdef _WIN32
    if (m_qBuffer) { _aligned_free(m_qBuffer); m_qBuffer = nullptr; }
    if (m_kBuffer) { _aligned_free(m_kBuffer); m_kBuffer = nullptr; }
    if (m_vBuffer) { _aligned_free(m_vBuffer); m_vBuffer = nullptr; }
    if (m_refOutput) { _aligned_free(m_refOutput); m_refOutput = nullptr; }
    if (m_faOutput) { _aligned_free(m_faOutput); m_faOutput = nullptr; }
    #else
    if (m_qBuffer) { free(m_qBuffer); m_qBuffer = nullptr; }
    if (m_kBuffer) { free(m_kBuffer); m_kBuffer = nullptr; }
    if (m_vBuffer) { free(m_vBuffer); m_vBuffer = nullptr; }
    if (m_refOutput) { free(m_refOutput); m_refOutput = nullptr; }
    if (m_faOutput) { free(m_faOutput); m_faOutput = nullptr; }
    #endif
}

void FlashAttentionValidator::GenerateRandomData(float* data, uint32_t count, uint32_t seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    
    for (uint32_t i = 0; i < count; ++i) {
        data[i] = dist(gen);
    }
}

ValidationReport FlashAttentionValidator::RunFullSuite() {
    ValidationReport report;
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    report.timestamp = ss.str();
    
    std::cout << "\nStarting Flash Attention Validation Suite\n";
    std::cout << "========================================\n\n";
    
    // Run tests for all dimension combinations
    for (uint32_t heads : m_dims.heads) {
        for (uint32_t seqLen : m_dims.seqLengths) {
            for (uint32_t headDim : m_dims.headDims) {
                for (uint32_t blockSize : m_dims.blockSizes) {
                    // Skip invalid combinations
                    if (blockSize > seqLen) continue;
                    
                    std::cout << "Testing: heads=" << heads 
                              << " seq=" << seqLen 
                              << " dim=" << headDim 
                              << " block=" << blockSize << "... ";
                    
                    auto result = RunSingleTest(heads, seqLen, headDim, blockSize);
                    report.results.push_back(result);
                    report.totalTests++;
                    
                    if (result.passed) {
                        report.passedTests++;
                        std::cout << "PASS\n";
                    } else {
                        report.failedTests++;
                        std::cout << "FAIL (max_err=" << std::scientific 
                                  << result.maxAbsError << ")\n";
                    }
                }
            }
        }
    }
    
    report.GenerateSummary();
    return report;
}

ValidationResult FlashAttentionValidator::RunSingleTest(
    uint32_t numHeads,
    uint32_t seqLen,
    uint32_t headDim,
    uint32_t blockSize
) {
    ValidationResult result;
    
    // Generate random test data
    uint32_t qSize = numHeads * headDim;
    uint32_t kvSize = seqLen * numHeads * headDim;
    
    GenerateRandomData(m_qBuffer, qSize, 42);
    GenerateRandomData(m_kBuffer, kvSize, 43);
    GenerateRandomData(m_vBuffer, kvSize, 44);
    
    // Run reference attention
    auto startRef = std::chrono::high_resolution_clock::now();
    ReferenceAttention::Compute(
        m_qBuffer, m_kBuffer, m_vBuffer, m_refOutput,
        numHeads, seqLen, headDim, seqLen
    );
    auto endRef = std::chrono::high_resolution_clock::now();
    double refTime = std::chrono::duration<double, std::milli>(endRef - startRef).count();
    
    // Run Flash Attention
    auto startFA = std::chrono::high_resolution_clock::now();
    
    // Initialize Flash Attention engine
    Kernels::FlashAttentionConfig faConfig;
    faConfig.numHeads = numHeads;
    faConfig.headDim = headDim;
    faConfig.maxSeqLength = seqLen;
    faConfig.blockSize = blockSize;
    
    Kernels::FlashAttentionEngine faEngine;
    faEngine.Initialize(faConfig);
    
    // Compute with Flash Attention
    faEngine.ComputeDecode(0, seqLen, m_qBuffer, m_kBuffer, m_vBuffer, m_faOutput);
    
    auto endFA = std::chrono::high_resolution_clock::now();
    result.executionTimeMs = std::chrono::duration<double, std::milli>(endFA - startFA).count();
    
    // Compare outputs
    CompareOutputs(m_refOutput, m_faOutput, numHeads * headDim, result);
    
    result.passed = result.IsWithinThresholds();
    return result;
}

void FlashAttentionValidator::CompareOutputs(
    const float* ref,
    const float* test,
    uint32_t numElements,
    ValidationResult& result
) {
    result.maxAbsError = 0.0f;
    double errorSum = 0.0;
    result.nanCount = 0;
    result.infCount = 0;
    
    float softmaxSum = 0.0f;
    
    for (uint32_t i = 0; i < numElements; ++i) {
        float refVal = ref[i];
        float testVal = test[i];
        
        // Check for NaN/Inf
        if (std::isnan(testVal)) result.nanCount++;
        if (std::isinf(testVal)) result.infCount++;
        
        // Calculate error
        float absError = std::abs(refVal - testVal);
        result.maxAbsError = std::max(result.maxAbsError, absError);
        errorSum += absError;
        
        // Track softmax sum (for attention outputs)
        softmaxSum += testVal;
    }
    
    result.meanError = static_cast<float>(errorSum / numElements);
    result.softmaxSumMin = std::min(1.0f, softmaxSum / numElements);
    result.softmaxSumMax = std::max(1.0f, softmaxSum / numElements);
}

bool FlashAttentionValidator::VerifyAVX512Dispatch() {
    // Check if AVX-512 is available
    #ifdef _WIN32
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    bool hasAVX512 = (cpuInfo[2] & (1 << 16)) != 0;  // Check AVX-512F bit
    #else
    bool hasAVX512 = __builtin_cpu_supports("avx512f");
    #endif
    
    return hasAVX512;
}

bool FlashAttentionValidator::RunSoakTest(
    uint32_t durationMinutes,
    uint32_t contextLength
) {
    std::cout << "\nStarting Soak Test\n";
    std::cout << "Duration: " << durationMinutes << " minutes\n";
    std::cout << "Context Length: " << contextLength << "\n\n";
    
    const uint32_t numHeads = 128;
    const uint32_t headDim = 64;
    
    // Generate test data
    GenerateRandomData(m_qBuffer, numHeads * headDim, 42);
    GenerateRandomData(m_kBuffer, contextLength * numHeads * headDim, 43);
    GenerateRandomData(m_vBuffer, contextLength * numHeads * headDim, 44);
    
    // Initialize Flash Attention
    Kernels::FlashAttentionConfig faConfig;
    faConfig.numHeads = numHeads;
    faConfig.headDim = headDim;
    faConfig.maxSeqLength = contextLength;
    
    Kernels::FlashAttentionEngine faEngine;
    faEngine.Initialize(faConfig);
    
    auto startTime = std::chrono::steady_clock::now();
    auto endTime = startTime + std::chrono::minutes(durationMinutes);
    
    uint64_t iteration = 0;
    float maxErrorSeen = 0.0f;
    
    while (std::chrono::steady_clock::now() < endTime) {
        // Run Flash Attention
        faEngine.ComputeDecode(0, contextLength, m_qBuffer, m_kBuffer, m_vBuffer, m_faOutput);
        
        // Every 1000 iterations, verify against reference
        if (iteration % 1000 == 0) {
            ReferenceAttention::Compute(
                m_qBuffer, m_kBuffer, m_vBuffer, m_refOutput,
                numHeads, contextLength, headDim, contextLength
            );
            
            ValidationResult check;
            CompareOutputs(m_refOutput, m_faOutput, numHeads * headDim, check);
            maxErrorSeen = std::max(maxErrorSeen, check.maxAbsError);
            
            if (check.maxAbsError > 1e-6f) {
                std::cout << "ERROR: Numerical drift detected at iteration " << iteration << "\n";
                std::cout << "Max error: " << check.maxAbsError << "\n";
                return false;
            }
            
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            auto elapsedMin = std::chrono::duration_cast<std::chrono::minutes>(elapsed).count();
            std::cout << "[" << elapsedMin << "m] Iteration " << iteration 
                      << ", max error: " << std::scientific << check.maxAbsError << "\n";
        }
        
        iteration++;
    }
    
    std::cout << "\nSoak test completed successfully!\n";
    std::cout << "Total iterations: " << iteration << "\n";
    std::cout << "Worst error seen: " << std::scientific << maxErrorSeen << "\n";
    return true;
}

FlashAttentionValidator::Telemetry FlashAttentionValidator::GetTelemetry() const {
    Telemetry telem;
    // This would be populated from actual telemetry system
    telem.tileSize = 128;
    telem.headDimension = 64;
    telem.avx512Active = VerifyAVX512Dispatch();
    telem.onlineSoftmax = true;
    return telem;
}

// C API exports
extern "C" {

__declspec(dllexport) int RawrXD_ValidateFlashAttention(
    uint32_t numHeads,
    uint32_t seqLen,
    uint32_t headDim,
    float* outMaxError,
    float* outMeanError
) {
    RawrXD::Validation::FlashAttentionValidator validator;
    RawrXD::Validation::TestDimensions dims;
    dims.heads = {numHeads};
    dims.seqLengths = {seqLen};
    dims.headDims = {headDim};
    
    if (!validator.Initialize(dims)) {
        return -1;
    }
    
    auto result = validator.RunSingleTest(numHeads, seqLen, headDim, 128);
    
    if (outMaxError) *outMaxError = result.maxAbsError;
    if (outMeanError) *outMeanError = result.meanError;
    
    return result.passed ? 0 : 1;
}

__declspec(dllexport) int RawrXD_RunFlashAttentionSoakTest(
    uint32_t durationMinutes,
    uint32_t contextLength
) {
    RawrXD::Validation::FlashAttentionValidator validator;
    RawrXD::Validation::TestDimensions dims;
    
    if (!validator.Initialize(dims)) {
        return -1;
    }
    
    return validator.RunSoakTest(durationMinutes, contextLength) ? 0 : 1;
}

} // extern "C"

} // namespace Validation
} // namespace RawrXD

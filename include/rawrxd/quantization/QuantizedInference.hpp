#pragma once

#include "rawrxd/quantization/Quantizer.hpp"
#include "rawrxd/inference/InferenceEngine.hpp"
#include <memory>
#include <functional>

namespace rawrxd {
namespace quantization {

// Quantized inference configuration
struct QuantizedInferenceConfig {
    // Model paths
    std::string quantizedModelPath;
    std::string originalModelPath;  // For comparison/fallback
    
    // Runtime options
    bool allowFallback = true;          // Allow fallback to FP16 if needed
    bool useMixedPrecision = true;      // Use FP16 for certain ops
    bool cacheDequantized = false;      // Cache dequantized weights
    
    // Performance
    int numThreads = 0;                 // 0 = auto
    bool useSIMD = true;
    bool useGPU = true;
    
    // Memory
    size_t maxCacheSizeMB = 1024;     // Max cache size for dequantized weights
};

// Quantized inference engine wrapper
class QuantizedInferenceEngine {
public:
    QuantizedInferenceEngine();
    ~QuantizedInferenceEngine();

    // Initialize with quantized model
    bool Initialize(const QuantizedInferenceConfig& config);
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Generate text
    std::string Generate(const std::string& prompt, int maxTokens = 512);
    
    // Generate with callback
    using TokenCallback = std::function<void(const std::string& token, bool isComplete)>;
    bool GenerateStreaming(const std::string& prompt, TokenCallback callback, int maxTokens = 512);
    
    // Get performance stats
    struct PerformanceStats {
        float avgTokensPerSecond = 0.0f;
        float avgDequantizeTimeMs = 0.0f;
        float cacheHitRate = 0.0f;
        size_t cacheSizeMB = 0;
        int fallbackCount = 0;
    };
    PerformanceStats GetPerformanceStats() const;
    
    // Compare with original (if available)
    struct ComparisonResult {
        float speedup = 1.0f;
        float memoryReduction = 1.0f;
        float qualityRetention = 100.0f;
    };
    ComparisonResult CompareWithOriginal(const std::string& testPrompt);
    
    // Get last error
    std::string GetLastError() const { return lastError_; }

private:
    QuantizedInferenceConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Internal inference engine
    std::unique_ptr<InferenceEngine> engine_;
    
    // Cache for dequantized weights
    std::unordered_map<std::string, std::vector<float>> weightCache_;
    size_t currentCacheSize_ = 0;
    
    // Performance tracking
    int inferenceCount_ = 0;
    float totalTokensPerSecond_ = 0.0f;
    int cacheHits_ = 0;
    int cacheMisses_ = 0;
    int fallbackCount_ = 0;
    
    // Internal methods
    bool LoadQuantizedModel();
    std::vector<float> GetLayerWeights(const std::string& layerName);
    void UpdateCache(const std::string& layerName, const std::vector<float>& weights);
    void EvictFromCache(size_t requiredSpace);
};

// Quantized kernel interface
class QuantizedKernels {
public:
    // Matrix multiplication with quantized weights
    static void QuantizedMatMul(const QuantizedTensor& weights,
                                const std::vector<float>& input,
                                std::vector<float>& output,
                                int m, int n, int k);
    
    // Dequantize on-the-fly during matmul
    static void DequantizeMatMul(const uint8_t* quantizedData,
                                   const float* scales,
                                   const float* zeroPoints,
                                   const float* input,
                                   float* output,
                                   int m, int n, int k,
                                   int bits, int groupSize);
    
    // SIMD-accelerated dequantization
    static void DequantizeSIMD(const QuantizedTensor& qtensor,
                               std::vector<float>& output);
    
    // Check SIMD support
    static bool HasAVX2();
    static bool HasAVX512();
    static bool HasNEON();  // ARM
};

} // namespace quantization
} // namespace rawrxd

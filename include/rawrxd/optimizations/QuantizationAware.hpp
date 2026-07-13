#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <string>

namespace rawrxd {
namespace optimizations {

// Quantization types for inference
enum class QuantType {
    Q4_0,      // 4-bit, block size 32
    Q4_1,      // 4-bit with separate min/max
    Q5_0,      // 5-bit
    Q5_1,      // 5-bit with separate min/max
    Q8_0,      // 8-bit, block size 32
    Q8_1,      // 8-bit with separate min/max
    Q6_K,      // 6-bit K-quants
    Q5_K,      // 5-bit K-quants
    Q4_K,      // 4-bit K-quants
    Q3_K,      // 3-bit K-quants
    Q2_K,      // 2-bit K-quants
    IQ4_XS,    // 4-bit importance-aware
    IQ4_NL,    // 4-bit non-linear
    F16,       // Half precision
    BF16,      // BFloat16
    FP8_E4M3,  // FP8 E4M3 format
    FP8_E5M2   // FP8 E5M2 format
};

// Quantization block
struct QuantBlock {
    std::vector<uint8_t> data;
    float scale = 1.0f;
    float min = 0.0f;
    int blockSize = 32;
    QuantType type = QuantType::Q4_0;
};

// Quantized tensor
class QuantizedTensor {
public:
    QuantizedTensor();
    ~QuantizedTensor();
    
    // Quantize from float
    bool Quantize(const float* data, int numElements, QuantType type);
    
    // Dequantize to float
    bool Dequantize(float* output, int numElements) const;
    
    // Get quantized data
    const std::vector<QuantBlock>& GetBlocks() const { return blocks_; }
    
    // Get memory size
    size_t GetSizeBytes() const;
    
    // Get original size
    size_t GetOriginalSizeBytes() const { return originalSizeBytes_; }
    
    // Get compression ratio
    float GetCompressionRatio() const;
    
    // Get quantization type
    QuantType GetType() const { return type_; }

private:
    std::vector<QuantBlock> blocks_;
    int numElements_ = 0;
    QuantType type_ = QuantType::Q4_0;
    size_t originalSizeBytes_ = 0;
    
    // Quantization helpers
    void QuantizeBlockQ4_0(const float* data, int offset, int size, QuantBlock& block);
    void QuantizeBlockQ8_0(const float* data, int offset, int size, QuantBlock& block);
    void QuantizeBlockQ4_K(const float* data, int offset, int size, QuantBlock& block);
    void QuantizeBlockQ6_K(const float* data, int offset, int size, QuantBlock& block);
    
    void DequantizeBlockQ4_0(const QuantBlock& block, float* output, int offset, int size) const;
    void DequantizeBlockQ8_0(const QuantBlock& block, float* output, int offset, int size) const;
    void DequantizeBlockQ4_K(const QuantBlock& block, float* output, int offset, int size) const;
    void DequantizeBlockQ6_K(const QuantBlock& block, float* output, int offset, int size) const;
};

// Quantized linear layer
class QuantizedLinear {
public:
    QuantizedLinear();
    ~QuantizedLinear();
    
    // Initialize from float weights
    bool Initialize(const float* weights, int inFeatures, int outFeatures,
                    QuantType weightType = QuantType::Q4_0,
                    bool quantizeActivations = false);
    
    // Forward pass
    bool Forward(const float* input, float* output,
                 int batchSize, int seqLen);
    
    // Forward with quantized activations
    bool ForwardQuantized(const QuantizedTensor& input, QuantizedTensor& output,
                          int batchSize, int seqLen);
    
    // Get quantization info
    QuantType GetWeightType() const { return weightType_; }
    QuantType GetActivationType() const { return activationType_; }

private:
    QuantizedTensor weights_;
    std::vector<float> bias_;
    int inFeatures_ = 0;
    int outFeatures_ = 0;
    
    QuantType weightType_ = QuantType::Q4_0;
    QuantType activationType_ = QuantType::Q8_0;
    bool quantizeActivations_ = false;
    
    // Quantized GEMM
    void QuantizedGEMM(const QuantizedTensor& A, const QuantizedTensor& B,
                       QuantizedTensor& C, int M, int N, int K);
};

// Mixed-precision configuration
struct MixedPrecisionConfig {
    QuantType attentionWeights = QuantType::Q4_K;
    QuantType ffnWeights = QuantType::Q6_K;
    QuantType embeddingWeights = QuantType::Q8_0;
    QuantType activationType = QuantType::Q8_0;
    bool useFP16ForAttention = true;
    bool useFP16ForNorm = true;
};

// Quantization-aware model converter
class QuantizationConverter {
public:
    // Convert model to quantized format
    static bool ConvertModel(const std::string& inputPath,
                              const std::string& outputPath,
                              const MixedPrecisionConfig& config);
    
    // Estimate quantized model size
    static size_t EstimateSize(const std::string& modelPath,
                               const MixedPrecisionConfig& config);
    
    // Recommend quantization config based on model and target size
    static MixedPrecisionConfig RecommendConfig(const std::string& modelPath,
                                                 size_t targetSizeMB);
    
    // Evaluate quantization quality
    struct QualityMetrics {
        float perplexityIncrease = 0.0f;
        float accuracyDrop = 0.0f;
        float compressionRatio = 0.0f;
    };
    static QualityMetrics EvaluateQuality(const std::string& originalPath,
                                          const std::string& quantizedPath,
                                          const std::vector<std::string>& testPrompts);
};

// Dynamic quantization (runtime quantization)
class DynamicQuantizer {
public:
    DynamicQuantizer();
    ~DynamicQuantizer();
    
    // Calibrate on sample data
    bool Calibrate(const std::vector<std::vector<float>>& sampleActivations);
    
    // Quantize activation dynamically
    QuantizedTensor QuantizeActivation(const float* activation, int numElements);
    
    // Get optimal scale for tensor
    float ComputeScale(const float* data, int numElements);

private:
    std::vector<float> observedRanges_;
    bool calibrated_ = false;
};

// Quantized KV cache
class QuantizedKVCache {
public:
    QuantizedKVCache();
    ~QuantizedKVCache();
    
    // Initialize
    bool Initialize(int numLayers, int numHeads, int headDim, 
                    int maxSeqLen, QuantType type = QuantType::Q8_0);
    
    // Store KV values
    void Store(int layer, int head, int seqPos,
               const float* key, const float* value);
    
    // Retrieve KV values
    bool Retrieve(int layer, int head, int seqPos,
                  float* key, float* value);
    
    // Get memory usage
    size_t GetMemoryUsage() const;
    
    // Get compression ratio vs FP32
    float GetCompressionRatio() const;

private:
    int numLayers_ = 0;
    int numHeads_ = 0;
    int headDim_ = 0;
    int maxSeqLen_ = 0;
    QuantType type_ = QuantType::Q8_0;
    
    // Quantized storage
    std::vector<QuantizedTensor> kCaches_;
    std::vector<QuantizedTensor> vCaches_;
    
    size_t fp32Size_ = 0;
};

// Quantization benchmark
class QuantizationBenchmark {
public:
    struct Result {
        QuantType type;
        float compressionRatio;
        float dequantizeTimeMs;
        float gemmTimeMs;
        float accuracyLoss;
        float throughputTokensPerSec;
    };
    
    // Benchmark specific quantization type
    static Result BenchmarkType(QuantType type, 
                                 const std::vector<float>& testWeights,
                                 const std::vector<float>& testActivations);
    
    // Benchmark all types
    static std::vector<Result> BenchmarkAll(
        const std::vector<float>& testWeights,
        const std::vector<float>& testActivations);
    
    // Generate report
    static std::string GenerateReport(const std::vector<Result>& results);
};

} // namespace optimizations
} // namespace rawrxd

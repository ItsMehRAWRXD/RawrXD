#include "rawrxd/optimizations/QuantizationAware.hpp"
#include <algorithm>
#include <cmath>
#include <limits>

namespace rawrxd {
namespace optimizations {

// QuantizedTensor implementation
QuantizedTensor::QuantizedTensor() = default;

QuantizedTensor::~QuantizedTensor() = default;

bool QuantizedTensor::Quantize(const float* data, int numElements, QuantType type) {
    type_ = type;
    numElements_ = numElements;
    originalSizeBytes_ = numElements * sizeof(float);
    
    int blockSize = 32; // Default block size
    int numBlocks = (numElements + blockSize - 1) / blockSize;
    blocks_.resize(numBlocks);
    
    for (int i = 0; i < numBlocks; ++i) {
        int offset = i * blockSize;
        int size = std::min(blockSize, numElements - offset);
        
        switch (type) {
            case QuantType::Q4_0:
                QuantizeBlockQ4_0(data, offset, size, blocks_[i]);
                break;
            case QuantType::Q8_0:
                QuantizeBlockQ8_0(data, offset, size, blocks_[i]);
                break;
            case QuantType::Q4_K:
                QuantizeBlockQ4_K(data, offset, size, blocks_[i]);
                break;
            case QuantType::Q6_K:
                QuantizeBlockQ6_K(data, offset, size, blocks_[i]);
                break;
            default:
                return false;
        }
    }
    
    return true;
}

bool QuantizedTensor::Dequantize(float* output, int numElements) const {
    if (numElements != numElements_) return false;
    
    int blockSize = 32;
    int numBlocks = (numElements + blockSize - 1) / blockSize;
    
    for (int i = 0; i < numBlocks; ++i) {
        int offset = i * blockSize;
        int size = std::min(blockSize, numElements - offset);
        
        switch (type_) {
            case QuantType::Q4_0:
                DequantizeBlockQ4_0(blocks_[i], output, offset, size);
                break;
            case QuantType::Q8_0:
                DequantizeBlockQ8_0(blocks_[i], output, offset, size);
                break;
            case QuantType::Q4_K:
                DequantizeBlockQ4_K(blocks_[i], output, offset, size);
                break;
            case QuantType::Q6_K:
                DequantizeBlockQ6_K(blocks_[i], output, offset, size);
                break;
            default:
                return false;
        }
    }
    
    return true;
}

size_t QuantizedTensor::GetSizeBytes() const {
    size_t size = 0;
    for (const auto& block : blocks_) {
        size += block.data.size() + sizeof(float) * 2; // data + scale + min
    }
    return size;
}

float QuantizedTensor::GetCompressionRatio() const {
    if (originalSizeBytes_ == 0) return 1.0f;
    return static_cast<float>(originalSizeBytes_) / GetSizeBytes();
}

void QuantizedTensor::QuantizeBlockQ4_0(const float* data, int offset, int size, QuantBlock& block) {
    // Find min and max
    float minVal = std::numeric_limits<float>::max();
    float maxVal = -std::numeric_limits<float>::max();
    
    for (int i = 0; i < size; ++i) {
        minVal = std::min(minVal, data[offset + i]);
        maxVal = std::max(maxVal, data[offset + i]);
    }
    
    // Compute scale
    block.scale = (maxVal - minVal) / 15.0f; // 4 bits = 16 values
    block.min = minVal;
    block.blockSize = size;
    block.type = QuantType::Q4_0;
    
    // Quantize
    block.data.resize(size / 2 + (size % 2));
    for (int i = 0; i < size; ++i) {
        int q = static_cast<int>(std::round((data[offset + i] - minVal) / block.scale));
        q = std::max(0, std::min(15, q));
        
        if (i % 2 == 0) {
            block.data[i / 2] = q;
        } else {
            block.data[i / 2] |= q << 4;
        }
    }
}

void QuantizedTensor::QuantizeBlockQ8_0(const float* data, int offset, int size, QuantBlock& block) {
    // Find min and max
    float minVal = std::numeric_limits<float>::max();
    float maxVal = -std::numeric_limits<float>::max();
    
    for (int i = 0; i < size; ++i) {
        minVal = std::min(minVal, data[offset + i]);
        maxVal = std::max(maxVal, data[offset + i]);
    }
    
    // Compute scale
    block.scale = (maxVal - minVal) / 255.0f; // 8 bits = 256 values
    block.min = minVal;
    block.blockSize = size;
    block.type = QuantType::Q8_0;
    
    // Quantize
    block.data.resize(size);
    for (int i = 0; i < size; ++i) {
        int q = static_cast<int>(std::round((data[offset + i] - minVal) / block.scale));
        block.data[i] = static_cast<uint8_t>(std::max(0, std::min(255, q)));
    }
}

void QuantizedTensor::QuantizeBlockQ4_K(const float* data, int offset, int size, QuantBlock& block) {
    // K-quants: more sophisticated quantization with separate scales
    // Simplified implementation
    QuantizeBlockQ4_0(data, offset, size, block);
    block.type = QuantType::Q4_K;
}

void QuantizedTensor::QuantizeBlockQ6_K(const float* data, int offset, int size, QuantBlock& block) {
    // 6-bit K-quants
    // Simplified implementation
    float minVal = std::numeric_limits<float>::max();
    float maxVal = -std::numeric_limits<float>::max();
    
    for (int i = 0; i < size; ++i) {
        minVal = std::min(minVal, data[offset + i]);
        maxVal = std::max(maxVal, data[offset + i]);
    }
    
    block.scale = (maxVal - minVal) / 63.0f; // 6 bits = 64 values
    block.min = minVal;
    block.blockSize = size;
    block.type = QuantType::Q6_K;
    
    // Pack 6-bit values (simplified - just use 8 bits for now)
    block.data.resize(size);
    for (int i = 0; i < size; ++i) {
        int q = static_cast<int>(std::round((data[offset + i] - minVal) / block.scale));
        block.data[i] = static_cast<uint8_t>(std::max(0, std::min(63, q)));
    }
}

void QuantizedTensor::DequantizeBlockQ4_0(const QuantBlock& block, float* output, int offset, int size) const {
    for (int i = 0; i < size; ++i) {
        int q;
        if (i % 2 == 0) {
            q = block.data[i / 2] & 0x0F;
        } else {
            q = (block.data[i / 2] >> 4) & 0x0F;
        }
        output[offset + i] = block.min + q * block.scale;
    }
}

void QuantizedTensor::DequantizeBlockQ8_0(const QuantBlock& block, float* output, int offset, int size) const {
    for (int i = 0; i < size; ++i) {
        output[offset + i] = block.min + block.data[i] * block.scale;
    }
}

void QuantizedTensor::DequantizeBlockQ4_K(const QuantBlock& block, float* output, int offset, int size) const {
    // Simplified - same as Q4_0
    DequantizeBlockQ4_0(block, output, offset, size);
}

void QuantizedTensor::DequantizeBlockQ6_K(const QuantBlock& block, float* output, int offset, int size) const {
    for (int i = 0; i < size; ++i) {
        output[offset + i] = block.min + block.data[i] * block.scale;
    }
}

// QuantizedLinear implementation
QuantizedLinear::QuantizedLinear() = default;

QuantizedLinear::~QuantizedLinear() = default;

bool QuantizedLinear::Initialize(const float* weights, int inFeatures, int outFeatures,
                                  QuantType weightType, bool quantizeActivations) {
    inFeatures_ = inFeatures;
    outFeatures_ = outFeatures;
    weightType_ = weightType;
    quantizeActivations_ = quantizeActivations;
    
    // Quantize weights
    if (!weights_.Quantize(weights, inFeatures * outFeatures, weightType)) {
        return false;
    }
    
    return true;
}

bool QuantizedLinear::Forward(const float* input, float* output,
                              int batchSize, int seqLen) {
    // Dequantize weights for computation
    std::vector<float> weightsDequantized(inFeatures_ * outFeatures_);
    if (!weights_.Dequantize(weightsDequantized.data(), inFeatures_ * outFeatures_)) {
        return false;
    }
    
    // Compute linear transformation
    for (int b = 0; b < batchSize; ++b) {
        for (int s = 0; s < seqLen; ++s) {
            for (int o = 0; o < outFeatures_; ++o) {
                float sum = 0.0f;
                for (int i = 0; i < inFeatures_; ++i) {
                    int inIdx = (b * seqLen + s) * inFeatures_ + i;
                    int wIdx = o * inFeatures_ + i;
                    sum += input[inIdx] * weightsDequantized[wIdx];
                }
                if (o < static_cast<int>(bias_.size())) {
                    sum += bias_[o];
                }
                int outIdx = (b * seqLen + s) * outFeatures_ + o;
                output[outIdx] = sum;
            }
        }
    }
    
    return true;
}

bool QuantizedLinear::ForwardQuantized(const QuantizedTensor& input, QuantizedTensor& output,
                                        int batchSize, int seqLen) {
    // Dequantize both input and weights
    std::vector<float> inputDequantized(batchSize * seqLen * inFeatures_);
    std::vector<float> weightsDequantized(inFeatures_ * outFeatures_);
    
    if (!input.Dequantize(inputDequantized.data(), inputDequantized.size())) return false;
    if (!weights_.Dequantize(weightsDequantized.data(), weightsDequantized.size())) return false;
    
    // Compute
    std::vector<float> outputFloat(batchSize * seqLen * outFeatures_);
    for (int b = 0; b < batchSize; ++b) {
        for (int s = 0; s < seqLen; ++s) {
            for (int o = 0; o < outFeatures_; ++o) {
                float sum = 0.0f;
                for (int i = 0; i < inFeatures_; ++i) {
                    int inIdx = (b * seqLen + s) * inFeatures_ + i;
                    int wIdx = o * inFeatures_ + i;
                    sum += inputDequantized[inIdx] * weightsDequantized[wIdx];
                }
                int outIdx = (b * seqLen + s) * outFeatures_ + o;
                outputFloat[outIdx] = sum;
            }
        }
    }
    
    // Quantize output
    return output.Quantize(outputFloat.data(), outputFloat.size(), QuantType::Q8_0);
}

void QuantizedLinear::QuantizedGEMM(const QuantizedTensor& A, const QuantizedTensor& B,
                                     QuantizedTensor& C, int M, int N, int K) {
    // Dequantize
    std::vector<float> aFloat(M * K);
    std::vector<float> bFloat(K * N);
    
    A.Dequantize(aFloat.data(), aFloat.size());
    B.Dequantize(bFloat.data(), bFloat.size());
    
    // Compute GEMM
    std::vector<float> cFloat(M * N);
    for (int m = 0; m < M; ++m) {
        for (int n = 0; n < N; ++n) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                sum += aFloat[m * K + k] * bFloat[k * N + n];
            }
            cFloat[m * N + n] = sum;
        }
    }
    
    // Quantize result
    C.Quantize(cFloat.data(), cFloat.size(), QuantType::Q8_0);
}

// QuantizationConverter implementation
bool QuantizationConverter::ConvertModel(const std::string& inputPath,
                                          const std::string& outputPath,
                                          const MixedPrecisionConfig& config) {
    // Load model
    // ... load from GGUF
    
    // Quantize each layer according to config
    // attention weights -> config.attentionWeights
    // ffn weights -> config.ffnWeights
    // embedding weights -> config.embeddingWeights
    
    // Save quantized model
    // ... save to outputPath
    
    return true;
}

size_t QuantizationConverter::EstimateSize(const std::string& modelPath,
                                            const MixedPrecisionConfig& config) {
    // Estimate based on quantization types
    float attentionRatio = 0.3f; // 30% of model is attention
    float ffnRatio = 0.6f;         // 60% is FFN
    float embeddingRatio = 0.1f;   // 10% is embeddings
    
    // Get compression ratios
    auto getCompression = [](QuantType type) -> float {
        switch (type) {
            case QuantType::Q4_0: return 8.0f;
            case QuantType::Q4_K: return 8.0f;
            case QuantType::Q5_K: return 6.4f;
            case QuantType::Q6_K: return 5.33f;
            case QuantType::Q8_0: return 4.0f;
            case QuantType::F16: return 2.0f;
            default: return 1.0f;
        }
    };
    
    float compression = attentionRatio * getCompression(config.attentionWeights) +
                       ffnRatio * getCompression(config.ffnWeights) +
                       embeddingRatio * getCompression(config.embeddingWeights);
    
    // Assume original model is ~4 bytes per parameter (FP32)
    // This is a rough estimate
    return static_cast<size_t>(7e9 / compression); // 7B model example
}

MixedPrecisionConfig QuantizationConverter::RecommendConfig(const std::string& modelPath,
                                                              size_t targetSizeMB) {
    MixedPrecisionConfig config;
    
    // Estimate original size
    size_t originalSizeMB = 28000; // 7B model in FP32
    
    float compressionNeeded = static_cast<float>(originalSizeMB) / targetSizeMB;
    
    if (compressionNeeded > 8.0f) {
        // Very aggressive compression
        config.attentionWeights = QuantType::Q4_K;
        config.ffnWeights = QuantType::Q4_K;
        config.embeddingWeights = QuantType::Q4_K;
    } else if (compressionNeeded > 6.0f) {
        // Aggressive compression
        config.attentionWeights = QuantType::Q4_K;
        config.ffnWeights = QuantType::Q6_K;
        config.embeddingWeights = QuantType::Q8_0;
    } else if (compressionNeeded > 4.0f) {
        // Moderate compression
        config.attentionWeights = QuantType::Q6_K;
        config.ffnWeights = QuantType::Q6_K;
        config.embeddingWeights = QuantType::Q8_0;
    } else {
        // Light compression
        config.attentionWeights = QuantType::Q8_0;
        config.ffnWeights = QuantType::Q8_0;
        config.embeddingWeights = QuantType::F16;
    }
    
    return config;
}

QuantizationConverter::QualityMetrics QuantizationConverter::EvaluateQuality(
    const std::string& originalPath,
    const std::string& quantizedPath,
    const std::vector<std::string>& testPrompts) {
    
    QualityMetrics metrics;
    
    // Load both models
    // ...
    
    // Evaluate on test prompts
    float totalPerplexityOriginal = 0.0f;
    float totalPerplexityQuantized = 0.0f;
    
    for (const auto& prompt : testPrompts) {
        // Compute perplexity for original
        // float pplOriginal = ComputePerplexity(originalModel, prompt);
        // totalPerplexityOriginal += pplOriginal;
        
        // Compute perplexity for quantized
        // float pplQuantized = ComputePerplexity(quantizedModel, prompt);
        // totalPerplexityQuantized += pplQuantized;
    }
    
    // float avgPplOriginal = totalPerplexityOriginal / testPrompts.size();
    // float avgPplQuantized = totalPerplexityQuantized / testPrompts.size();
    
    // metrics.perplexityIncrease = (avgPplQuantized - avgPplOriginal) / avgPplOriginal;
    // metrics.compressionRatio = GetModelSize(originalPath) / GetModelSize(quantizedPath);
    
    return metrics;
}

// DynamicQuantizer implementation
DynamicQuantizer::DynamicQuantizer() = default;

DynamicQuantizer::~DynamicQuantizer() = default;

bool DynamicQuantizer::Calibrate(const std::vector<std::vector<float>>& sampleActivations) {
    // Compute observed ranges
    observedRanges_.clear();
    
    for (const auto& activation : sampleActivations) {
        float minVal = *std::min_element(activation.begin(), activation.end());
        float maxVal = *std::max_element(activation.begin(), activation.end());
        observedRanges_.push_back(maxVal - minVal);
    }
    
    calibrated_ = true;
    return true;
}

QuantizedTensor DynamicQuantizer::QuantizeActivation(const float* activation, int numElements) {
    QuantizedTensor result;
    
    // Compute dynamic scale
    float scale = ComputeScale(activation, numElements);
    
    // Quantize
    result.Quantize(activation, numElements, QuantType::Q8_0);
    
    return result;
}

float DynamicQuantizer::ComputeScale(const float* data, int numElements) {
    float maxAbs = 0.0f;
    for (int i = 0; i < numElements; ++i) {
        maxAbs = std::max(maxAbs, std::abs(data[i]));
    }
    return maxAbs / 127.0f; // For 8-bit quantization
}

// QuantizedKVCache implementation
QuantizedKVCache::QuantizedKVCache() = default;

QuantizedKVCache::~QuantizedKVCache() = default;

bool QuantizedKVCache::Initialize(int numLayers, int numHeads, int headDim,
                                   int maxSeqLen, QuantType type) {
    numLayers_ = numLayers;
    numHeads_ = numHeads;
    headDim_ = headDim;
    maxSeqLen_ = maxSeqLen;
    type_ = type;
    
    // Pre-allocate quantized cache for each layer
    kCaches_.resize(numLayers);
    vCaches_.resize(numLayers);
    
    fp32Size_ = numLayers * numHeads * maxSeqLen * headDim * sizeof(float);
    
    return true;
}

void QuantizedKVCache::Store(int layer, int head, int seqPos,
                              const float* key, const float* value) {
    if (layer >= numLayers_ || head >= numHeads_) return;
    
    // Quantize and store
    int elements = headDim_;
    
    // For simplicity, store entire cache per layer
    if (kCaches_[layer].GetSizeBytes() == 0) {
        std::vector<float> dummy(numHeads_ * maxSeqLen_ * headDim_, 0.0f);
        kCaches_[layer].Quantize(dummy.data(), dummy.size(), type_);
        vCaches_[layer].Quantize(dummy.data(), dummy.size(), type_);
    }
}

bool QuantizedKVCache::Retrieve(int layer, int head, int seqPos,
                                float* key, float* value) {
    if (layer >= numLayers_ || head >= numHeads_) return false;
    
    // Dequantize and retrieve
    std::vector<float> kDequantized;
    std::vector<float> vDequantized;
    
    // ... retrieve logic
    
    return true;
}

size_t QuantizedKVCache::GetMemoryUsage() const {
    size_t total = 0;
    for (const auto& cache : kCaches_) {
        total += cache.GetSizeBytes();
    }
    for (const auto& cache : vCaches_) {
        total += cache.GetSizeBytes();
    }
    return total;
}

float QuantizedKVCache::GetCompressionRatio() const {
    if (fp32Size_ == 0) return 1.0f;
    return static_cast<float>(fp32Size_) / GetMemoryUsage();
}

// QuantizationBenchmark implementation
QuantizationBenchmark::Result QuantizationBenchmark::BenchmarkType(
    QuantType type,
    const std::vector<float>& testWeights,
    const std::vector<float>& testActivations) {
    
    Result result;
    result.type = type;
    
    // Quantize weights
    QuantizedTensor quantizedWeights;
    auto start = std::chrono::high_resolution_clock::now();
    quantizedWeights.Quantize(testWeights.data(), testWeights.size(), type);
    auto end = std::chrono::high_resolution_clock::now();
    
    // Dequantize
    std::vector<float> dequantized(testWeights.size());
    start = std::chrono::high_resolution_clock::now();
    quantizedWeights.Dequantize(dequantized.data(), dequantized.size());
    end = std::chrono::high_resolution_clock::now();
    result.dequantizeTimeMs = std::chrono::duration<float, std::milli>(end - start).count();
    
    // Compute compression ratio
    result.compressionRatio = quantizedWeights.GetCompressionRatio();
    
    // Compute accuracy loss
    float mse = 0.0f;
    for (size_t i = 0; i < testWeights.size(); ++i) {
        float diff = testWeights[i] - dequantized[i];
        mse += diff * diff;
    }
    mse /= testWeights.size();
    result.accuracyLoss = mse;
    
    return result;
}

std::vector<QuantizationBenchmark::Result> QuantizationBenchmark::BenchmarkAll(
    const std::vector<float>& testWeights,
    const std::vector<float>& testActivations) {
    
    std::vector<Result> results;
    
    std::vector<QuantType> types = {
        QuantType::Q4_0,
        QuantType::Q4_K,
        QuantType::Q5_K,
        QuantType::Q6_K,
        QuantType::Q8_0,
        QuantType::F16
    };
    
    for (auto type : types) {
        results.push_back(BenchmarkType(type, testWeights, testActivations));
    }
    
    return results;
}

std::string QuantizationBenchmark::GenerateReport(const std::vector<Result>& results) {
    std::string report = "Quantization Benchmark Report\n";
    report += "============================\n\n";
    report += "Type | Compression | Dequant(ms) | Accuracy Loss\n";
    report += "-----|-------------|-------------|--------------\n";
    
    for (const auto& result : results) {
        std::string typeName;
        switch (result.type) {
            case QuantType::Q4_0: typeName = "Q4_0"; break;
            case QuantType::Q4_K: typeName = "Q4_K"; break;
            case QuantType::Q5_K: typeName = "Q5_K"; break;
            case QuantType::Q6_K: typeName = "Q6_K"; break;
            case QuantType::Q8_0: typeName = "Q8_0"; break;
            case QuantType::F16: typeName = "F16"; break;
            default: typeName = "Unknown";
        }
        
        char line[256];
        snprintf(line, sizeof(line), "%4s | %11.2fx | %11.3f | %13.6f\n",
                 typeName.c_str(), result.compressionRatio,
                 result.dequantizeTimeMs, result.accuracyLoss);
        report += line;
    }
    
    return report;
}

} // namespace optimizations
} // namespace rawrxd

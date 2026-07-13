// RawrXD Quantization Interface
// Phase AK: Model Optimization Suite

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace rawrxd {
namespace optimization {

// Quantization types
enum class QuantizationType {
    Q4_0,           // 4-bit quantization, version 0
    Q4_1,           // 4-bit quantization, version 1
    Q4_K,           // 4-bit K-quant
    Q5_0,           // 5-bit quantization
    Q5_1,           // 5-bit quantization
    Q5_K,           // 5-bit K-quant
    Q6_K,           // 6-bit K-quant
    Q8_0,           // 8-bit quantization, version 0
    Q8_1,           // 8-bit quantization, version 1
    Q8_K,           // 8-bit K-quant
    F16,            // Half precision
    BF16,           // BFloat16
    IQ2_XXS,        // 2-bit extreme compression
    IQ2_XS,         // 2-bit extreme compression
    IQ3_XXS,        // 3-bit extreme compression
    IQ3_XS,         // 3-bit extreme compression
    IQ4_XS,         // 4-bit extreme compression
    IQ4_NL          // 4-bit normal
};

// Quantization configuration
struct QuantizationConfig {
    QuantizationType type;
    bool use_gpu;
    int threads;
    bool allow_requantize;
    float importance_threshold;
    
    QuantizationConfig() 
        : type(QuantizationType::Q4_0)
        , use_gpu(true)
        , threads(4)
        , allow_requantize(true)
        , importance_threshold(0.0f) {}
};

// Quantization statistics
struct QuantizationStats {
    size_t original_size;
    size_t quantized_size;
    double compression_ratio;
    double perplexity_delta;
    double accuracy_delta;
    double quantization_error;
    double processing_time_ms;
    
    QuantizationStats()
        : original_size(0)
        , quantized_size(0)
        , compression_ratio(0.0)
        , perplexity_delta(0.0)
        , accuracy_delta(0.0)
        , quantization_error(0.0)
        , processing_time_ms(0.0) {}
};

// Tensor quantization data
struct QuantizedTensor {
    std::vector<uint8_t> data;
    std::vector<float> scales;
    std::vector<uint8_t> zero_points;
    std::vector<int> shape;
    QuantizationType type;
    size_t original_size;
    
    size_t size() const { return data.size(); }
};

// Forward declarations
class IQuantizer;
class QuantizationPipeline;

/**
 * QuantizationManager - Central quantization management
 */
class QuantizationManager {
public:
    QuantizationManager();
    ~QuantizationManager();
    
    // Initialize quantization system
    bool initialize();
    
    // Quantize tensor
    QuantizedTensor quantize(const float* data, const std::vector<int>& shape,
                              const QuantizationConfig& config);
    
    // Dequantize tensor
    std::vector<float> dequantize(const QuantizedTensor& tensor);
    
    // Quantize model file
    bool quantizeModel(const std::string& input_path, const std::string& output_path,
                       const QuantizationConfig& config, QuantizationStats* stats = nullptr);
    
    // Get quantizer for type
    std::shared_ptr<IQuantizer> getQuantizer(QuantizationType type);
    
    // Supported types
    std::vector<QuantizationType> getSupportedTypes() const;
    bool isTypeSupported(QuantizationType type) const;
    
    // Type information
    std::string getTypeName(QuantizationType type) const;
    int getTypeBits(QuantizationType type) const;
    double getExpectedCompression(QuantizationType type) const;
    
    // Utility functions
    static float computePerplexity(const float* logits, const int* tokens, size_t count);
    static float computeQuantizationError(const float* original, const float* quantized, size_t count);
    
private:
    std::unordered_map<QuantizationType, std::shared_ptr<IQuantizer>> quantizers_;
    bool initialized_;
};

/**
 * IQuantizer - Base quantizer interface
 */
class IQuantizer {
public:
    virtual ~IQuantizer() = default;
    
    // Quantize float data
    virtual QuantizedTensor quantize(const float* data, const std::vector<int>& shape) = 0;
    
    // Dequantize to float
    virtual std::vector<float> dequantize(const QuantizedTensor& tensor) = 0;
    
    // Get quantizer info
    virtual QuantizationType getType() const = 0;
    virtual int getBits() const = 0;
    virtual std::string getName() const = 0;
    
    // Check if GPU is supported
    virtual bool supportsGPU() const { return false; }
    
    // Set GPU mode
    virtual void setGPU(bool use_gpu) {}
};

/**
 * Q4Quantizer - 4-bit quantization
 */
class Q4Quantizer : public IQuantizer {
public:
    QuantizedTensor quantize(const float* data, const std::vector<int>& shape) override;
    std::vector<float> dequantize(const QuantizedTensor& tensor) override;
    QuantizationType getType() const override { return QuantizationType::Q4_0; }
    int getBits() const override { return 4; }
    std::string getName() const override { return "Q4_0"; }
    bool supportsGPU() const override { return true; }
};

/**
 * Q8Quantizer - 8-bit quantization
 */
class Q8Quantizer : public IQuantizer {
public:
    QuantizedTensor quantize(const float* data, const std::vector<int>& shape) override;
    std::vector<float> dequantize(const QuantizedTensor& tensor) override;
    QuantizationType getType() const override { return QuantizationType::Q8_0; }
    int getBits() const override { return 8; }
    std::string getName() const override { return "Q8_0"; }
    bool supportsGPU() const override { return true; }
};

/**
 * QuantizationPipeline - Batch quantization processing
 */
class QuantizationPipeline {
public:
    QuantizationPipeline();
    
    // Add tensor to pipeline
    void addTensor(const std::string& name, const float* data, const std::vector<int>& shape);
    
    // Process all tensors
    std::unordered_map<std::string, QuantizedTensor> process(const QuantizationConfig& config);
    
    // Clear pipeline
    void clear();
    
    // Get tensor count
    size_t getTensorCount() const;
    
private:
    struct TensorData {
        std::string name;
        std::vector<float> data;
        std::vector<int> shape;
    };
    
    std::vector<TensorData> tensors_;
};

// Global quantization manager accessor
QuantizationManager* getQuantizationManager();
void setQuantizationManager(std::unique_ptr<QuantizationManager> manager);

// Convenience macros
#define RAWRXD_QUANTIZE(data, shape, type) \
    rawrxd::optimization::getQuantizationManager()->quantize(data, shape, \
        rawrxd::optimization::QuantizationConfig{.type = type})

} // namespace optimization
} // namespace rawrxd

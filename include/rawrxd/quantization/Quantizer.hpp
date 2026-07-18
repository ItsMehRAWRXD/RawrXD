#pragma once

#include "rawrxd/quantization/QuantizationConfig.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd {
namespace quantization {

// Forward declaration
class Tensor;

// Quantized tensor representation
struct QuantizedTensor {
    std::vector<uint8_t> data;          // Quantized data
    std::vector<float> scales;         // Per-group scales
    std::vector<float> zeroPoints;      // Per-group zero points (if asymmetric)
    int originalRows = 0;
    int originalCols = 0;
    QuantFormat format = QuantFormat::Q4_0;
    int groupSize = 128;
    
    // Get size in bytes
    size_t GetSizeBytes() const { return data.size() * sizeof(uint8_t); }
    
    // Get original size in bytes (FP32)
    size_t GetOriginalSizeBytes() const { 
        return static_cast<size_t>(originalRows) * originalCols * sizeof(float); 
    }
    
    // Get compression ratio
    float GetCompressionRatio() const {
        return static_cast<float>(GetOriginalSizeBytes()) / GetSizeBytes();
    }
};

// Base quantizer interface
class Quantizer {
public:
    Quantizer() = default;
    virtual ~Quantizer() = default;

    // Initialize with config
    virtual bool Initialize(const QuantizationConfig& config) = 0;
    
    // Quantize a tensor
    virtual QuantizedTensor Quantize(const std::vector<float>& data, 
                                      int rows, int cols,
                                      const std::string& layerName = "") = 0;
    
    // Dequantize back to float
    virtual std::vector<float> Dequantize(const QuantizedTensor& qtensor) = 0;
    
    // Get last error
    virtual std::string GetLastError() const = 0;
    
    // Check if initialized
    virtual bool IsInitialized() const = 0;
};

// Round-to-nearest quantizer (baseline)
class RTNQuantizer : public Quantizer {
public:
    RTNQuantizer() = default;
    ~RTNQuantizer() override = default;

    bool Initialize(const QuantizationConfig& config) override;
    QuantizedTensor Quantize(const std::vector<float>& data, 
                            int rows, int cols,
                            const std::string& layerName = "") override;
    std::vector<float> Dequantize(const QuantizedTensor& qtensor) override;
    std::string GetLastError() const override { return lastError_; }
    bool IsInitialized() const override { return initialized_; }

private:
    QuantizationConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Quantization helpers
    QuantizedTensor QuantizeQ4_0(const std::vector<float>& data, int rows, int cols);
    QuantizedTensor QuantizeQ4_1(const std::vector<float>& data, int rows, int cols);
    QuantizedTensor QuantizeQ8_0(const std::vector<float>& data, int rows, int cols);
    QuantizedTensor QuantizeQ8_1(const std::vector<float>& data, int rows, int cols);
    QuantizedTensor QuantizeKQuant(const std::vector<float>& data, int rows, int cols, QuantFormat format);
};

// GPTQ quantizer
class GPTQQuantizer : public Quantizer {
public:
    GPTQQuantizer();
    ~GPTQQuantizer() override = default;

    bool Initialize(const QuantizationConfig& config) override;
    QuantizedTensor Quantize(const std::vector<float>& data, 
                            int rows, int cols,
                            const std::string& layerName = "") override;
    std::vector<float> Dequantize(const QuantizedTensor& qtensor) override;
    std::string GetLastError() const override { return lastError_; }
    bool IsInitialized() const override { return initialized_; }
    
    // GPTQ-specific: calibrate with activations
    bool Calibrate(const std::vector<std::vector<float>>& activations);

private:
    QuantizationConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Calibration data
    std::vector<std::vector<float>> calibrationData_;
    bool calibrated_ = false;
    
    // GPTQ algorithm
    QuantizedTensor QuantizeGPTQ(const std::vector<float>& data, int rows, int cols);
    std::vector<float> ComputeHessian(const std::vector<std::vector<float>>& activations);
};

// AWQ quantizer
class AWQQuantizer : public Quantizer {
public:
    AWQQuantizer();
    ~AWQQuantizer() override = default;

    bool Initialize(const QuantizationConfig& config) override;
    QuantizedTensor Quantize(const std::vector<float>& data, 
                            int rows, int cols,
                            const std::string& layerName = "") override;
    std::vector<float> Dequantize(const QuantizedTensor& qtensor) override;
    std::string GetLastError() const override { return lastError_; }
    bool IsInitialized() const override { return initialized_; }
    
    // AWQ-specific: search for optimal scales
    bool SearchScales(const std::vector<std::vector<float>>& activations);

private:
    QuantizationConfig config_;
    bool initialized_ = false;
    std::string lastError_;
    
    // AWQ scaling factors
    std::vector<float> scalingFactors_;
    bool scalesSearched_ = false;
    
    QuantizedTensor QuantizeAWQ(const std::vector<float>& data, int rows, int cols);
};

// Quantizer factory
class QuantizerFactory {
public:
    static std::unique_ptr<Quantizer> Create(QuantMethod method);
    static std::unique_ptr<Quantizer> Create(const QuantizationConfig& config);
};

} // namespace quantization
} // namespace rawrxd

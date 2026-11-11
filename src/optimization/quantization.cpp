// RawrXD Quantization Implementation
// Phase AK: Model Optimization Suite

#include "quantization.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <chrono>
#include <fstream>

namespace rawrxd {
namespace optimization {

// Global quantization manager instance
static std::unique_ptr<QuantizationManager> g_quantization_manager;

QuantizationManager* getQuantizationManager() {
    return g_quantization_manager.get();
}

void setQuantizationManager(std::unique_ptr<QuantizationManager> manager) {
    g_quantization_manager = std::move(manager);
}

// QuantizationManager implementation
QuantizationManager::QuantizationManager() : initialized_(false) {}

QuantizationManager::~QuantizationManager() = default;

bool QuantizationManager::initialize() {
    // Register quantizers
    quantizers_[QuantizationType::Q4_0] = std::make_shared<Q4Quantizer>();
    quantizers_[QuantizationType::Q8_0] = std::make_shared<Q8Quantizer>();
    
    initialized_ = true;
    return true;
}

QuantizedTensor QuantizationManager::quantize(const float* data, const std::vector<int>& shape,
                                               const QuantizationConfig& config) {
    auto quantizer = getQuantizer(config.type);
    if (!quantizer) {
        throw std::runtime_error("Quantizer not available for type");
    }
    
    quantizer->setGPU(config.use_gpu);
    return quantizer->quantize(data, shape);
}

std::vector<float> QuantizationManager::dequantize(const QuantizedTensor& tensor) {
    auto quantizer = getQuantizer(tensor.type);
    if (!quantizer) {
        throw std::runtime_error("Quantizer not available for type");
    }
    
    return quantizer->dequantize(tensor);
}

bool QuantizationManager::quantizeModel(const std::string& input_path, const std::string& output_path,
                                        const QuantizationConfig& config, QuantizationStats* stats) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // This is a simplified implementation
    // In production, this would:
    // 1. Load GGUF model
    // 2. Iterate through tensors
    // 3. Quantize each tensor
    // 4. Write quantized model
    
    if (stats) {
        auto end_time = std::chrono::high_resolution_clock::now();
        stats->processing_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    }
    
    return true;
}

std::shared_ptr<IQuantizer> QuantizationManager::getQuantizer(QuantizationType type) {
    auto it = quantizers_.find(type);
    if (it != quantizers_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<QuantizationType> QuantizationManager::getSupportedTypes() const {
    std::vector<QuantizationType> types;
    for (const auto& [type, _] : quantizers_) {
        types.push_back(type);
    }
    return types;
}

bool QuantizationManager::isTypeSupported(QuantizationType type) const {
    return quantizers_.find(type) != quantizers_.end();
}

std::string QuantizationManager::getTypeName(QuantizationType type) const {
    switch (type) {
        case QuantizationType::Q4_0: return "Q4_0";
        case QuantizationType::Q4_1: return "Q4_1";
        case QuantizationType::Q4_K: return "Q4_K";
        case QuantizationType::Q5_0: return "Q5_0";
        case QuantizationType::Q5_1: return "Q5_1";
        case QuantizationType::Q5_K: return "Q5_K";
        case QuantizationType::Q6_K: return "Q6_K";
        case QuantizationType::Q8_0: return "Q8_0";
        case QuantizationType::Q8_1: return "Q8_1";
        case QuantizationType::Q8_K: return "Q8_K";
        case QuantizationType::F16: return "F16";
        case QuantizationType::BF16: return "BF16";
        case QuantizationType::IQ2_XXS: return "IQ2_XXS";
        case QuantizationType::IQ2_XS: return "IQ2_XS";
        case QuantizationType::IQ3_XXS: return "IQ3_XXS";
        case QuantizationType::IQ3_XS: return "IQ3_XS";
        case QuantizationType::IQ4_XS: return "IQ4_XS";
        case QuantizationType::IQ4_NL: return "IQ4_NL";
        default: return "UNKNOWN";
    }
}

int QuantizationManager::getTypeBits(QuantizationType type) const {
    switch (type) {
        case QuantizationType::Q4_0:
        case QuantizationType::Q4_1:
        case QuantizationType::Q4_K:
        case QuantizationType::IQ4_XS:
        case QuantizationType::IQ4_NL:
            return 4;
        case QuantizationType::Q5_0:
        case QuantizationType::Q5_1:
        case QuantizationType::Q5_K:
            return 5;
        case QuantizationType::Q6_K:
            return 6;
        case QuantizationType::Q8_0:
        case QuantizationType::Q8_1:
        case QuantizationType::Q8_K:
            return 8;
        case QuantizationType::F16:
        case QuantizationType::BF16:
            return 16;
        case QuantizationType::IQ2_XXS:
        case QuantizationType::IQ2_XS:
            return 2;
        case QuantizationType::IQ3_XXS:
        case QuantizationType::IQ3_XS:
            return 3;
        default:
            return 32;
    }
}

double QuantizationManager::getExpectedCompression(QuantizationType type) const {
    int bits = getTypeBits(type);
    return 32.0 / bits;  // Assuming 32-bit float original
}

float QuantizationManager::computePerplexity(const float* logits, const int* tokens, size_t count) {
    // Simplified perplexity calculation
    double sum_log_probs = 0.0;
    for (size_t i = 0; i < count; ++i) {
        // This would use softmax and log in production
        sum_log_probs += std::log(std::max(logits[i], 1e-10f));
    }
    return std::exp(-sum_log_probs / count);
}

float QuantizationManager::computeQuantizationError(const float* original, const float* quantized, size_t count) {
    double sum_squared_error = 0.0;
    for (size_t i = 0; i < count; ++i) {
        double diff = original[i] - quantized[i];
        sum_squared_error += diff * diff;
    }
    return std::sqrt(sum_squared_error / count);
}

// Q4Quantizer implementation
QuantizedTensor Q4Quantizer::quantize(const float* data, const std::vector<int>& shape) {
    QuantizedTensor result;
    result.type = QuantizationType::Q4_0;
    result.shape = shape;
    
    // Calculate total elements
    size_t num_elements = 1;
    for (int dim : shape) {
        num_elements *= dim;
    }
    
    // Block size for Q4_0
    const int block_size = 32;
    size_t num_blocks = (num_elements + block_size - 1) / block_size;
    
    // Allocate space for quantized data
    // Each block: 1 scale (float) + 16 bytes (32 * 4 bits)
    result.data.resize(num_blocks * (sizeof(float) + 16));
    result.scales.resize(num_blocks);
    
    // Quantize each block
    for (size_t block = 0; block < num_blocks; ++block) {
        size_t start_idx = block * block_size;
        size_t end_idx = std::min(start_idx + block_size, num_elements);
        
        // Find min and max for this block
        float min_val = data[start_idx];
        float max_val = data[start_idx];
        for (size_t i = start_idx + 1; i < end_idx; ++i) {
            min_val = std::min(min_val, data[i]);
            max_val = std::max(max_val, data[i]);
        }
        
        // Calculate scale
        float scale = (max_val - min_val) / 15.0f;
        if (scale == 0) scale = 1.0f;
        
        result.scales[block] = scale;
        
        // Write scale to data
        float* scale_ptr = reinterpret_cast<float*>(&result.data[block * (sizeof(float) + 16)]);
        *scale_ptr = scale;
        
        // Quantize values
        uint8_t* quantized_ptr = &result.data[block * (sizeof(float) + 16) + sizeof(float)];
        for (size_t i = start_idx; i < end_idx; i += 2) {
            int q1 = static_cast<int>(std::round((data[i] - min_val) / scale));
            q1 = std::clamp(q1, 0, 15);
            
            int q2 = 0;
            if (i + 1 < end_idx) {
                q2 = static_cast<int>(std::round((data[i + 1] - min_val) / scale));
                q2 = std::clamp(q2, 0, 15);
            }
            
            quantized_ptr[(i - start_idx) / 2] = (q2 << 4) | q1;
        }
    }
    
    result.original_size = num_elements * sizeof(float);
    return result;
}

std::vector<float> Q4Quantizer::dequantize(const QuantizedTensor& tensor) {
    // Calculate total elements
    size_t num_elements = 1;
    for (int dim : tensor.shape) {
        num_elements *= dim;
    }
    
    std::vector<float> result(num_elements);
    
    const int block_size = 32;
    size_t num_blocks = (num_elements + block_size - 1) / block_size;
    
    // Dequantize each block
    for (size_t block = 0; block < num_blocks; ++block) {
        size_t start_idx = block * block_size;
        size_t end_idx = std::min(start_idx + block_size, num_elements);
        
        // Read scale
        float scale = *reinterpret_cast<const float*>(&tensor.data[block * (sizeof(float) + 16)]);
        
        // Dequantize values
        const uint8_t* quantized_ptr = &tensor.data[block * (sizeof(float) + 16) + sizeof(float)];
        for (size_t i = start_idx; i < end_idx; i += 2) {
            uint8_t packed = quantized_ptr[(i - start_idx) / 2];
            int q1 = packed & 0x0F;
            int q2 = (packed >> 4) & 0x0F;
            
            result[i] = q1 * scale;
            if (i + 1 < end_idx) {
                result[i + 1] = q2 * scale;
            }
        }
    }
    
    return result;
}

// Q8Quantizer implementation
QuantizedTensor Q8Quantizer::quantize(const float* data, const std::vector<int>& shape) {
    QuantizedTensor result;
    result.type = QuantizationType::Q8_0;
    result.shape = shape;
    
    // Calculate total elements
    size_t num_elements = 1;
    for (int dim : shape) {
        num_elements *= dim;
    }
    
    // Block size for Q8_0
    const int block_size = 32;
    size_t num_blocks = (num_elements + block_size - 1) / block_size;
    
    // Allocate space for quantized data
    // Each block: 1 scale (float) + 32 bytes (32 * 8 bits)
    result.data.resize(num_blocks * (sizeof(float) + block_size));
    result.scales.resize(num_blocks);
    
    // Quantize each block
    for (size_t block = 0; block < num_blocks; ++block) {
        size_t start_idx = block * block_size;
        size_t end_idx = std::min(start_idx + block_size, num_elements);
        
        // Find max absolute value for this block
        float max_abs = 0.0f;
        for (size_t i = start_idx; i < end_idx; ++i) {
            max_abs = std::max(max_abs, std::abs(data[i]));
        }
        
        // Calculate scale
        float scale = max_abs / 127.0f;
        if (scale == 0) scale = 1.0f;
        
        result.scales[block] = scale;
        
        // Write scale to data
        float* scale_ptr = reinterpret_cast<float*>(&result.data[block * (sizeof(float) + block_size)]);
        *scale_ptr = scale;
        
        // Quantize values
        int8_t* quantized_ptr = reinterpret_cast<int8_t*>(&result.data[block * (sizeof(float) + block_size) + sizeof(float)]);
        for (size_t i = start_idx; i < end_idx; ++i) {
            int q = static_cast<int>(std::round(data[i] / scale));
            quantized_ptr[i - start_idx] = static_cast<int8_t>(std::clamp(q, -127, 127));
        }
    }
    
    result.original_size = num_elements * sizeof(float);
    return result;
}

std::vector<float> Q8Quantizer::dequantize(const QuantizedTensor& tensor) {
    // Calculate total elements
    size_t num_elements = 1;
    for (int dim : tensor.shape) {
        num_elements *= dim;
    }
    
    std::vector<float> result(num_elements);
    
    const int block_size = 32;
    size_t num_blocks = (num_elements + block_size - 1) / block_size;
    
    // Dequantize each block
    for (size_t block = 0; block < num_blocks; ++block) {
        size_t start_idx = block * block_size;
        size_t end_idx = std::min(start_idx + block_size, num_elements);
        
        // Read scale
        float scale = *reinterpret_cast<const float*>(&tensor.data[block * (sizeof(float) + block_size)]);
        
        // Dequantize values
        const int8_t* quantized_ptr = reinterpret_cast<const int8_t*>(&tensor.data[block * (sizeof(float) + block_size) + sizeof(float)]);
        for (size_t i = start_idx; i < end_idx; ++i) {
            result[i] = quantized_ptr[i - start_idx] * scale;
        }
    }
    
    return result;
}

// QuantizationPipeline implementation
QuantizationPipeline::QuantizationPipeline() = default;

void QuantizationPipeline::addTensor(const std::string& name, const float* data, const std::vector<int>& shape) {
    TensorData td;
    td.name = name;
    
    size_t num_elements = 1;
    for (int dim : shape) {
        num_elements *= dim;
    }
    
    td.data.resize(num_elements);
    std::memcpy(td.data.data(), data, num_elements * sizeof(float));
    td.shape = shape;
    
    tensors_.push_back(std::move(td));
}

std::unordered_map<std::string, QuantizedTensor> QuantizationPipeline::process(const QuantizationConfig& config) {
    std::unordered_map<std::string, QuantizedTensor> results;
    
    auto manager = getQuantizationManager();
    if (!manager) {
        return results;
    }
    
    for (const auto& tensor : tensors_) {
        results[tensor.name] = manager->quantize(tensor.data.data(), tensor.shape, config);
    }
    
    return results;
}

void QuantizationPipeline::clear() {
    tensors_.clear();
}

size_t QuantizationPipeline::getTensorCount() const {
    return tensors_.size();
}

} // namespace optimization
} // namespace rawrxd

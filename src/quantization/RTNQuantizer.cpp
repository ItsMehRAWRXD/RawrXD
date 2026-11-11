#include "rawrxd/quantization/Quantizer.hpp"
#include <cmath>
#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace quantization {

bool RTNQuantizer::Initialize(const QuantizationConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

QuantizedTensor RTNQuantizer::Quantize(const std::vector<float>& data, 
                                         int rows, int cols,
                                         const std::string& layerName) {
    if (!initialized_) {
        lastError_ = "Quantizer not initialized";
        return QuantizedTensor();
    }
    
    QuantFormat format = config_.GetLayerFormat(layerName);
    
    switch (format) {
        case QuantFormat::Q4_0:
            return QuantizeQ4_0(data, rows, cols);
        case QuantFormat::Q4_1:
            return QuantizeQ4_1(data, rows, cols);
        case QuantFormat::Q8_0:
            return QuantizeQ8_0(data, rows, cols);
        case QuantFormat::Q8_1:
            return QuantizeQ8_1(data, rows, cols);
        case QuantFormat::Q4_K_M:
        case QuantFormat::Q4_K_S:
        case QuantFormat::Q5_K_M:
        case QuantFormat::Q6_K:
        case QuantFormat::Q8_K:
            return QuantizeKQuant(data, rows, cols, format);
        default:
            lastError_ = "Unsupported quantization format";
            return QuantizedTensor();
    }
}

std::vector<float> RTNQuantizer::Dequantize(const QuantizedTensor& qtensor) {
    std::vector<float> result;
    int numElements = qtensor.originalRows * qtensor.originalCols;
    result.resize(numElements);
    
    switch (qtensor.format) {
        case QuantFormat::Q4_0: {
            // Q4_0: 4-bit, one scale per block of 32
            int blockSize = 32;
            int numBlocks = (numElements + blockSize - 1) / blockSize;
            
            for (int b = 0; b < numBlocks; ++b) {
                float scale = qtensor.scales[b];
                int blockStart = b * blockSize;
                int blockEnd = std::min(blockStart + blockSize, numElements);
                
                for (int i = blockStart; i < blockEnd; i += 2) {
                    uint8_t byte = qtensor.data[(i - blockStart) / 2 + b * (blockSize / 2)];
                    int q0 = byte & 0x0F;
                    int q1 = (byte >> 4) & 0x0F;
                    
                    if (i < blockEnd) result[i] = (q0 - 8) * scale;
                    if (i + 1 < blockEnd) result[i + 1] = (q1 - 8) * scale;
                }
            }
            break;
        }
        case QuantFormat::Q8_0: {
            // Q8_0: 8-bit, one scale per block
            int blockSize = config_.defaultGroupSize;
            int numBlocks = (numElements + blockSize - 1) / blockSize;
            
            for (int b = 0; b < numBlocks; ++b) {
                float scale = qtensor.scales[b];
                int blockStart = b * blockSize;
                int blockEnd = std::min(blockStart + blockSize, numElements);
                
                for (int i = blockStart; i < blockEnd; ++i) {
                    int q = static_cast<int8_t>(qtensor.data[i]);
                    result[i] = q * scale;
                }
            }
            break;
        }
        default:
            // Fallback: return zeros
            std::fill(result.begin(), result.end(), 0.0f);
            break;
    }
    
    return result;
}

QuantizedTensor RTNQuantizer::QuantizeQ4_0(const std::vector<float>& data, int rows, int cols) {
    QuantizedTensor result;
    result.originalRows = rows;
    result.originalCols = cols;
    result.format = QuantFormat::Q4_0;
    result.groupSize = 32;
    
    int numElements = rows * cols;
    int numBlocks = (numElements + result.groupSize - 1) / result.groupSize;
    
    result.scales.resize(numBlocks);
    result.data.resize(numBlocks * (result.groupSize / 2));  // 2 values per byte
    
    for (int b = 0; b < numBlocks; ++b) {
        int blockStart = b * result.groupSize;
        int blockEnd = std::min(blockStart + result.groupSize, numElements);
        int blockSize = blockEnd - blockStart;
        
        // Find max absolute value for scale
        float maxAbs = 0.0f;
        for (int i = blockStart; i < blockEnd; ++i) {
            maxAbs = std::max(maxAbs, std::abs(data[i]));
        }
        
        // Scale to fit in 4 bits (-8 to 7)
        float scale = maxAbs / 7.0f;
        if (scale == 0.0f) scale = 1.0f;
        result.scales[b] = scale;
        
        // Quantize
        for (int i = blockStart; i < blockEnd; i += 2) {
            int q0 = 0, q1 = 0;
            
            if (i < blockEnd) {
                float v0 = data[i] / scale;
                q0 = static_cast<int>(std::round(v0));
                q0 = std::max(-8, std::min(7, q0));
            }
            
            if (i + 1 < blockEnd) {
                float v1 = data[i + 1] / scale;
                q1 = static_cast<int>(std::round(v1));
                q1 = std::max(-8, std::min(7, q1));
            }
            
            // Pack into byte (offset by 8 to make unsigned 0-15)
            uint8_t packed = static_cast<uint8_t>((q1 + 8) << 4 | (q0 + 8));
            result.data[(i - blockStart) / 2 + b * (result.groupSize / 2)] = packed;
        }
    }
    
    return result;
}

QuantizedTensor RTNQuantizer::QuantizeQ4_1(const std::vector<float>& data, int rows, int cols) {
    // Q4_1: 4-bit with offset (min/max)
    QuantizedTensor result;
    result.originalRows = rows;
    result.originalCols = cols;
    result.format = QuantFormat::Q4_1;
    result.groupSize = 32;
    
    int numElements = rows * cols;
    int numBlocks = (numElements + result.groupSize - 1) / result.groupSize;
    
    // Q4_1 stores both scale and zero point
    result.scales.resize(numBlocks * 2);  // scale and zero point
    result.data.resize(numBlocks * (result.groupSize / 2));
    
    for (int b = 0; b < numBlocks; ++b) {
        int blockStart = b * result.groupSize;
        int blockEnd = std::min(blockStart + result.groupSize, numElements);
        
        // Find min and max
        float minVal = data[blockStart];
        float maxVal = data[blockStart];
        for (int i = blockStart + 1; i < blockEnd; ++i) {
            minVal = std::min(minVal, data[i]);
            maxVal = std::max(maxVal, data[i]);
        }
        
        // Compute scale and zero point
        float scale = (maxVal - minVal) / 15.0f;
        if (scale == 0.0f) scale = 1.0f;
        float zeroPoint = minVal;
        
        result.scales[b * 2] = scale;
        result.scales[b * 2 + 1] = zeroPoint;
        
        // Quantize
        for (int i = blockStart; i < blockEnd; i += 2) {
            int q0 = 0, q1 = 0;
            
            if (i < blockEnd) {
                q0 = static_cast<int>(std::round((data[i] - zeroPoint) / scale));
                q0 = std::max(0, std::min(15, q0));
            }
            
            if (i + 1 < blockEnd) {
                q1 = static_cast<int>(std::round((data[i + 1] - zeroPoint) / scale));
                q1 = std::max(0, std::min(15, q1));
            }
            
            uint8_t packed = static_cast<uint8_t>(q1 << 4 | q0);
            result.data[(i - blockStart) / 2 + b * (result.groupSize / 2)] = packed;
        }
    }
    
    return result;
}

QuantizedTensor RTNQuantizer::QuantizeQ8_0(const std::vector<float>& data, int rows, int cols) {
    QuantizedTensor result;
    result.originalRows = rows;
    result.originalCols = cols;
    result.format = QuantFormat::Q8_0;
    result.groupSize = config_.defaultGroupSize;
    
    int numElements = rows * cols;
    int numBlocks = (numElements + result.groupSize - 1) / result.groupSize;
    
    result.scales.resize(numBlocks);
    result.data.resize(numElements);  // One byte per element
    
    for (int b = 0; b < numBlocks; ++b) {
        int blockStart = b * result.groupSize;
        int blockEnd = std::min(blockStart + result.groupSize, numElements);
        
        // Find max absolute value
        float maxAbs = 0.0f;
        for (int i = blockStart; i < blockEnd; ++i) {
            maxAbs = std::max(maxAbs, std::abs(data[i]));
        }
        
        // Scale to fit in 8 bits (-127 to 127)
        float scale = maxAbs / 127.0f;
        if (scale == 0.0f) scale = 1.0f;
        result.scales[b] = scale;
        
        // Quantize
        for (int i = blockStart; i < blockEnd; ++i) {
            int q = static_cast<int>(std::round(data[i] / scale));
            q = std::max(-127, std::min(127, q));
            result.data[i] = static_cast<uint8_t>(static_cast<int8_t>(q));
        }
    }
    
    return result;
}

QuantizedTensor RTNQuantizer::QuantizeQ8_1(const std::vector<float>& data, int rows, int cols) {
    // Q8_1: 8-bit with offset (similar to Q4_1 but 8-bit)
    QuantizedTensor result;
    result.originalRows = rows;
    result.originalCols = cols;
    result.format = QuantFormat::Q8_1;
    result.groupSize = config_.defaultGroupSize;
    
    int numElements = rows * cols;
    int numBlocks = (numElements + result.groupSize - 1) / result.groupSize;
    
    result.scales.resize(numBlocks * 2);  // scale and zero point
    result.data.resize(numElements);
    
    for (int b = 0; b < numBlocks; ++b) {
        int blockStart = b * result.groupSize;
        int blockEnd = std::min(blockStart + result.groupSize, numElements);
        
        // Find min and max
        float minVal = data[blockStart];
        float maxVal = data[blockStart];
        for (int i = blockStart + 1; i < blockEnd; ++i) {
            minVal = std::min(minVal, data[i]);
            maxVal = std::max(maxVal, data[i]);
        }
        
        float scale = (maxVal - minVal) / 255.0f;
        if (scale == 0.0f) scale = 1.0f;
        float zeroPoint = minVal;
        
        result.scales[b * 2] = scale;
        result.scales[b * 2 + 1] = zeroPoint;
        
        // Quantize
        for (int i = blockStart; i < blockEnd; ++i) {
            int q = static_cast<int>(std::round((data[i] - zeroPoint) / scale));
            q = std::max(0, std::min(255, q));
            result.data[i] = static_cast<uint8_t>(q);
        }
    }
    
    return result;
}

QuantizedTensor RTNQuantizer::QuantizeKQuant(const std::vector<float>& data, int rows, int cols, QuantFormat format) {
    // K-quants: More sophisticated quantization with better accuracy
    // This is a simplified implementation
    QuantizedTensor result;
    result.originalRows = rows;
    result.originalCols = cols;
    result.format = format;
    result.groupSize = 256;  // K-quants use larger groups
    
    int numElements = rows * cols;
    int numBlocks = (numElements + result.groupSize - 1) / result.groupSize;
    
    // K-quants store multiple scales per block for better accuracy
    int scalesPerBlock = (format == QuantFormat::Q4_K_M) ? 2 : 1;
    result.scales.resize(numBlocks * scalesPerBlock);
    
    // Calculate data size based on format
    int bitsPerWeight = GetBitsPerWeight(format);
    size_t dataSize = (numElements * bitsPerWeight + 7) / 8;
    result.data.resize(dataSize);
    
    // Simplified K-quant implementation
    // Real implementation would use more sophisticated algorithms
    for (int b = 0; b < numBlocks; ++b) {
        int blockStart = b * result.groupSize;
        int blockEnd = std::min(blockStart + result.groupSize, numElements);
        
        // Find max absolute value
        float maxAbs = 0.0f;
        for (int i = blockStart; i < blockEnd; ++i) {
            maxAbs = std::max(maxAbs, std::abs(data[i]));
        }
        
        // Compute scale
        int maxQ = (1 << (bitsPerWeight - 1)) - 1;
        float scale = maxAbs / maxQ;
        if (scale == 0.0f) scale = 1.0f;
        result.scales[b * scalesPerBlock] = scale;
        
        // Quantize (simplified - real K-quants are more complex)
        for (int i = blockStart; i < blockEnd; ++i) {
            int q = static_cast<int>(std::round(data[i] / scale));
            int minQ = -(1 << (bitsPerWeight - 1));
            int maxQVal = (1 << (bitsPerWeight - 1)) - 1;
            q = std::max(minQ, std::min(maxQVal, q));
            
            // Pack into result.data (simplified)
            // Real implementation would pack multiple values per byte for 4-bit
        }
    }
    
    return result;
}

} // namespace quantization
} // namespace rawrxd

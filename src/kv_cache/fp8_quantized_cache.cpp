#include "kv_cache/fp8_quantized_cache.hpp"
#include <algorithm>
#include <cmath>
#include <string>

namespace RawrXD {
namespace KVCache {

// ============================================================================
// FP8Quantizer Implementation
// ============================================================================

FP8Quantizer::FP8Quantizer(FP8Format format) : format_(format) {}

uint8_t FP8Quantizer::quantize(float value) const {
    switch (format_) {
        case FP8Format::E4M3:
            return floatToE4M3(value);
        case FP8Format::E5M2:
            return floatToE5M2(value);
        default:
            return floatToE4M3(value);
    }
}

float FP8Quantizer::dequantize(uint8_t fp8) const {
    switch (format_) {
        case FP8Format::E4M3:
            return e4m3ToFloat(fp8);
        case FP8Format::E5M2:
            return e5m2ToFloat(fp8);
        default:
            return e4m3ToFloat(fp8);
    }
}

void FP8Quantizer::quantize(const float* input, uint8_t* output, size_t count,
                            const QuantParams& params) {
    for (size_t i = 0; i < count; ++i) {
        float scaled = input[i] * params.invScale;
        output[i] = quantize(scaled);
    }
}

void FP8Quantizer::dequantize(const uint8_t* input, float* output, size_t count,
                              const QuantParams& params) {
    for (size_t i = 0; i < count; ++i) {
        float val = dequantize(input[i]);
        output[i] = val * params.scale;
    }
}

QuantParams FP8Quantizer::computeScale(const float* data, size_t count,
                                        float percentile) {
    if (count == 0) return QuantParams(1.0f, format_);
    
    // Find max absolute value at percentile
    std::vector<float> absVals;
    absVals.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        absVals.push_back(std::abs(data[i]));
    }
    
    std::nth_element(absVals.begin(), 
                     absVals.begin() + static_cast<size_t>(count * percentile),
                     absVals.end());
    
    float maxVal = absVals[static_cast<size_t>(count * percentile)];
    
    // Compute scale to map maxVal to FP8 max
    float fp8Max = (format_ == FP8Format::E4M3) ? 
                   FP8Constants::E4M3_MAX : FP8Constants::E5M2_MAX;
    
    float scale = maxVal / fp8Max;
    if (scale < 1e-7f) scale = 1.0f;  // Avoid division by zero
    
    return QuantParams(scale, format_);
}

void FP8Quantizer::quantizeWithAutoScale(const float* input, uint8_t* output,
                                           size_t count, QuantParams& outParams) {
    outParams = computeScale(input, count);
    quantize(input, output, count, outParams);
}

// ============================================================================
// E4M3 Implementation (4-bit exponent, 3-bit mantissa)
// ============================================================================

uint8_t FP8Quantizer::floatToE4M3(float value) const {
    // Handle special cases
    if (value == 0.0f) return 0;
    
    // Clamp to E4M3 range
    value = std::max(-FP8Constants::E4M3_MAX, 
                     std::min(FP8Constants::E4M3_MAX, value));
    
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(float));
    
    uint32_t sign = (bits >> 31) & 0x1;
    uint32_t exp = (bits >> 23) & 0xFF;
    uint32_t mant = bits & 0x7FFFFF;
    
    // Adjust exponent bias: 127 (FP32) -> 7 (E4M3)
    int32_t newExp = static_cast<int32_t>(exp) - 127 + FP8Constants::E4M3_BIAS;
    
    // Handle denormals and underflow
    if (newExp <= 0) {
        if (newExp < -3) return static_cast<uint8_t>(sign << 7);
        
        // Denormal: shift mantissa
        uint32_t denormMant = mant | 0x800000;
        denormMant >>= static_cast<uint32_t>(1 - newExp);
        uint32_t mantBits = (denormMant >> 20) & 0x7;
        return static_cast<uint8_t>((sign << 7) | mantBits);
    }
    
    // Clamp exponent
    newExp = std::min(newExp, 15);
    
    // Extract top 3 bits of mantissa
    uint32_t mantBits = (mant >> 20) & 0x7;
    
    // Round to nearest even
    uint32_t roundBit = (mant >> 19) & 0x1;
    uint32_t sticky = mant & 0x7FFFF;
    
    if (roundBit && (sticky != 0 || (mantBits & 0x1))) {
        mantBits++;
        if (mantBits > 7) {
            mantBits = 0;
            newExp++;
            if (newExp > 15) {
                newExp = 15;
                mantBits = 6;
            }
        }
    }
    
    return static_cast<uint8_t>((sign << 7) | (newExp << 3) | mantBits);
}

float FP8Quantizer::e4m3ToFloat(uint8_t fp8) const {
    if (fp8 == 0) return 0.0f;
    
    uint32_t sign = (fp8 >> 7) & 0x1;
    uint32_t exp = (fp8 >> 3) & 0xF;
    uint32_t mant = fp8 & 0x7;
    
    // Reconstruct FP32
    uint32_t fp32Exp;
    uint32_t fp32Mant;
    
    if (exp == 0) {
        // Denormal
        if (mant == 0) {
            // Signed zero
            uint32_t result = sign << 31;
            float f;
            std::memcpy(&f, &result, sizeof(float));
            return f;
        }
        // Normalize denormal
        int shift = 1;
        while ((mant & 0x8) == 0) {
            mant <<= 1;
            shift++;
        }
        mant &= 0x7;
        fp32Exp = (127 - FP8Constants::E4M3_BIAS - shift + 1) << 23;
        fp32Mant = mant << 20;
    } else {
        // Normal number
        fp32Exp = (exp + 127 - FP8Constants::E4M3_BIAS) << 23;
        fp32Mant = mant << 20;
    }
    
    uint32_t result = (sign << 31) | fp32Exp | fp32Mant;
    float f;
    std::memcpy(&f, &result, sizeof(float));
    return f;
}

// ============================================================================
// E5M2 Implementation (5-bit exponent, 2-bit mantissa)
// ============================================================================

uint8_t FP8Quantizer::floatToE5M2(float value) const {
    if (value == 0.0f) return 0;
    
    value = std::max(-FP8Constants::E5M2_MAX, 
                     std::min(FP8Constants::E5M2_MAX, value));
    
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(float));
    
    uint32_t sign = (bits >> 31) & 0x1;
    uint32_t exp = (bits >> 23) & 0xFF;
    uint32_t mant = bits & 0x7FFFFF;
    
    int32_t newExp = static_cast<int32_t>(exp) - 127 + FP8Constants::E5M2_BIAS;
    
    if (newExp <= 0) {
        if (newExp < -1) return static_cast<uint8_t>(sign << 7);
        
        uint32_t denormMant = mant | 0x800000;
        denormMant >>= static_cast<uint32_t>(1 - newExp);
        uint32_t mantBits = (denormMant >> 21) & 0x3;
        return static_cast<uint8_t>((sign << 7) | mantBits);
    }
    
    newExp = std::min(newExp, 31);
    uint32_t mantBits = (mant >> 21) & 0x3;
    
    // Round to nearest even
    uint32_t roundBit = (mant >> 20) & 0x1;
    uint32_t sticky = mant & 0xFFFFF;
    
    if (roundBit && (sticky != 0 || (mantBits & 0x1))) {
        mantBits++;
        if (mantBits > 3) {
            mantBits = 0;
            newExp++;
            if (newExp > 31) {
                newExp = 31;
                mantBits = 2;
            }
        }
    }
    
    return static_cast<uint8_t>((sign << 7) | (newExp << 2) | mantBits);
}

float FP8Quantizer::e5m2ToFloat(uint8_t fp8) const {
    if (fp8 == 0) return 0.0f;
    
    uint32_t sign = (fp8 >> 7) & 0x1;
    uint32_t exp = (fp8 >> 2) & 0x1F;
    uint32_t mant = fp8 & 0x3;
    
    uint32_t fp32Exp;
    uint32_t fp32Mant;
    
    if (exp == 0) {
        if (mant == 0) {
            uint32_t result = sign << 31;
            float f;
            std::memcpy(&f, &result, sizeof(float));
            return f;
        }
        int shift = 1;
        while ((mant & 0x4) == 0) {
            mant <<= 1;
            shift++;
        }
        mant &= 0x3;
        fp32Exp = (127 - FP8Constants::E5M2_BIAS - shift + 1) << 23;
        fp32Mant = mant << 21;
    } else {
        fp32Exp = (exp + 127 - FP8Constants::E5M2_BIAS) << 23;
        fp32Mant = mant << 21;
    }
    
    uint32_t result = (sign << 31) | fp32Exp | fp32Mant;
    float f;
    std::memcpy(&f, &result, sizeof(float));
    return f;
}

// ============================================================================
// KVCacheBlock Implementation
// ============================================================================

KVCacheBlock::KVCacheBlock(size_t heads, size_t dim, size_t len)
    : numHeads(heads), headDim(dim), seqLen(len) {
    size_t totalElements = numHeads * seqLen * headDim;
    keys.resize(totalElements);
    values.resize(totalElements);
    keyScales.resize(numHeads);
    valueScales.resize(numHeads);
}

void KVCacheBlock::resizeSeqLen(size_t newLen) {
    if (newLen <= seqLen) return;
    
    size_t oldElements = numHeads * seqLen * headDim;
    size_t newElements = numHeads * newLen * headDim;
    
    keys.resize(newElements);
    values.resize(newElements);
    seqLen = newLen;
}

size_t KVCacheBlock::memoryBytes() const {
    return keys.size() + values.size() + 
           keyScales.size() * sizeof(QuantParams) +
           valueScales.size() * sizeof(QuantParams);
}

size_t KVCacheBlock::memoryBytesFP32() const {
    return (keys.size() + values.size()) * sizeof(float);
}

double KVCacheBlock::compressionRatio() const {
    return static_cast<double>(memoryBytesFP32()) / memoryBytes();
}

// ============================================================================
// QuantizedKVCache Implementation
// ============================================================================

QuantizedKVCache::QuantizedKVCache(size_t numLayers, size_t numHeads,
                                     size_t headDim, size_t maxSeqLen,
                                     FP8Format format)
    : numLayers_(numLayers), numHeads_(numHeads), headDim_(headDim),
      maxSeqLen_(maxSeqLen), format_(format), quantizer_(format) {
    
    layers_.reserve(numLayers);
    currentSeqLens_.resize(numLayers, 0);
    
    for (size_t i = 0; i < numLayers; ++i) {
        layers_.push_back(std::make_unique<KVCacheBlock>(
            numHeads, headDim, maxSeqLen));
    }
}

void QuantizedKVCache::cacheLayer(size_t layer, size_t seqPos,
                                   const float* keys, const float* values,
                                   size_t numTokens) {
    if (layer >= numLayers_) return;
    
    auto& block = *layers_[layer];
    
    // Ensure capacity
    if (seqPos + numTokens > block.seqLen) {
        block.resizeSeqLen(seqPos + numTokens);
    }
    
    // Quantize per-head
    for (size_t h = 0; h < numHeads_; ++h) {
        size_t headOffset = h * block.seqLen * headDim_;
        size_t tokenOffset = seqPos * headDim_;
        
        // Keys
        const float* keyHead = keys + h * numTokens * headDim_;
        uint8_t* keyDst = block.keys.data() + headOffset + tokenOffset;
        
        QuantParams keyParams = quantizer_.computeScale(keyHead, 
                                                        numTokens * headDim_);
        block.keyScales[h] = keyParams;
        quantizer_.quantize(keyHead, keyDst, numTokens * headDim_, keyParams);
        
        // Values
        const float* valueHead = values + h * numTokens * headDim_;
        uint8_t* valueDst = block.values.data() + headOffset + tokenOffset;
        
        QuantParams valueParams = quantizer_.computeScale(valueHead,
                                                          numTokens * headDim_);
        block.valueScales[h] = valueParams;
        quantizer_.quantize(valueHead, valueDst, numTokens * headDim_, valueParams);
    }
    
    currentSeqLens_[layer] = std::max(currentSeqLens_[layer], seqPos + numTokens);
}

void QuantizedKVCache::retrieveKeys(size_t layer, size_t startPos, size_t endPos,
                                     float* output, size_t headIdx) const {
    if (layer >= numLayers_ || headIdx >= numHeads_) return;
    
    const auto& block = *layers_[layer];
    size_t headOffset = headIdx * block.seqLen * headDim_;
    size_t tokenOffset = startPos * headDim_;
    size_t numTokens = endPos - startPos;
    
    const uint8_t* src = block.keys.data() + headOffset + tokenOffset;
    quantizer_.dequantize(src, output, numTokens * headDim_, block.keyScales[headIdx]);
}

void QuantizedKVCache::retrieveValues(size_t layer, size_t startPos, size_t endPos,
                                       float* output, size_t headIdx) const {
    if (layer >= numLayers_ || headIdx >= numHeads_) return;
    
    const auto& block = *layers_[layer];
    size_t headOffset = headIdx * block.seqLen * headDim_;
    size_t tokenOffset = startPos * headDim_;
    size_t numTokens = endPos - startPos;
    
    const uint8_t* src = block.values.data() + headOffset + tokenOffset;
    quantizer_.dequantize(src, output, numTokens * headDim_, block.valueScales[headIdx]);
}

float QuantizedKVCache::computeAttentionScore(size_t layer, size_t seqPos,
                                               size_t headIdx,
                                               const float* query) const {
    if (layer >= numLayers_ || headIdx >= numHeads_) return 0.0f;
    
    // Retrieve key for this position
    float key[headDim_];  // VLA not standard, use max or allocate
    retrieveKeys(layer, seqPos, seqPos + 1, key, headIdx);
    
    // Dot product
    float score = 0.0f;
    for (size_t i = 0; i < headDim_; ++i) {
        score += query[i] * key[i];
    }
    
    // Scale by sqrt(headDim)
    return score / std::sqrt(static_cast<float>(headDim_));
}

void QuantizedKVCache::clearLayer(size_t layer) {
    if (layer >= numLayers_) return;
    currentSeqLens_[layer] = 0;
}

void QuantizedKVCache::clearAll() {
    std::fill(currentSeqLens_.begin(), currentSeqLens_.end(), 0);
}

size_t QuantizedKVCache::totalMemoryBytes() const {
    size_t total = 0;
    for (const auto& layer : layers_) {
        total += layer->memoryBytes();
    }
    return total;
}

size_t QuantizedKVCache::theoreticalMemoryBytesFP32() const {
    size_t total = 0;
    for (const auto& layer : layers_) {
        total += layer->memoryBytesFP32();
    }
    return total;
}

void QuantizedKVCache::setFormat(FP8Format format) {
    format_ = format;
    quantizer_.setFormat(format);
}

} // namespace KVCache
} // namespace RawrXD

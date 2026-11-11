// ============================================================================
// MixedPrecisionPipeline.cpp - Mixed Precision Pipeline Implementation
// ============================================================================

#include "MixedPrecisionPipeline.hpp"
#include <cstring>
#include <cmath>
#include <iostream>

namespace Sovereign {

MixedPrecisionPipeline::MixedPrecisionPipeline() = default;
MixedPrecisionPipeline::~MixedPrecisionPipeline() = default;

bool MixedPrecisionPipeline::Initialize(const MixedPrecisionConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

void MixedPrecisionPipeline::Shutdown() { initialized_ = false; }

void* MixedPrecisionPipeline::CastToFP16(const float* input, size_t count) {
    stats_.totalCasts++;
    stats_.fp16Casts++;
    uint16_t* output = new uint16_t[count];
    for (size_t i = 0; i < count; ++i) {
        float v = input[i] * config_.lossScale;
        if (std::isinf(v) || std::isnan(v)) { stats_.overflowEvents++; v = 65504.0f; }
        output[i] = static_cast<uint16_t>(std::min(std::max(v, -65504.0f), 65504.0f) * (v >= 0 ? 1 : -1));
    }
    return output;
}

void* MixedPrecisionPipeline::CastToBF16(const float* input, size_t count) {
    stats_.totalCasts++;
    stats_.bf16Casts++;
    uint16_t* output = new uint16_t[count];
    for (size_t i = 0; i < count; ++i) {
        uint32_t bits;
        memcpy(&bits, &input[i], sizeof(bits));
        output[i] = bits >> 16;
    }
    return output;
}

void* MixedPrecisionPipeline::CastToFP8(const float* input, size_t count) {
    stats_.totalCasts++;
    stats_.fp8Casts++;
    int8_t* output = new int8_t[count];
    for (size_t i = 0; i < count; ++i) {
        float v = input[i] * config_.lossScale;
        output[i] = static_cast<int8_t>(std::min(std::max(v, -127.0f), 127.0f));
    }
    return output;
}

void MixedPrecisionPipeline::CastBackToFP32(const void* input, float* output, size_t count, int srcType) {
    if (srcType == 0) { // FP16
        uint16_t* src = (uint16_t*)input;
        for (size_t i = 0; i < count; ++i) {
            uint32_t bits = (src[i] << 16) | (src[i] & 0x8000 ? 0x80000000 : 0);
            memcpy(&output[i], &bits, sizeof(bits));
            output[i] /= config_.lossScale;
        }
    } else if (srcType == 1) { // BF16
        uint16_t* src = (uint16_t*)input;
        for (size_t i = 0; i < count; ++i) {
            uint32_t bits = src[i] << 16;
            memcpy(&output[i], &bits, sizeof(bits));
        }
    } else if (srcType == 2) { // FP8
        int8_t* src = (int8_t*)input;
        for (size_t i = 0; i < count; ++i) {
            output[i] = src[i] / config_.lossScale;
        }
    }
}

} // namespace Sovereign

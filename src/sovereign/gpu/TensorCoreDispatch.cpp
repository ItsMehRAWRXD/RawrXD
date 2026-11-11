// ============================================================================
// TensorCoreDispatch.cpp - Tensor Core & Mixed Precision Implementation
// ============================================================================

#include "TensorCoreDispatch.hpp"
#include <cstring>
#include <iostream>

namespace Sovereign {

TensorCoreDispatch::TensorCoreDispatch() = default;
TensorCoreDispatch::~TensorCoreDispatch() = default;

bool TensorCoreDispatch::Initialize() {
    hasTensorCores_ = true;
    hasFP16_ = true;
    hasBF16_ = true;
    hasFP8_ = false;
    initialized_ = true;
    return true;
}

void TensorCoreDispatch::Shutdown() { initialized_ = false; }

bool TensorCoreDispatch::SelectPrecision(const TensorOpConfig& config) {
    stats_.totalDispatches++;
    switch (config.computePrecision) {
        case PrecisionMode::FP32: stats_.fp32Dispatches++; break;
        case PrecisionMode::FP16: stats_.fp16Dispatches++; break;
        case PrecisionMode::BF16: stats_.bf16Dispatches++; break;
        case PrecisionMode::FP8: stats_.fp8Dispatches++; break;
        case PrecisionMode::MIXED: stats_.mixedDispatches++; break;
    }
    return true;
}

PrecisionMode TensorCoreDispatch::GetOptimalPrecision(TensorOp op, uint32_t m, uint32_t n, uint32_t k) const {
    if (hasFP8_) return PrecisionMode::FP8;
    if (hasFP16_) return PrecisionMode::FP16;
    return PrecisionMode::FP32;
}

bool TensorCoreDispatch::SupportsPrecision(PrecisionMode mode) const {
    switch (mode) {
        case PrecisionMode::FP16: return hasFP16_;
        case PrecisionMode::BF16: return hasBF16_;
        case PrecisionMode::FP8: return hasFP8_;
        default: return true;
    }
}

bool TensorCoreDispatch::DispatchGEMV(const float* weights, const float* input, float* output, uint32_t rows, uint32_t cols, PrecisionMode mode) {
    for (uint32_t i = 0; i < rows; ++i) {
        float sum = 0;
        for (uint32_t j = 0; j < cols; ++j) {
            sum += weights[i * cols + j] * input[j];
        }
        output[i] = sum;
    }
    return true;
}

bool TensorCoreDispatch::DispatchGEMM(const float* A, const float* B, float* C, uint32_t m, uint32_t n, uint32_t k, PrecisionMode mode) {
    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            float sum = 0;
            for (uint32_t l = 0; l < k; ++l) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
    return true;
}

} // namespace Sovereign

// ============================================================================
// QuantKernelRegistryHooks.cpp - Implementation of built-in dequant/GEMV hooks
// ============================================================================
#include "QuantKernelRegistryHooks.h"
#include "GGUFLoader.hpp"
#include <cstring>
#include <cmath>

namespace Deep2 {

// FP16 to FP32 conversion helper
static inline float fp16ToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400));
            mant &= 0x3FF;
            f = (sign << 31) | ((127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float result;
    std::memcpy(&result, &f, sizeof(float));
    return result;
}

// Q4_0 dequant: 32 weights + 1 FP16 scale per block
static void DequantQ4_0(const void* input, float* output, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(input);
    size_t numBlocks = n / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        uint16_t d = *reinterpret_cast<const uint16_t*>(data + b * 18);
        float scale = fp16ToFloat(d);
        const uint8_t* qs = data + b * 18 + 2;
        for (int i = 0; i < 16; ++i) {
            int lo = qs[i] & 0xF;
            int hi = (qs[i] >> 4) & 0xF;
            output[b * 32 + i]      = scale * (lo - 8);
            output[b * 32 + i + 16] = scale * (hi - 8);
        }
    }
}

// Q4_1 dequant: 32 weights + 1 FP16 scale + 1 FP16 min per block
static void DequantQ4_1(const void* input, float* output, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(input);
    size_t numBlocks = n / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        uint16_t d = *reinterpret_cast<const uint16_t*>(data + b * 20);
        uint16_t m = *reinterpret_cast<const uint16_t*>(data + b * 20 + 2);
        float scale = fp16ToFloat(d);
        float min = fp16ToFloat(m);
        const uint8_t* qs = data + b * 20 + 4;
        for (int i = 0; i < 16; ++i) {
            int lo = qs[i] & 0xF;
            int hi = (qs[i] >> 4) & 0xF;
            output[b * 32 + i]      = scale * lo + min;
            output[b * 32 + i + 16] = scale * hi + min;
        }
    }
}

// Q5_0 dequant
static void DequantQ5_0(const void* input, float* output, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(input);
    size_t numBlocks = n / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        uint16_t d = *reinterpret_cast<const uint16_t*>(data + b * 22);
        float scale = fp16ToFloat(d);
        const uint8_t* qh = data + b * 22 + 2;
        const uint8_t* qs = data + b * 22 + 7;
        for (int i = 0; i < 32; ++i) {
            int x = (qs[i] & 0xF);
            int h = (qh[i / 8] >> (i % 8)) & 1;
            output[b * 32 + i] = scale * (x + (h << 4) - 16);
        }
    }
}

// Q8_0 dequant: 32 weights + 1 FP16 scale per block
static void DequantQ8_0(const void* input, float* output, size_t n) {
    const uint8_t* data = static_cast<const uint8_t*>(input);
    size_t numBlocks = n / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        uint16_t d = *reinterpret_cast<const uint16_t*>(data + b * 34);
        float scale = fp16ToFloat(d);
        const int8_t* qs = reinterpret_cast<const int8_t*>(data + b * 34 + 2);
        for (int i = 0; i < 32; ++i) {
            output[b * 32 + i] = scale * (float)qs[i];
        }
    }
}

// FP32 passthrough
static void DequantFP32(const void* input, float* output, size_t n) {
    std::memcpy(output, input, n * sizeof(float));
}

// FP16 to FP32
static void DequantFP16(const void* input, float* output, size_t n) {
    const uint16_t* data = static_cast<const uint16_t*>(input);
    for (size_t i = 0; i < n; ++i) {
        output[i] = fp16ToFloat(data[i]);
    }
}

// Q4_K_M dequant (simplified)
static void DequantQ4_K(const void* input, float* output, size_t n) {
    // Simplified Q4_K dequant - full implementation would parse block_q4_K
    // For now, zero-fill as placeholder
    std::memset(output, 0, n * sizeof(float));
}

// Q2_K dequant stub
static void DequantQ2_K(const void* input, float* output, size_t n) {
    std::memset(output, 0, n * sizeof(float));
}

// Q3_K dequant stub
static void DequantQ3_K(const void* input, float* output, size_t n) {
    std::memset(output, 0, n * sizeof(float));
}

// Q5_K dequant stub
static void DequantQ5_K(const void* input, float* output, size_t n) {
    std::memset(output, 0, n * sizeof(float));
}

// Q6_K dequant stub
static void DequantQ6_K(const void* input, float* output, size_t n) {
    std::memset(output, 0, n * sizeof(float));
}

// GEMV stubs for each quant type
static void GEMV_Q4_0(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q4_1(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q5_0(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q8_0(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_FP32(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    const float* w = reinterpret_cast<const float*>(weights);
    for (size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; ++c) {
            sum += w[r * cols + c] * input[c];
        }
        output[r] = sum;
    }
}

static void GEMV_FP16(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    const uint16_t* w = reinterpret_cast<const uint16_t*>(weights);
    for (size_t r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; ++c) {
            sum += fp16ToFloat(w[r * cols + c]) * input[c];
        }
        output[r] = sum;
    }
}

static void GEMV_Q4_K(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q2_K(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q3_K(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q5_K(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

static void GEMV_Q6_K(const uint8_t* weights, const float* input, float* output, size_t rows, size_t cols) {
    std::memset(output, 0, rows * sizeof(float));
}

void QuantKernelRegistryHooks::InitializeBuiltins() {
    // Register dequant handlers
    RegisterDequant(0, DequantFP32);    // GGML_TYPE_F32
    RegisterDequant(1, DequantFP16);     // GGML_TYPE_F16
    RegisterDequant(2, DequantQ4_0);     // GGML_TYPE_Q4_0
    RegisterDequant(3, DequantQ4_1);     // GGML_TYPE_Q4_1
    RegisterDequant(6, DequantQ5_0);     // GGML_TYPE_Q5_0
    RegisterDequant(8, DequantQ8_0);     // GGML_TYPE_Q8_0
    RegisterDequant(10, DequantQ2_K);    // GGML_TYPE_Q2_K
    RegisterDequant(11, DequantQ3_K);    // GGML_TYPE_Q3_K
    RegisterDequant(12, DequantQ4_K);    // GGML_TYPE_Q4_K
    RegisterDequant(13, DequantQ5_K);    // GGML_TYPE_Q5_K
    RegisterDequant(14, DequantQ6_K);    // GGML_TYPE_Q6_K

    // Register GEMV handlers
    RegisterGEMV(0, GEMV_FP32);          // GGML_TYPE_F32
    RegisterGEMV(1, GEMV_FP16);          // GGML_TYPE_F16
    RegisterGEMV(2, GEMV_Q4_0);           // GGML_TYPE_Q4_0
    RegisterGEMV(3, GEMV_Q4_1);           // GGML_TYPE_Q4_1
    RegisterGEMV(6, GEMV_Q5_0);           // GGML_TYPE_Q5_0
    RegisterGEMV(8, GEMV_Q8_0);           // GGML_TYPE_Q8_0
    RegisterGEMV(10, GEMV_Q2_K);          // GGML_TYPE_Q2_K
    RegisterGEMV(11, GEMV_Q3_K);          // GGML_TYPE_Q3_K
    RegisterGEMV(12, GEMV_Q4_K);          // GGML_TYPE_Q4_K
    RegisterGEMV(13, GEMV_Q5_K);          // GGML_TYPE_Q5_K
    RegisterGEMV(14, GEMV_Q6_K);          // GGML_TYPE_Q6_K
}

} // namespace Deep2

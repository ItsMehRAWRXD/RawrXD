// src/engine/kernels/SovereignMathCore.hpp
// Sovereign Math Core — Multi-Architecture Intrinsic Dispatch
// Zero-dependency vector math for GGUF inference
//
// Exposes uniform mathematical function signatures to execution graph builders,
// choosing the most efficient vector registers dynamically depending on hardware
// feature flags detected at startup.

#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

// ---------------------------------------------------------------------------
// GGUF tensor type codes
// ---------------------------------------------------------------------------
enum class GgufType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q2_K = 14,
    Q3_K = 15,
    Q4_K = 16,
    Q5_K = 17,
    Q6_K = 18,
    Unknown = 0xFFFFFFFF
};

// ---------------------------------------------------------------------------
// Structural layout specs for GGUF Q4_0 blocks (32 elements per block)
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
struct Block_Q4_0 {
    uint16_t deltaHalf;      // FP16 scale multiplier tracking variable
    uint8_t  packedNibbles[16]; // 32 compressed 4-bit weight states
};
#pragma pack(pop)

struct Block_Q8_0 {
    float scale;             // FP32 scale
    int8_t quantized[32];    // 32 8-bit quantized values
};

struct Block_Q4_K {
    uint8_t scale[8];        // 6-bit scales (48 bits) + 2 reserved
    uint8_t highBits;         // High bits for 256 4-bit values
    uint8_t packedNibbles[128]; // 256 4-bit values packed
};

// ---------------------------------------------------------------------------
// Hardware feature detection
// ---------------------------------------------------------------------------
struct CpuFeatures {
    bool hasAvx2 = false;
    bool hasAvx512 = false;
    bool hasFma = false;
    bool hasF16c = false;

    static CpuFeatures Detect() {
        CpuFeatures f;
        int cpuInfo[4] = {0};
#if defined(_MSC_VER)
        __cpuid(cpuInfo, 1);
#else
        __get_cpuid(1, (unsigned*)&cpuInfo[0], (unsigned*)&cpuInfo[1],
                    (unsigned*)&cpuInfo[2], (unsigned*)&cpuInfo[3]);
#endif
        f.hasAvx2 = (cpuInfo[2] & (1 << 5)) != 0;  // EBX bit 5 for AVX2
        f.hasAvx512 = (cpuInfo[2] & (1 << 16)) != 0; // AVX512F
        f.hasFma = (cpuInfo[2] & (1 << 12)) != 0;
        f.hasF16c = (cpuInfo[2] & (1 << 29)) != 0;
        return f;
    }
};

// ---------------------------------------------------------------------------
// Sovereign Math Core — unified entry points
// ---------------------------------------------------------------------------
class SovereignMathCore {
public:
    // Hardware feature flags (populated once at startup)
    static CpuFeatures s_features;

    // Initialize feature detection
    static void Initialize() { s_features = CpuFeatures::Detect(); }

    // Dequantize a single Q4_0 row (32 elements) to FP32
    static void Dequantize_Q4_0_Row(const void* __restrict src, float* __restrict dst, size_t elements);

    // Dequantize a single Q8_0 row (32 elements) to FP32
    static void Dequantize_Q8_0_Row(const void* __restrict src, float* __restrict dst, size_t elements);

    // Matrix-vector multiply: y = A * x where A is Q4_0 quantized
    // A is m rows x n columns, stored in Q4_0 block format
    static void Gemv_Q4_0_Matrix(
        size_t m, size_t n,
        const void* __restrict weights,
        const float* __restrict input,
        float* __restrict output
    );

    // Matrix-vector multiply: y = A * x where A is FP32
    static void Gemv_F32_Matrix(
        size_t m, size_t n,
        const float* __restrict weights,
        const float* __restrict input,
        float* __restrict output
    );

    // RMS Normalization
    static void RmsNorm(float* o, const float* x, const float* weight, int n, float eps = 1e-6f);

    // Softmax
    static void Softmax(float* x, int n);

    // SiLU activation
    static void SiLU(float* x, int n);

    // RoPE (Rotary Position Embedding)
    static void RoPE(float* q, int dim, int pos, float theta = 10000.0f);

    // FP16 → FP32 conversion
    static float FP16_To_FP32(uint16_t h);
};

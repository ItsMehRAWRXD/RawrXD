/*
====================================================================
 rawr_braid_classifier.hpp - Weight Block Format Classifier
====================================================================

 Determines optimal braid quantization format per 256-weight block
 based on statistical analysis of the weight distribution.

 Formats:
   WF_ZERO = 0  : All zeros / no valid finite values
   WF_B1   = 1  : Binary (1-bit), density < 20%
   WF_T3   = 3  : Ternary (3-state), tight distribution
   WF_Q3   = 4  : 3-bit quantized, moderate dynamic range
   WF_Q4   = 5  : 4-bit quantized, high dynamic range
   WF_RAW  = 255: Fallback / passthrough

 The classifier analyzes:
   Density = nz / n
   Peak    = maxAbs / (meanAbs + eps)

 Decision matrix:
   maxAbs == 0        → WF_ZERO
   density < 0.20     → WF_B1
   peak < 2.5         → WF_T3
   peak < 6.0         → WF_Q3
   otherwise          → WF_Q4

 Compile:
   ml64 /c /Fo rawr_classifier_scalar.obj rawr_classifier_scalar.asm
   ml64 /c /Fo rawr_classifier_avx2.obj rawr_classifier_avx2.asm
   cl /std:c++17 /O2 /arch:AVX2 ...
====================================================================
*/

#ifndef RAWR_BRAID_CLASSIFIER_HPP
#define RAWR_BRAID_CLASSIFIER_HPP

#include <cstdint>
#include <cstddef>

#ifdef _WIN32
  #include <intrin.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// External MASM Routines
// ============================================================================

// Scalar classifier - works on all x64, no SIMD required
// Parameters: RCX = const float* w, EDX = uint32_t n
// Returns: AX = WeightFormat
uint16_t ClassifyScalar(const float* w, uint32_t n);

// AVX2 classifier - processes 8 floats per iteration
// Parameters: RCX = const float* w, EDX = uint32_t n
// Returns: AX = WeightFormat
// Requires: AVX2 support (check CPUID before calling)
uint16_t ClassifyAVX2(const float* w, uint32_t n);

#ifdef __cplusplus
}
#endif

namespace rawrxd {
namespace braid {

// ============================================================================
// C++ Interface
// ============================================================================

enum WeightFormat : uint8_t {
    WF_ZERO = 0,    // All zeros / empty
    WF_B1   = 1,    // Binary: {-scale, +scale}
    WF_T3   = 3,    // Ternary: {-scale, 0, +scale}
    WF_Q3   = 4,    // 3-bit: 8 levels
    WF_Q4   = 5,    // 4-bit: 16 levels (signed)
    WF_RAW  = 255   // Passthrough / unclassified
};

// CPU feature detection for runtime dispatch
struct CPUFeatures {
    bool has_avx2 = false;
    bool has_fma = false;
    bool has_avx512f = false;
    bool initialized = false;

    void detect() {
        if (initialized) return;
#ifdef _WIN32
        int regs[4];
        __cpuid(regs, 1);
        has_avx2 = (regs[2] & (1 << 28)) != 0;  // AVX
        has_fma = (regs[2] & (1 << 12)) != 0;   // FMA
        __cpuidex(regs, 7, 0);
        has_avx2 = has_avx2 && ((regs[1] & (1 << 5)) != 0);  // AVX2
        has_avx512f = (regs[1] & (1 << 16)) != 0;
#else
        // Linux: parse /proc/cpuinfo or use __builtin_cpu_supports
        __builtin_cpu_init();
        has_avx2 = __builtin_cpu_supports("avx2");
        has_fma = __builtin_cpu_supports("fma");
        has_avx512f = __builtin_cpu_supports("avx512f");
#endif
        initialized = true;
    }
};

// Thread-safe singleton feature detector
inline const CPUFeatures& GetCPUFeatures() {
    static CPUFeatures features;
    features.detect();
    return features;
}

// ============================================================================
// Unified Classifier - Auto-dispatches to best implementation
// ============================================================================
inline WeightFormat ClassifyBlock(const float* weights, uint32_t count) {
    const auto& cpu = GetCPUFeatures();
    if (cpu.has_avx2) {
        return static_cast<WeightFormat>(ClassifyAVX2(weights, count));
    }
    return static_cast<WeightFormat>(ClassifyScalar(weights, count));
}

// ============================================================================
// Format Properties
// ============================================================================
inline const char* FormatName(WeightFormat fmt) {
    switch (fmt) {
        case WF_ZERO: return "ZERO";
        case WF_B1:   return "B1";
        case WF_T3:   return "T3";
        case WF_Q3:   return "Q3";
        case WF_Q4:   return "Q4";
        case WF_RAW:  return "RAW";
        default:      return "UNKNOWN";
    }
}

inline uint8_t FormatBits(WeightFormat fmt) {
    switch (fmt) {
        case WF_ZERO: return 0;
        case WF_B1:   return 1;
        case WF_T3:   return 2;  // ~1.585 bits theoretical, 2 practical
        case WF_Q3:   return 3;
        case WF_Q4:   return 4;
        case WF_RAW:  return 32; // FP32 passthrough
        default:      return 32;
    }
}

// Expected compressed bytes for a 256-weight block
inline uint32_t FormatBlockBytes(WeightFormat fmt) {
    switch (fmt) {
        case WF_ZERO: return 2;   // Just scale (0)
        case WF_B1:   return 34;  // 2-byte scale + 32-byte bitset
        case WF_T3:   return 54;  // 2-byte scale + 52-byte base-3 payload
        case WF_Q3:   return 98;  // 2-byte scale + 96-byte payload (256*3/8)
        case WF_Q4:   return 130; // 2-byte scale + 128-byte payload
        case WF_RAW:  return 1024; // 256 * 4 bytes FP32
        default:      return 1024;
    }
}

// Compression ratio vs FP32
inline float FormatCompressionRatio(WeightFormat fmt) {
    return 1024.0f / static_cast<float>(FormatBlockBytes(fmt));
}

} // namespace braid
} // namespace rawrxd

#endif // RAWR_BRAID_CLASSIFIER_HPP

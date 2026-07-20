#pragma once
#include <cstdint>
#include <cstddef>

// ═══════════════════════════════════════════════════════════════════════════════
// VAL-036 Fix: LUT-based Vectorized Softmax (AVX-512)
// ═══════════════════════════════════════════════════════════════════════════════
// Replaces polynomial exp with fast LUT + linear interpolation
// Target: < 0.3 µs (down from 27.941 µs polynomial catastrophe)
// ═══════════════════════════════════════════════════════════════════════════════

namespace RawrXD {

// External assembly functions
extern "C" {
    // Fast softmax using LUT + linear interpolation
    void Softmax_LUT_AVX512(
        const float* input,     // [length]
        float* output,          // [length]
        uint32_t length         // Number of elements
    );

    // Initialize LUT tables (call once at startup)
    void Softmax_LUT_Init();
}

// C++ wrapper class
class SoftmaxLUTKernel {
public:
    SoftmaxLUTKernel() {
        // Initialize LUT on first use
        static bool initialized = false;
        if (!initialized) {
            Softmax_LUT_Init();
            initialized = true;
        }
    }

    void Compute(const float* input, float* output, uint32_t length) {
        Softmax_LUT_AVX512(input, output, length);
    }

    // Check if AVX-512 is available
    static bool IsSupported();
};

} // namespace RawrXD

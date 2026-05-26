#pragma once
#include <cstdint>
#include <immintrin.h>

// =============================================================================
// TITAN ACCUMULATOR STATE ABI BOUNDARY
// =============================================================================
// Maps the architectural register file (YMM0-YMM7) directly into C++ memory.
// Must be strictly 32-byte aligned for vmovups/vmovaps efficiency.
// This structure allows the MASM engine to preserve and resume the 8-way 
// execution wave across tensor tile boundaries without destroying context.
// =============================================================================

namespace Titan {
namespace Core {

#if defined(_MSC_VER)
    __declspec(align(64))
#else
    __attribute__((aligned(64)))
#endif
    struct AccumulatorState {
        // 8 YMM registers * 32 bytes = 256 bytes 
        // Fits perfectly into 4 typical 64-byte L1 cache lines
        float ymm0[8];
        float ymm1[8];
        float ymm2[8];
        float ymm3[8];
        float ymm4[8];
        float ymm5[8];
        float ymm6[8];
        float ymm7[8];

        void Clear() {
            for (int i = 0; i < 8; ++i) {
                ymm0[i] = 0.0f; ymm1[i] = 0.0f;
                ymm2[i] = 0.0f; ymm3[i] = 0.0f;
                ymm4[i] = 0.0f; ymm5[i] = 0.0f;
                ymm6[i] = 0.0f; ymm7[i] = 0.0f;
            }
        }
    };

    // External MASM kernel function definition
    extern "C" void RunFused8WayKernel(
        const float* activations, 
        const float* weights, 
        uint64_t step_count, 
        AccumulatorState* state
    );

} // namespace Core
} // namespace Titan
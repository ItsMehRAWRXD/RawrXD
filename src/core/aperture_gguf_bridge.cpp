// ============================================================================
// aperture_gguf_bridge.cpp — Aperture AVX-512 Kernel Integration for GGUF Loader
// ============================================================================
// Bridges the Aperture AVX-512 Q4_0 dequantization kernel to the GGUF DML loader.
// Provides dispatch-based selection between AVX-512 and reference implementations.
//
// Integration point: Replaces/augments asm_dml_dequant_q4_0_to_fp32
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>

// Aperture kernel API
extern "C" {
    // CPU feature detection
    void Aperture_InitCPUFeatures(void);
    int Aperture_HasAVX512F(void);
    int Aperture_HasAVX512BW(void);
    const char* Aperture_GetKernelName(void);
    
    // Dequantization kernels
    int Aperture_Q4_0_Dequant(const uint8_t* src, float* dst, size_t num_blocks);
    int Aperture_Q4_0_Dequant_Reference(const uint8_t* src, float* dst, size_t num_blocks);
    int Aperture_Q4_0_Dequant_AVX512(const uint8_t* src, float* dst, size_t num_blocks);
}

// ============================================================================
// Feature Flags
// ============================================================================

static bool g_aperture_initialized = false;
static bool g_aperture_use_avx512 = false;

/**
 * @brief Initialize Aperture kernel dispatch
 * 
 * Call once during engine startup to detect CPU features and select optimal kernel.
 */
extern "C" void Aperture_InitDispatch(void) {
    if (g_aperture_initialized) {
        return;
    }
    
    Aperture_InitCPUFeatures();
    
    // Check for AVX-512 Foundation and Byte/Word support
    g_aperture_use_avx512 = (Aperture_HasAVX512F() && Aperture_HasAVX512BW());
    
    g_aperture_initialized = true;
    
    // Production heartbeat: Log kernel selection on first init
    static bool first_run = true;
    if (first_run) {
        if (g_aperture_use_avx512) {
            printf("[Aperture] Initialization complete: Using AVX-512 Kernel (Ready for inference)\n");
        } else {
            printf("[Aperture] Initialization complete: Using Reference Kernel (AVX-512 unavailable)\n");
        }
        first_run = false;
    }
}

/**
 * @brief Check if AVX-512 kernel is available and selected
 */
extern "C" int Aperture_IsAVX512Available(void) {
    if (!g_aperture_initialized) {
        Aperture_InitDispatch();
    }
    return g_aperture_use_avx512 ? 1 : 0;
}

/**
 * @brief Get current kernel name for diagnostics
 */
extern "C" const char* Aperture_GetActiveKernelName(void) {
    if (!g_aperture_initialized) {
        Aperture_InitDispatch();
    }
    return Aperture_GetKernelName();
}

// ============================================================================
// GGUF DML Bridge Integration
// ============================================================================

/**
 * @brief Q4_0 dequantization for GGUF DML bridge
 * 
 * This function replaces the existing asm_dml_dequant_q4_0_to_fp32.
 * It automatically dispatches to AVX-512 or reference based on CPU capabilities.
 * 
 * @param dest Output buffer (float32, must be 64-byte aligned for AVX-512)
 * @param src Input buffer (Q4_0 quantized data)
 * @param blockCount Number of Q4_0 blocks to dequantize
 * @return 0 on success, negative error code on failure
 */
extern "C" int64_t asm_dml_dequant_q4_0_to_fp32(float* dest, const uint8_t* src, uint64_t blockCount) {
    if (!dest || !src || blockCount == 0) {
        return -1;  // Invalid parameters
    }
    
    if (!g_aperture_initialized) {
        Aperture_InitDispatch();
    }
    
    // Use dispatch function which automatically selects AVX-512 or reference
    int result = Aperture_Q4_0_Dequant(src, dest, static_cast<size_t>(blockCount));
    
    return (result == 0) ? 0 : -10;  // 0 = success, -10 = dequant failed
}

// Forward declaration for intrinsics kernel
extern "C" int64_t Aperture_Q8_0_Dequant_AVX512_Intrinsics(float* dest, const uint8_t* src, uint64_t blockCount);

/**
 * @brief Q8_0 dequantization with AVX-512 acceleration
 * 
 * Automatically dispatches to AVX-512 intrinsics kernel when available,
 * falls back to reference implementation on non-AVX-512 systems.
 * 
 * @param dest Output buffer (float32)
 * @param src Input buffer (Q8_0 quantized data)
 * @param blockCount Number of Q8_0 blocks to dequantize
 * @return 0 on success, negative error code on failure
 */
extern "C" int64_t asm_dml_dequant_q8_0_to_fp32(float* dest, const uint8_t* src, uint64_t blockCount) {
    if (!dest || !src || blockCount == 0) {
        return -1;
    }
    
    // Ensure dispatch is initialized
    if (!g_aperture_initialized) {
        Aperture_InitDispatch();
    }
    
    // Use AVX-512 intrinsics kernel if available
    if (g_aperture_use_avx512) {
        return Aperture_Q8_0_Dequant_AVX512_Intrinsics(dest, src, blockCount);
    }
    
    // Fallback to reference implementation
    // Q8_0 format: 2 bytes scale (fp16) + 32 bytes data (int8)
    // Total: 34 bytes per 32 weights
    const size_t Q8_0_BLOCK_SIZE = 32;
    const size_t Q8_0_BLOCK_BYTES = 34;
    
    for (uint64_t b = 0; b < blockCount; ++b) {
        const uint8_t* block = src + b * Q8_0_BLOCK_BYTES;
        
        // Read scale as fp16
        uint16_t scale_raw = *reinterpret_cast<const uint16_t*>(block);
        
        // Convert fp16 to fp32
        auto fp16ToFp32 = [](uint16_t h) -> float {
            uint32_t sign = (h >> 15) & 1;
            uint32_t exp = (h >> 10) & 0x1F;
            uint32_t man = h & 0x3FF;
            
            if (exp == 0) {
                if (man == 0) return sign ? -0.0f : 0.0f;
                float v = static_cast<float>(man) / 1024.0f * 0.00006103515625f;
                return sign ? -v : v;
            }
            if (exp == 31) {
                return (man == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
            }
            
            int32_t new_exp = static_cast<int32_t>(exp) - 15 + 127;
            uint32_t f32 = (sign << 31) | (static_cast<uint32_t>(new_exp) << 23) | (man << 13);
            float result;
            memcpy(&result, &f32, sizeof(float));
            return result;
        };
        
        float scale = fp16ToFp32(scale_raw);
        
        // Dequantize int8 weights
        const int8_t* weights = reinterpret_cast<const int8_t*>(block + 2);
        for (size_t i = 0; i < Q8_0_BLOCK_SIZE; ++i) {
            dest[b * Q8_0_BLOCK_SIZE + i] = static_cast<float>(weights[i]) * scale;
        }
    }
    
    return 0;
}

// ============================================================================
// Feature Flag Access
// ============================================================================

/**
 * @brief Enable/disable AVX-512 kernel at runtime
 * 
 * Useful for testing or working around hardware issues.
 * 
 * @param enable true to use AVX-512 (if available), false to force reference
 */
extern "C" void Aperture_SetUseAVX512(bool enable) {
    if (!g_aperture_initialized) {
        Aperture_InitDispatch();
    }
    g_aperture_use_avx512 = enable;
}

/**
 * @brief Check if AVX-512 is currently enabled
 */
extern "C" int Aperture_GetUseAVX512(void) {
    return g_aperture_use_avx512 ? 1 : 0;
}

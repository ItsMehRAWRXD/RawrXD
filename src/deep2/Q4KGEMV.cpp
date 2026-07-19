// ============================================================================
// Q4KGEMV.cpp - Q4_K_M GEMV Implementation
// ============================================================================

#include "Q4KGEMV.h"
#include <cstring>
#include <cstdio>

#ifdef _WIN32
    #include <intrin.h>
#else
    #include <cpuid.h>
#endif

namespace Deep2 {

// ============================================================================
// CPU Feature Detection
// ============================================================================
static bool g_cpuFeaturesChecked = false;
static bool g_hasAVX2 = false;
static bool g_hasAVX512 = false;

static void checkCPUFeatures() {
    if (g_cpuFeaturesChecked) return;
    
    int cpuInfo[4] = {0};
    
#ifdef _WIN32
    __cpuid(cpuInfo, 1);
    bool hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuidex(cpuInfo, 7, 0);
    g_hasAVX2 = hasAVX && ((cpuInfo[1] & (1 << 5)) != 0);
    g_hasAVX512 = g_hasAVX2 && ((cpuInfo[1] & (1 << 16)) != 0);
#else
    __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    bool hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuid_count(7, 0, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    g_hasAVX2 = hasAVX && ((cpuInfo[1] & (1 << 5)) != 0);
    g_hasAVX512 = g_hasAVX2 && ((cpuInfo[1] & (1 << 16)) != 0);
#endif
    
    g_cpuFeaturesChecked = true;
}

// ============================================================================
// Scalar fallback for comparison/testing
// ============================================================================
static void q4k_gemv_scalar(
    const Q4_K_M_Block* blocks,
    const float* input,
    float* output,
    size_t numRows,
    size_t numCols
) {
    size_t blockCols = (numCols + 255) / 256;
    
    for (size_t row = 0; row < numRows; ++row) {
        float sum = 0.0f;
        size_t blockRow = row / 256;
        size_t localRow = row % 256;
        size_t group = localRow / 8;
        size_t idx = localRow % 8;
        
        for (size_t bc = 0; bc < blockCols; ++bc) {
            const Q4_K_M_Block* block = &blocks[blockRow * blockCols + bc];
            
            // Load scale and min
            float scale = block->scales[group] / 1000.0f;
            float minVal = block->mins[group] / 1000.0f;
            
            // Process 256 columns in this block
            for (size_t c = 0; c < 256 && (bc * 256 + c) < numCols; ++c) {
                size_t cg = c / 8;
                size_t ci = c % 8;
                
                float cScale = block->scales[cg] / 1000.0f;
                float cMin = block->mins[cg] / 1000.0f;
                
                // Dequantize
                uint8_t packed = block->qs[cg * 4 + ci / 2];
                int q = (ci % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                float weight = cMin + cScale * q;
                
                sum += input[bc * 256 + c] * weight;
            }
        }
        
        output[row] = sum;
    }
}

// ============================================================================
// Q4KGEMV Implementation
// ============================================================================

void Q4KGEMV::multiply(
    const Q4KTensorView& weights,
    const float* input,
    float* output
) {
    if (!weights.blocks || !input || !output) {
        return;
    }
    
    checkCPUFeatures();
    
    size_t numBlocks = (weights.numRows + 255) / 256;
    size_t blockStride = weights.blockCols * sizeof(Q4_K_M_Block);
    
    // Choose implementation based on CPU features
    if (g_hasAVX2) {
        // Use AVX2 MASM kernel
        Sovereign_Q4K_GEMV_AVX2(
            weights.blocks,
            input,
            output,
            numBlocks,
            blockStride
        );
    } else {
        // Fallback to scalar
        q4k_gemv_scalar(
            weights.blocks,
            input,
            output,
            weights.numRows,
            weights.numCols
        );
    }
}

const char* Q4KGEMV::getKernelName() {
    checkCPUFeatures();
    if (g_hasAVX512) return "Sovereign_Q4K_GEMV_AVX512";
    if (g_hasAVX2) return "Sovereign_Q4K_GEMV_AVX2";
    return "q4k_gemv_scalar";
}

bool Q4KGEMV::isAVX2Supported() {
    checkCPUFeatures();
    return g_hasAVX2;
}

bool Q4KGEMV::isAVX512Supported() {
    checkCPUFeatures();
    return g_hasAVX512;
}

} // namespace Deep2

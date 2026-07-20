// ============================================================================
// KernelDispatcher.cpp - Runtime Kernel Selection and Dispatch
// ============================================================================

#include "KernelDispatcher.hpp"
#include "Deep2Engine.h"
#include <cstdio>
#include <chrono>
#include <intrin.h>

// MASM kernel interface
extern "C" {
    void Deep2_Q4K_GEMV(const void* weights, const float* input, float* output,
                        uint32_t numBlocks, uint32_t rows);
}

namespace Deep2 {

// Static members
bool KernelDispatcher::initialized = false;
CPUFeatures KernelDispatcher::cpuFeatures;
DispatchRecord KernelDispatcher::lastDispatch;

// ============================================================================
// CPU Feature Detection
// ============================================================================
CPUFeatures CPUFeatures::Detect() {
    CPUFeatures features;
    
    int cpuInfo[4] = {0};
    
    // Get vendor string and max basic function
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];
    
    if (nIds >= 1) {
        __cpuid(cpuInfo, 1);
        features.hasAVX  = (cpuInfo[2] & (1 << 28)) != 0;  // ECX bit 28
    }
    
    if (nIds >= 7) {
        __cpuid(cpuInfo, 7);
        features.hasAVX2   = (cpuInfo[1] & (1 << 5))  != 0;  // EBX bit 5
        features.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;  // EBX bit 16 (AVX512F)
        features.hasVNNI   = (cpuInfo[2] & (1 << 11)) != 0;  // ECX bit 11 (AVX512-VNNI)
    }
    
    // FMA is implied by AVX2 but check explicitly
    if (nIds >= 1) {
        __cpuid(cpuInfo, 1);
        features.hasFMA = (cpuInfo[2] & (1 << 12)) != 0;  // ECX bit 12
    }
    
    return features;
}

void CPUFeatures::Print() const {
    printf("[KernelDispatcher] CPU Features:\n");
    printf("  AVX:    %s\n", hasAVX    ? "YES" : "NO");
    printf("  AVX2:   %s\n", hasAVX2   ? "YES" : "NO");
    printf("  AVX512: %s\n", hasAVX512 ? "YES" : "NO");
    printf("  FMA:    %s\n", hasFMA    ? "YES" : "NO");
    printf("  VNNI:   %s\n", hasVNNI   ? "YES" : "NO");
}

// ============================================================================
// KernelDispatcher Implementation
// ============================================================================
void KernelDispatcher::Initialize() {
    if (initialized) return;
    
    cpuFeatures = CPUFeatures::Detect();
    cpuFeatures.Print();
    
    initialized = true;
    printf("[KernelDispatcher] Initialized\n");
}

KernelType KernelDispatcher::Select(WeightType type, size_t rows, size_t cols) {
    if (!initialized) {
        Initialize();
    }
    
    // Dispatch based on weight type and CPU features
    switch (type) {
        case WEIGHT_Q4_K:
            if (cpuFeatures.hasAVX2) {
                return KernelType::Q4_K_M_GEMV_AVX2;
            }
            // Fall through to scalar if no AVX2
            break;
            
        case WEIGHT_Q4_0:
            if (cpuFeatures.hasAVX2) {
                return KernelType::Q4_0_GEMV_AVX2;
            }
            break;
            
        case WEIGHT_FP16:
            if (cpuFeatures.hasAVX2) {
                return KernelType::FP16_GEMV_AVX2;
            }
            break;
            
        case WEIGHT_FP32:
        default:
            if (cpuFeatures.hasAVX2) {
                return KernelType::FP32_GEMV_AVX2;
            }
            return KernelType::FP32_GEMV_SCALAR;
    }
    
    return KernelType::FP32_GEMV_SCALAR;
}

double KernelDispatcher::ExecuteLinear(
    int weightIdx,
    const float* input,
    const float* bias,
    float* output,
    size_t outDim,
    bool useParallel,
    Deep2Engine* engine
) {
    if (!initialized) {
        Initialize();
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // For now, route through engine's Linear methods
    // In production, this would dispatch to specific kernels
    if (engine) {
        if (useParallel) {
            engine->LinearParallel(weightIdx, input, bias, output, outDim);
        } else {
            engine->Linear(weightIdx, input, bias, output, outDim);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double elapsedMs = duration.count() / 1000.0;
    
    // Update dispatch record
    lastDispatch.executionTimeMs = elapsedMs;
    
    return elapsedMs;
}

bool KernelDispatcher::IsKernelAvailable(KernelType kernel) {
    if (!initialized) {
        Initialize();
    }
    
    switch (kernel) {
        case KernelType::Q4_K_M_GEMV_AVX2:
        case KernelType::Q4_0_GEMV_AVX2:
        case KernelType::FP16_GEMV_AVX2:
        case KernelType::FP32_GEMV_AVX2:
            return cpuFeatures.hasAVX2;
            
        case KernelType::Q4_K_M_GEMV_AVX512:
            return cpuFeatures.hasAVX512;
            
        case KernelType::FP32_GEMV_SCALAR:
            return true;  // Always available
            
        default:
            return false;
    }
}

// ============================================================================
// String Conversions
// ============================================================================
const char* KernelTypeToString(KernelType type) {
    switch (type) {
        case KernelType::Q4_K_M_GEMV_AVX2:   return "Q4_K_M_GEMV_AVX2";
        case KernelType::Q4_K_M_GEMV_AVX512: return "Q4_K_M_GEMV_AVX512";
        case KernelType::Q4_0_GEMV_AVX2:     return "Q4_0_GEMV_AVX2";
        case KernelType::FP16_GEMV_AVX2:     return "FP16_GEMV_AVX2";
        case KernelType::FP32_GEMV_AVX2:     return "FP32_GEMV_AVX2";
        case KernelType::FP32_GEMV_SCALAR:  return "FP32_GEMV_SCALAR";
        default:                             return "UNKNOWN";
    }
}

const char* WeightTypeToString(WeightType type) {
    switch (type) {
        case WEIGHT_FP32:  return "FP32";
        case WEIGHT_FP16:  return "FP16";
        case WEIGHT_Q4_0:  return "Q4_0";
        case WEIGHT_Q4_1:  return "Q4_1";
        case WEIGHT_Q5_0:  return "Q5_0";
        case WEIGHT_Q5_1:  return "Q5_1";
        case WEIGHT_Q8_0:  return "Q8_0";
        case WEIGHT_Q8_K:  return "Q8_K";
        case WEIGHT_Q2_K:  return "Q2_K";
        case WEIGHT_Q3_K:  return "Q3_K";
        case WEIGHT_Q4_K:  return "Q4_K_M";
        case WEIGHT_Q5_K:  return "Q5_K";
        case WEIGHT_Q6_K:  return "Q6_K";
        default:           return "UNKNOWN";
    }
}

} // namespace Deep2

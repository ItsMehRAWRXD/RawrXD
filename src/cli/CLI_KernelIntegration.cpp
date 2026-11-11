//==============================================================================
// CLI_KernelIntegration.cpp
// Implementation of CLI to Titan Kernel Integration layer
//
// Phase 7 Complete Integration
// Date: July 10, 2026
//==============================================================================

#include "CLI_KernelIntegration.hpp"
#include "d:/rawrxd/src/core/execution/Titan_KernelIntegration.cpp"
#include <cstdio>
#include <cstring>

namespace CLI {

bool TitanIntegration::initialized_ = false;

bool TitanIntegration::Initialize() {
    if (initialized_) return true;
    
    int result = Titan_InitializeKernelSystem();
    if (result != 0) {
        printf("ERROR: Titan_InitializeKernelSystem failed with code %d\n", result);
        return false;
    }
    
    initialized_ = true;
    return true;
}

bool TitanIntegration::IsInitialized() {
    return initialized_;
}

void TitanIntegration::Shutdown() {
    initialized_ = false;
}

bool TitanIntegration::IsKernelAvailable(uint64_t kernelName) {
    if (!initialized_) return false;
    return ::Titan_IsKernelAvailable(kernelName);
}

void TitanIntegration::PrintStatusReport() {
    printf("Titan Kernel Integration Status:\n");
    printf("  Initialized: %s\n", initialized_ ? "YES" : "NO");
    
    if (!initialized_) {
        printf("  Not initialized - call Initialize() first\n");
        return;
    }
    
    printf("\nKernel Availability:\n");
    printf("  RMSNorm:       %s\n", IsKernelAvailable(KERNEL_RMSNORM_F32) ? "YES" : "NO");
    printf("  LayerNorm:     %s\n", IsKernelAvailable(KERNEL_LAYERNORM_F32) ? "YES" : "NO");
    printf("  ResidualAdd:   %s\n", IsKernelAvailable(KERNEL_RESIDUAL_ADD) ? "YES" : "NO");
    printf("  RoPE:          %s\n", IsKernelAvailable(KERNEL_ROPE_APPLY) ? "YES" : "NO");
    printf("  Q4K Dequant:   %s\n", IsKernelAvailable(KERNEL_Q4K_DEQUANT) ? "YES" : "NO");
    printf("  Q4Q8 MatMul:   %s\n", IsKernelAvailable(KERNEL_Q4Q8_MATMUL) ? "YES" : "NO");
    printf("  FlashAttention:%s\n", IsKernelAvailable(KERNEL_FLASH_ATTENTION) ? "YES" : "NO");
    
    const char* version = Titan_GetKernelVersion();
    printf("\nKernel Version: %s\n", version ? version : "Unknown");
}

bool TitanIntegration::ExecuteRMSNorm(float* input, float* output, float* weight,
                                       size_t n_elements, float epsilon, float* execTimeMs) {
    if (!initialized_) return false;
    
    GPU_KERNEL_DESCRIPTOR desc = {};
    desc.kernelName = KERNEL_RMSNORM_F32;
    
    struct RMSNormParams {
        float* input;
        float* output;
        float* weight;
        size_t n_elements;
        float epsilon;
    } params = { input, output, weight, n_elements, epsilon };
    
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (execTimeMs) {
        *execTimeMs = desc.executionTimeUs / 1000.0f;
    }
    
    return result == 0;
}

bool TitanIntegration::ExecuteLayerNorm(float* input, float* output, float* gamma, float* beta,
                                         size_t n_elements, float epsilon, float* execTimeMs) {
    if (!initialized_) return false;
    
    GPU_KERNEL_DESCRIPTOR desc = {};
    desc.kernelName = KERNEL_LAYERNORM_F32;
    
    struct LayerNormParams {
        float* input;
        float* output;
        float* gamma;
        float* beta;
        size_t n_elements;
        float epsilon;
    } params = { input, output, gamma, beta, n_elements, epsilon };
    
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (execTimeMs) {
        *execTimeMs = desc.executionTimeUs / 1000.0f;
    }
    
    return result == 0;
}

bool TitanIntegration::ExecuteResidualAdd(float* input, float* residual, float* output,
                                           size_t n_elements, float* execTimeMs) {
    if (!initialized_) return false;
    
    GPU_KERNEL_DESCRIPTOR desc = {};
    desc.kernelName = KERNEL_RESIDUAL_ADD;
    
    struct ResidualAddParams {
        float* input;
        float* residual;
        float* output;
        size_t n_elements;
        float scale_factor;
    } params = { input, residual, output, n_elements, 1.0f };
    
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (execTimeMs) {
        *execTimeMs = desc.executionTimeUs / 1000.0f;
    }
    
    return result == 0;
}

} // namespace CLI

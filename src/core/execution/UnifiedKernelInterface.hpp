//==============================================================================
// UnifiedKernelInterface.hpp
// Bridges existing Sovereign kernels with new runtime
//
// This header provides a unified interface that:
// 1. Works with existing MSVC-built kernel libraries
// 2. Provides runtime kernel loading via LoadLibrary/GetProcAddress
// 3. Integrates with MemoryBridge for unified memory
// 4. Connects to Titan dispatch layer
//==============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

namespace Sovereign {

//==============================================================================
// Kernel Function Types (matching Sovereign_KernelDispatch.h)
//==============================================================================
using PFN_RMSNorm_F32 = int (*)(float* input, float* output, float* weight,
                                 size_t n_elements, float epsilon);
using PFN_LayerNorm_F32 = int (*)(float* input, float* output,
                                    float* gamma, float* beta,
                                    size_t n_elements, float epsilon);
using PFN_RoPE_Apply_F32 = int (*)(float* tensor, float* freq_cache,
                                     size_t seq_len, size_t head_dim, 
                                     size_t num_heads);
using PFN_ResidualAdd_F32 = int (*)(float* input, float* residual, 
                                      float* output, size_t n_elements);
using PFN_Q4K_Dequant_Tensor = int (*)(const void* tensor_data, float* output,
                                          size_t num_elements, const void* tensor_info);
using PFN_Q4Q8_MatMul_Intrinsics = int (*)(const void* A, const void* B, float* C,
                                            size_t m, size_t n, size_t k);
using PFN_FlashAttentionV2_Intrinsics = int (*)(float* Q, float* K, float* V, float* output,
                                                  size_t seq_len, size_t head_dim);

//==============================================================================
// Unified Kernel Interface
// Loads kernel libraries at runtime to avoid linker issues
//==============================================================================
class UnifiedKernelInterface {
public:
    UnifiedKernelInterface();
    ~UnifiedKernelInterface();

    // Initialize - loads all kernel libraries
    bool Initialize();
    
    // Check if interface is ready
    bool IsReady() const { return initialized_; }
    
    // Get kernel availability
    bool HasRMSNorm() const { return rms_norm_f32_ != nullptr; }
    bool HasLayerNorm() const { return layer_norm_f32_ != nullptr; }
    bool HasRoPE() const { return rope_apply_f32_ != nullptr; }
    bool HasResidualAdd() const { return residual_add_f32_ != nullptr; }
    bool HasQ4KDequant() const { return q4k_dequant_tensor_ != nullptr; }
    bool HasQ4Q8MatMul() const { return q4q8_matmul_intrinsics_ != nullptr; }
    bool HasFlashAttention() const { return flash_attention_v2_intrinsics_ != nullptr; }
    
    // Kernel execution wrappers
    bool RMSNorm(float* input, float* output, float* weight, size_t n, float epsilon);
    bool LayerNorm(float* input, float* output, float* gamma, float* beta, 
                   size_t n, float epsilon);
    bool RoPE(float* tensor, float* freq_cache, size_t seq_len, size_t head_dim, size_t num_heads);
    bool ResidualAdd(float* input, float* residual, float* output, size_t n);
    bool Q4KDequant(const void* tensor_data, float* output, size_t num_elements, 
                    const void* tensor_info);
    bool Q4Q8MatMul(const void* A, const void* B, float* C, size_t m, size_t n, size_t k);
    bool FlashAttentionV2(float* Q, float* K, float* V, float* output,
                          size_t seq_len, size_t head_dim);
    
    // Get loaded kernel count
    int GetLoadedKernelCount() const;
    
    // Get status string
    std::string GetStatus() const;

private:
    bool initialized_;
    
    // Library handles
    HMODULE hLegacyKernels_;
    HMODULE hIntrinsics_;
    HMODULE hRMSNorm_;
    HMODULE hResidualAdd_;
    HMODULE hRoPE_;
    HMODULE hLayerNorm_;
    HMODULE hQ4KDequant_;
    
    // Function pointers
    PFN_RMSNorm_F32 rms_norm_f32_;
    PFN_LayerNorm_F32 layer_norm_f32_;
    PFN_RoPE_Apply_F32 rope_apply_f32_;
    PFN_ResidualAdd_F32 residual_add_f32_;
    PFN_Q4K_Dequant_Tensor q4k_dequant_tensor_;
    PFN_Q4Q8_MatMul_Intrinsics q4q8_matmul_intrinsics_;
    PFN_FlashAttentionV2_Intrinsics flash_attention_v2_intrinsics_;
    
    // Helper to load a library
    HMODULE LoadKernelLibrary(const char* name);
    
    // Helper to get function pointer
    template<typename T>
    T GetProc(HMODULE hMod, const char* name) {
        if (!hMod) return nullptr;
        return reinterpret_cast<T>(GetProcAddress(hMod, name));
    }
};

// Singleton access
UnifiedKernelInterface& GetKernelInterface();

} // namespace Sovereign

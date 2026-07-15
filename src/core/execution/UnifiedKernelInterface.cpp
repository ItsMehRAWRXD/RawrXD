//==============================================================================
// UnifiedKernelInterface.cpp
// Runtime kernel loading implementation
//==============================================================================

#include "UnifiedKernelInterface.hpp"
#include <sstream>
#include <iomanip>

namespace Sovereign {

//==============================================================================
// Constructor / Destructor
//==============================================================================
UnifiedKernelInterface::UnifiedKernelInterface()
    : initialized_(false)
    , hLegacyKernels_(nullptr)
    , hIntrinsics_(nullptr)
    , hRMSNorm_(nullptr)
    , hResidualAdd_(nullptr)
    , hRoPE_(nullptr)
    , hLayerNorm_(nullptr)
    , hQ4KDequant_(nullptr)
    , rms_norm_f32_(nullptr)
    , layer_norm_f32_(nullptr)
    , rope_apply_f32_(nullptr)
    , residual_add_f32_(nullptr)
    , q4k_dequant_tensor_(nullptr)
    , q4q8_matmul_intrinsics_(nullptr)
    , flash_attention_v2_intrinsics_(nullptr)
{
}

UnifiedKernelInterface::~UnifiedKernelInterface() {
    if (hLegacyKernels_) FreeLibrary(hLegacyKernels_);
    if (hIntrinsics_) FreeLibrary(hIntrinsics_);
    if (hRMSNorm_) FreeLibrary(hRMSNorm_);
    if (hResidualAdd_) FreeLibrary(hResidualAdd_);
    if (hRoPE_) FreeLibrary(hRoPE_);
    if (hLayerNorm_) FreeLibrary(hLayerNorm_);
    if (hQ4KDequant_) FreeLibrary(hQ4KDequant_);
}

//==============================================================================
// Library Loading
//==============================================================================
HMODULE UnifiedKernelInterface::LoadKernelLibrary(const char* name) {
    // Try multiple paths
    const char* paths[] = {
        "d:\\src\\asm\\",
        ".\\",
        "..\\..\\..\\src\\asm\\",
        ""
    };
    
    char fullPath[MAX_PATH];
    HMODULE hMod = nullptr;
    
    for (const char* base : paths) {
        snprintf(fullPath, sizeof(fullPath), "%s%s.dll", base, name);
        hMod = LoadLibraryA(fullPath);
        if (hMod) {
            return hMod;
        }
    }
    
    return nullptr;
}

//==============================================================================
// Initialization
//==============================================================================
bool UnifiedKernelInterface::Initialize() {
    if (initialized_) return true;
    
    // Load libraries
    hLegacyKernels_ = LoadKernelLibrary("Sovereign_Legacy_Kernels");
    hIntrinsics_ = LoadKernelLibrary("Sovereign_Intrinsics");
    hRMSNorm_ = LoadKernelLibrary("Sovereign_RMSNorm");
    hResidualAdd_ = LoadKernelLibrary("Sovereign_ResidualAdd");
    hRoPE_ = LoadKernelLibrary("Sovereign_RoPE");
    hLayerNorm_ = LoadKernelLibrary("Sovereign_LayerNorm");
    hQ4KDequant_ = LoadKernelLibrary("Sovereign_Q4K_Dequant");
    
    // Load function pointers from legacy kernels
    if (hLegacyKernels_) {
        // Legacy kernels may have different naming
        rms_norm_f32_ = GetProc<PFN_RMSNorm_F32>(hLegacyKernels_, "rms_norm_f32");
        layer_norm_f32_ = GetProc<PFN_LayerNorm_F32>(hLegacyKernels_, "layer_norm_f32");
        rope_apply_f32_ = GetProc<PFN_RoPE_Apply_F32>(hLegacyKernels_, "rope_apply_f32");
        residual_add_f32_ = GetProc<PFN_ResidualAdd_F32>(hLegacyKernels_, "residual_add_f32");
    }
    
    // Load function pointers from intrinsics library
    if (hIntrinsics_) {
        q4q8_matmul_intrinsics_ = GetProc<PFN_Q4Q8_MatMul_Intrinsics>(
            hIntrinsics_, "q4q8_matmul_intrinsics");
        flash_attention_v2_intrinsics_ = GetProc<PFN_FlashAttentionV2_Intrinsics>(
            hIntrinsics_, "flash_attention_v2_intrinsics");
    }
    
    // Load from individual libraries (these may have different exports)
    if (hRMSNorm_ && !rms_norm_f32_) {
        rms_norm_f32_ = GetProc<PFN_RMSNorm_F32>(hRMSNorm_, "rms_norm_f32");
    }
    if (hLayerNorm_ && !layer_norm_f32_) {
        layer_norm_f32_ = GetProc<PFN_LayerNorm_F32>(hLayerNorm_, "layer_norm_f32");
    }
    if (hRoPE_ && !rope_apply_f32_) {
        rope_apply_f32_ = GetProc<PFN_RoPE_Apply_F32>(hRoPE_, "rope_apply_f32");
    }
    if (hResidualAdd_ && !residual_add_f32_) {
        residual_add_f32_ = GetProc<PFN_ResidualAdd_F32>(hResidualAdd_, "residual_add_f32");
    }
    if (hQ4KDequant_) {
        q4k_dequant_tensor_ = GetProc<PFN_Q4K_Dequant_Tensor>(hQ4KDequant_, "q4k_dequant_tensor");
    }
    
    initialized_ = true;
    return GetLoadedKernelCount() > 0;
}

//==============================================================================
// Kernel Execution Wrappers
//==============================================================================
bool UnifiedKernelInterface::RMSNorm(float* input, float* output, float* weight, 
                                      size_t n, float epsilon) {
    if (!rms_norm_f32_) return false;
    int result = rms_norm_f32_(input, output, weight, n, epsilon);
    return result == 0;
}

bool UnifiedKernelInterface::LayerNorm(float* input, float* output, 
                                        float* gamma, float* beta,
                                        size_t n, float epsilon) {
    if (!layer_norm_f32_) return false;
    int result = layer_norm_f32_(input, output, gamma, beta, n, epsilon);
    return result == 0;
}

bool UnifiedKernelInterface::RoPE(float* tensor, float* freq_cache, 
                                   size_t seq_len, size_t head_dim, size_t num_heads) {
    if (!rope_apply_f32_) return false;
    int result = rope_apply_f32_(tensor, freq_cache, seq_len, head_dim, num_heads);
    return result == 0;
}

bool UnifiedKernelInterface::ResidualAdd(float* input, float* residual, 
                                          float* output, size_t n) {
    if (!residual_add_f32_) return false;
    int result = residual_add_f32_(input, residual, output, n);
    return result == 0;
}

bool UnifiedKernelInterface::Q4KDequant(const void* tensor_data, float* output, 
                                         size_t num_elements, const void* tensor_info) {
    if (!q4k_dequant_tensor_) return false;
    int result = q4k_dequant_tensor_(tensor_data, output, num_elements, tensor_info);
    return result == 0;
}

bool UnifiedKernelInterface::Q4Q8MatMul(const void* A, const void* B, float* C,
                                         size_t m, size_t n, size_t k) {
    if (!q4q8_matmul_intrinsics_) return false;
    int result = q4q8_matmul_intrinsics_(A, B, C, m, n, k);
    return result == 0;
}

bool UnifiedKernelInterface::FlashAttentionV2(float* Q, float* K, float* V, float* output,
                                               size_t seq_len, size_t head_dim) {
    if (!flash_attention_v2_intrinsics_) return false;
    int result = flash_attention_v2_intrinsics_(Q, K, V, output, seq_len, head_dim);
    return result == 0;
}

//==============================================================================
// Status
//==============================================================================
int UnifiedKernelInterface::GetLoadedKernelCount() const {
    int count = 0;
    if (rms_norm_f32_) count++;
    if (layer_norm_f32_) count++;
    if (rope_apply_f32_) count++;
    if (residual_add_f32_) count++;
    if (q4k_dequant_tensor_) count++;
    if (q4q8_matmul_intrinsics_) count++;
    if (flash_attention_v2_intrinsics_) count++;
    return count;
}

std::string UnifiedKernelInterface::GetStatus() const {
    std::stringstream ss;
    ss << "=== Unified Kernel Interface Status ===\n";
    ss << "Libraries loaded:\n";
    ss << "  Legacy Kernels: " << (hLegacyKernels_ ? "YES" : "NO") << "\n";
    ss << "  Intrinsics: " << (hIntrinsics_ ? "YES" : "NO") << "\n";
    ss << "  RMSNorm: " << (hRMSNorm_ ? "YES" : "NO") << "\n";
    ss << "  ResidualAdd: " << (hResidualAdd_ ? "YES" : "NO") << "\n";
    ss << "  RoPE: " << (hRoPE_ ? "YES" : "NO") << "\n";
    ss << "  LayerNorm: " << (hLayerNorm_ ? "YES" : "NO") << "\n";
    ss << "  Q4KDequant: " << (hQ4KDequant_ ? "YES" : "NO") << "\n";
    ss << "\nKernels available:\n";
    ss << "  RMSNorm: " << (rms_norm_f32_ ? "YES" : "NO") << "\n";
    ss << "  LayerNorm: " << (layer_norm_f32_ ? "YES" : "NO") << "\n";
    ss << "  RoPE: " << (rope_apply_f32_ ? "YES" : "NO") << "\n";
    ss << "  ResidualAdd: " << (residual_add_f32_ ? "YES" : "NO") << "\n";
    ss << "  Q4KDequant: " << (q4k_dequant_tensor_ ? "YES" : "NO") << "\n";
    ss << "  Q4Q8MatMul: " << (q4q8_matmul_intrinsics_ ? "YES" : "NO") << "\n";
    ss << "  FlashAttentionV2: " << (flash_attention_v2_intrinsics_ ? "YES" : "NO") << "\n";
    ss << "\nTotal: " << GetLoadedKernelCount() << "/7 kernels ready\n";
    return ss.str();
}

//==============================================================================
// Singleton
//==============================================================================
UnifiedKernelInterface& GetKernelInterface() {
    static UnifiedKernelInterface instance;
    return instance;
}

} // namespace Sovereign

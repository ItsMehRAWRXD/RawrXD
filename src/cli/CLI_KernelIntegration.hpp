//==============================================================================
// CLI_KernelIntegration.hpp
// Header for CLI to access Titan Kernel Integration layer
//
// Phase 7 Complete Integration
// Date: July 10, 2026
//==============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// Forward declarations for Titan integration
extern "C" {

// Titan kernel descriptor (matches ASM layout)
struct GPU_KERNEL_DESCRIPTOR;
struct GPU_COPY_OPERATION;

// Initialize Titan kernel system
int Titan_InitializeKernelSystem(void);

// Execute compute kernel
int Titan_ExecuteComputeKernel(GPU_KERNEL_DESCRIPTOR* desc, void* resultBuffer, size_t resultSize);

// Perform copy operation
int Titan_PerformCopy(GPU_COPY_OPERATION* op, uint32_t flags);

// Get kernel version
const char* Titan_GetKernelVersion(void);

// Check if kernel is available
bool Titan_IsKernelAvailable(uint64_t kernelName);

// Get kernel stats
bool Titan_GetKernelStats(uint64_t kernelName, uint64_t* avgTimeUs, uint64_t* totalCalls);

} // extern "C"

namespace CLI {

//==============================================================================
// Kernel Type Identifiers (64-bit hashes)
//==============================================================================
constexpr uint64_t KERNEL_RMSNORM_F32          = 0x524D534E4F524D00ULL;
constexpr uint64_t KERNEL_LAYERNORM_F32        = 0x4C415945524E4F00ULL;
constexpr uint64_t KERNEL_ROPE_APPLY           = 0x524F504550504C00ULL;
constexpr uint64_t KERNEL_RESIDUAL_ADD         = 0x5245534944554100ULL;
constexpr uint64_t KERNEL_Q4K_DEQUANT          = 0x51344B44455100ULL;
constexpr uint64_t KERNEL_Q4Q8_MATMUL          = 0x513451384D4D00ULL;
constexpr uint64_t KERNEL_FLASH_ATTENTION      = 0x464C415348415400ULL;
constexpr uint64_t KERNEL_MATMUL_INTRINSICS    = 0x4D4D494E545200ULL;
constexpr uint64_t KERNEL_FLASHATTN_INTRINSICS = 0x4641494E545200ULL;

//==============================================================================
// Titan Integration Wrapper
//==============================================================================
class TitanIntegration {
public:
    static bool Initialize();
    static bool IsInitialized();
    static void Shutdown();
    
    // Check kernel availability
    static bool IsKernelAvailable(uint64_t kernelName);
    
    // Get status report
    static void PrintStatusReport();
    
    // Execute kernels
    static bool ExecuteRMSNorm(float* input, float* output, float* weight, 
                                size_t n_elements, float epsilon, float* execTimeMs);
    static bool ExecuteLayerNorm(float* input, float* output, float* gamma, float* beta,
                                  size_t n_elements, float epsilon, float* execTimeMs);
    static bool ExecuteResidualAdd(float* input, float* residual, float* output,
                                    size_t n_elements, float* execTimeMs);
    
private:
    static bool initialized_;
};

} // namespace CLI

//==============================================================================
// Titan_KernelIntegration.hpp
// Complete integration layer for Titan with Sovereign kernels
//
// This is the main integration point that:
// 1. Initializes UnifiedKernelInterface
// 2. Sets up MemoryBridge
// 3. Provides Titan-compatible kernel dispatch
// 4. Integrates with CLI
//==============================================================================

#pragma once

#include "UnifiedKernelInterface.hpp"
#include "MemoryBridge.hpp"
#include <string>
#include <functional>
#include <vector>

namespace Titan {

//==============================================================================
// Titan Kernel Types (matching Titan's expectations)
//==============================================================================
enum class KernelType {
    RMS_NORM,
    LAYER_NORM,
    ROPE,
    RESIDUAL_ADD,
    Q4K_DEQUANT,
    Q4Q8_MATMUL,
    FLASH_ATTENTION_V2,
    COUNT
};

//==============================================================================
// Kernel Execution Context
// Passed to all kernel executions
//==============================================================================
struct KernelContext {
    // Input/output buffers
    void* input;
    void* output;
    void* weights;
    void* bias;
    
    // Dimensions
    size_t batchSize;
    size_t seqLen;
    size_t embedDim;
    size_t numHeads;
    size_t headDim;
    
    // Parameters
    float epsilon;
    float scale;
    
    // Memory bridge reference
    Sovereign::MemoryBridge* memoryBridge;
    
    KernelContext() 
        : input(nullptr), output(nullptr), weights(nullptr), bias(nullptr)
        , batchSize(1), seqLen(1), embedDim(4096), numHeads(32), headDim(128)
        , epsilon(1e-5f), scale(1.0f)
        , memoryBridge(nullptr)
    {}
};

//==============================================================================
// Kernel Result
//==============================================================================
struct KernelResult {
    bool success;
    float executionTimeMs;
    const char* errorMessage;
    
    KernelResult() : success(false), executionTimeMs(0.0f), errorMessage(nullptr) {}
    explicit KernelResult(bool ok) : success(ok), executionTimeMs(0.0f), errorMessage(nullptr) {}
};

//==============================================================================
// Titan Kernel Integration
// Main class that bridges Titan with Sovereign kernels
//==============================================================================
class TitanKernelIntegration {
public:
    TitanKernelIntegration();
    ~TitanKernelIntegration();
    
    // Initialize the integration
    // Must be called before any kernel execution
    bool Initialize();
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get kernel availability
    bool IsKernelAvailable(KernelType type) const;
    
    // Execute kernels
    KernelResult ExecuteRMSNorm(KernelContext& ctx);
    KernelResult ExecuteLayerNorm(KernelContext& ctx);
    KernelResult ExecuteRoPE(KernelContext& ctx);
    KernelResult ExecuteResidualAdd(KernelContext& ctx);
    KernelResult ExecuteQ4KDequant(KernelContext& ctx);
    KernelResult ExecuteQ4Q8MatMul(KernelContext& ctx);
    KernelResult ExecuteFlashAttentionV2(KernelContext& ctx);
    
    // Generic execute by type
    KernelResult Execute(KernelType type, KernelContext& ctx);
    
    // Get kernel name
    const char* GetKernelName(KernelType type) const;
    
    // Get status report
    std::string GetStatusReport() const;
    
    // Get number of available kernels
    int GetAvailableKernelCount() const;
    
    // Memory bridge access
    Sovereign::MemoryBridge* GetMemoryBridge() { return &memoryBridge_; }
    
    // Singleton access
    static TitanKernelIntegration& GetInstance();

private:
    bool initialized_;
    Sovereign::UnifiedKernelInterface kernelInterface_;
    Sovereign::MemoryBridge memoryBridge_;
    
    // Kernel availability cache
    bool kernelAvailable_[static_cast<int>(KernelType::COUNT)];
    
    void UpdateKernelAvailability();
};

//==============================================================================
// C API for CLI Integration
//==============================================================================
extern "C" {
    // Initialize Titan kernel integration
    __declspec(dllexport) bool Titan_Kernels_Initialize();
    
    // Check if kernel is available
    __declspec(dllexport) bool Titan_Kernel_IsAvailable(int kernelType);
    
    // Get status string (caller must free with Titan_Kernels_FreeString)
    __declspec(dllexport) char* Titan_Kernels_GetStatus();
    
    // Free string returned by Titan_Kernels_GetStatus
    __declspec(dllexport) void Titan_Kernels_FreeString(char* str);
    
    // Get available kernel count
    __declspec(dllexport) int Titan_Kernels_GetCount();
    
    // Execute RMS norm (simple interface for testing)
    __declspec(dllexport) bool Titan_Kernel_ExecuteRMSNorm(
        float* input, float* output, float* weight,
        int n_elements, float epsilon);
}

} // namespace Titan

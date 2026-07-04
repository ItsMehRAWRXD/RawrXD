// ============================================================================
// RawrXD Hotpatch Model Manager - C++ Integration Layer
// ============================================================================
// Phase 4A: Synchronous Block with Epoch-RCU
// - Loads GGUF models via llama.cpp C API
// - Manages model lifetime with 3-slot epoch rotation
// - Provides cleanup callback for retired models
// ============================================================================

#pragma once

#include <windows.h>
#include <stdint.h>
#include <string>
#include <atomic>
#include <mutex>
#include <queue>
#include <vector>

// Include TensorInfo from interfaces
#include "../RawrXD_Interfaces.h"

// Forward declaration for llama.cpp (if available)
struct llama_model;
struct llama_context;

// Forward declaration for Vulkan
#ifndef RAWRXD_NO_VULKAN
namespace RawrXD {
    struct VulkanBuffer;
}
#endif

namespace RawrXD {

// ============================================================================
// GPU Tensor Upload Status
// ============================================================================
// Uses TensorInfo from RawrXD_Interfaces.h
// Additional GPU-specific metadata for upload tracking

// ============================================================================
// Model Descriptor - Wraps llama.cpp state + GPU resources
// ============================================================================
struct alignas(64) ModelDescriptor {
    // llama.cpp handles (opaque to router)
    llama_model*    model           = nullptr;
    llama_context*  ctx             = nullptr;
    
    // GPU resources - Phase 3: Vulkan tensor storage
    #ifndef RAWRXD_NO_VULKAN
    std::vector<VulkanBuffer*> tensorBuffers;  // Per-tensor GPU buffers
    VulkanBuffer*   unifiedBuffer   = nullptr;   // Single large buffer (optional)
    #endif
    void*           gpuBuffer       = nullptr; // Legacy/generic pointer
    uint64_t        gpuFence        = 0;         // VkFence or hipEvent_t
    
    // Tensor metadata
    std::vector<TensorInfo> tensors;
    size_t          totalTensorBytes = 0;
    
    // Metadata
    char            modelPath[512]  = {0};
    uint64_t        loadedEpoch     = 0;
    uint64_t        retiredEpoch    = 0;
    size_t          vramBytes       = 0;
    
    // State
    std::atomic<bool> isValid       {false};
    std::atomic<bool> isRetired      {false};
    std::atomic<bool> gpuUploadComplete {false}; // Phase 3: GPU upload status
    
    // Constructor/Destructor
    ModelDescriptor() = default;
    ~ModelDescriptor();
    
    // Disable copy (models are heavy resources)
    ModelDescriptor(const ModelDescriptor&) = delete;
    ModelDescriptor& operator=(const ModelDescriptor&) = delete;
};

// ============================================================================
// Hotpatch Model Manager
// ============================================================================
class HotpatchModelManager {
public:
    // Singleton access
    static HotpatchModelManager& Instance();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Model loading (called from pipe_server_callback)
    // Returns opaque handle (ModelDescriptor*) for router
    uint64_t LoadModel(const char* modelPath);
    
    // Model unloading (called from router's retired slot cleanup)
    void UnloadModel(uint64_t modelHandle);
    
    // Get current active model
    ModelDescriptor* GetActiveModel();
    
    // Phase 3: GPU tensor upload (public for C API access)
    bool UploadTensorsToGPU(ModelDescriptor* desc);
    
    // Statistics
    struct Stats {
        uint64_t modelsLoaded = 0;
        uint64_t modelsUnloaded = 0;
        uint64_t hotpatchesCompleted = 0;
        uint64_t vramUsedBytes = 0;
    };
    Stats GetStats() const;
    
private:
    HotpatchModelManager() = default;
    ~HotpatchModelManager() = default;
    
    // Internal helpers
    ModelDescriptor* LoadGGUF(const char* path);
    void FreeModelResources(ModelDescriptor* desc);
    
    // Phase 3: GPU tensor upload internals
    bool UploadTensorUnified(ModelDescriptor* desc);  // Single buffer approach
    bool UploadTensorPerTensor(ModelDescriptor* desc); // Per-tensor approach
    
    // Thread-safe handle management
    mutable std::mutex m_mutex;
    std::queue<ModelDescriptor*> m_retiredQueue;  // Models waiting for cleanup
    
    // Active model tracking
    std::atomic<ModelDescriptor*> m_activeModel{nullptr};
    
    // Statistics
    Stats m_stats;
};

// ============================================================================
// C API for MASM64 Router Integration
// ============================================================================

extern "C" {
    // Called by router when a slot is retired
    // Input: rcx = model descriptor handle (ModelDescriptor*)
    void RawrXD_HotpatchModelCleanup(uint64_t modelHandle);
    
    // Called by pipe_server_callback to load a model from path
    // Input: rcx = model path string
    // Output: rax = model handle (or 0 on failure)
    uint64_t RawrXD_HotpatchLoadModel(const char* modelPath);
    
    // Get current active model handle
    // Output: rax = model handle (or 0 if none)
    uint64_t RawrXD_HotpatchGetActiveModel();
    
    // Initialize model manager
    // Output: rax = 0 (success), 1 (failure)
    uint64_t RawrXD_HotpatchInitManager();
    
    // Shutdown and cleanup all models
    void RawrXD_HotpatchShutdownManager();
}

} // namespace RawrXD

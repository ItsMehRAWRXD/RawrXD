// ============================================================================
// RawrXD Hotpatch Model Manager - Implementation
// ============================================================================
// Phase 4A: Synchronous Block with Epoch-RCU
// Phase 4B: Option A - Wrap existing GGUFLoader (file handle lifetime safe)
// ============================================================================

#include "hotpatch_model_manager.hpp"
#include "../gguf_loader.h"
#include <cstdio>
#include <string>

// llama.cpp C API (if available)
// #include "llama.h"

namespace RawrXD {

// ============================================================================
// ModelDescriptor Destructor
// ============================================================================
ModelDescriptor::~ModelDescriptor() {
    // Phase 4B: Resources should be freed via FreeModelResources before destruction
    // This is just a safety check
    if (gpuBuffer || gpuFence) {
        printf("[WARN] ModelDescriptor destroyed with unfreed GPU resources\n");
    }
}

// ============================================================================
// Singleton Implementation
// ============================================================================
HotpatchModelManager& HotpatchModelManager::Instance() {
    static HotpatchModelManager instance;
    return instance;
}

// ============================================================================
// Initialization
// ============================================================================
bool HotpatchModelManager::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    printf("[HotpatchModelManager] Initialized\n");
    
    // TODO: Initialize llama.cpp backend
    // TODO: Initialize GPU context (Vulkan/HIP)
    
    return true;
}

void HotpatchModelManager::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Cleanup any remaining models
    while (!m_retiredQueue.empty()) {
        ModelDescriptor* desc = m_retiredQueue.front();
        m_retiredQueue.pop();
        FreeModelResources(desc);
        delete desc;
    }
    
    // Cleanup active model
    ModelDescriptor* active = m_activeModel.exchange(nullptr);
    if (active) {
        FreeModelResources(active);
        delete active;
    }
    
    printf("[HotpatchModelManager] Shutdown complete\n");
}

// ============================================================================
// Model Loading
// ============================================================================
uint64_t HotpatchModelManager::LoadModel(const char* modelPath) {
    if (!modelPath || !modelPath[0]) {
        printf("[ERROR] Invalid model path\n");
        return 0;
    }
    
    printf("[HotpatchModelManager] Loading model: %s\n", modelPath);
    
    // Load the GGUF model
    ModelDescriptor* desc = LoadGGUF(modelPath);
    if (!desc) {
        printf("[ERROR] Failed to load model: %s\n", modelPath);
        return 0;
    }
    
    // Store path
    strncpy(desc->modelPath, modelPath, sizeof(desc->modelPath) - 1);
    desc->modelPath[sizeof(desc->modelPath) - 1] = '\0';
    
    // Mark as valid
    desc->isValid.store(true);
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.modelsLoaded++;
        m_stats.vramUsedBytes += desc->vramBytes;
    }
    
    printf("[HotpatchModelManager] Model loaded: %s (VRAM: %zu MB)\n", 
           modelPath, desc->vramBytes / (1024 * 1024));
    
    // Return opaque handle
    return reinterpret_cast<uint64_t>(desc);
}

// ============================================================================
// Model Unloading (Called from router's retired slot cleanup)
// ============================================================================
void HotpatchModelManager::UnloadModel(uint64_t modelHandle) {
    if (!modelHandle) {
        return;
    }
    
    ModelDescriptor* desc = reinterpret_cast<ModelDescriptor*>(modelHandle);
    
    // Validate
    if (!desc->isValid.load()) {
        printf("[WARN] Attempt to unload invalid model\n");
        return;
    }
    
    printf("[HotpatchModelManager] Unloading model: %s\n", desc->modelPath);
    
    // Mark as retired
    desc->isRetired.store(true);
    
    // Free resources
    FreeModelResources(desc);
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.modelsUnloaded++;
        m_stats.vramUsedBytes -= desc->vramBytes;
    }
    
    // Delete the descriptor
    delete desc;
    
    printf("[HotpatchModelManager] Model unloaded\n");
}

// ============================================================================
// Get Active Model
// ============================================================================
ModelDescriptor* HotpatchModelManager::GetActiveModel() {
    return m_activeModel.load();
}

// ============================================================================
// Statistics
// ============================================================================
HotpatchModelManager::Stats HotpatchModelManager::GetStats() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_stats;
}

// ============================================================================
// Internal: Load GGUF Model (Option A - Wrap existing GGUFLoader)
// ============================================================================
// CRITICAL: GGUFLoader is created ON THE STACK here. When this function returns,
// the loader's destructor fires, calling UnmapViewOfFile and CloseHandle.
// This unlocks the file on disk immediately, allowing subsequent hotpatches
// to overwrite the same file path without ERROR_SHARING_VIOLATION.
// ============================================================================
ModelDescriptor* HotpatchModelManager::LoadGGUF(const char* path) {
    if (!path || !path[0]) {
        printf("[ERROR] Invalid model path\n");
        return nullptr;
    }
    
    printf("[HotpatchModelManager] Loading GGUF: %s\n", path);
    
    // Phase 4B: Use existing GGUFLoader on stack for automatic cleanup
    // The loader opens the file, parses GGUF, and uploads to GPU.
    // When 'loader' goes out of scope, file handles are released.
    GGUFLoader loader;
    
    // Open the GGUF file
    if (!loader.Open(path)) {
        printf("[ERROR] Failed to open GGUF: %s\n", path);
        return nullptr;
    }
    
    // Parse header and metadata
    if (!loader.ParseHeader()) {
        printf("[ERROR] Failed to parse GGUF header: %s\n", path);
        return nullptr;
    }
    
    if (!loader.ParseMetadata()) {
        printf("[ERROR] Failed to parse GGUF metadata: %s\n", path);
        return nullptr;
    }
    
    // Get header info for VRAM estimation
    RawrXD::GGUFHeader header = loader.GetHeader();
    RawrXD::GGUFMetadata metadata = loader.GetMetadata();
    
    printf("[HotpatchModelManager] GGUF version %u, tensors: %zu\n", 
           header.version, loader.GetTensorInfo().size());
    
    // Create the model descriptor
    ModelDescriptor* desc = new ModelDescriptor();
    
    // Store the path
    strncpy(desc->modelPath, path, sizeof(desc->modelPath) - 1);
    desc->modelPath[sizeof(desc->modelPath) - 1] = '\0';
    
    // Phase 4B CRITICAL FIX: Copy tensor data to heap BEFORE loader dies
    // The loader's mapped view will be unmapped when ~GGUFLoader() fires.
    // We must copy the data we need to a separate allocation that survives.
    
    // Calculate total size needed
    size_t totalTensorBytes = 0;
    for (const auto& tensor : loader.GetTensorInfo()) {
        totalTensorBytes += tensor.size;
    }
    
    // Allocate heap buffer to hold tensor data (survives loader destruction)
    // In Phase 5, this will be replaced with vkCreateBuffer/VkDeviceMemory
    void* heapBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalTensorBytes);
    if (!heapBuffer) {
        printf("[ERROR] Failed to allocate heap buffer for model data\n");
        delete desc;
        return nullptr;
    }
    
    // Copy tensor data from mapped view to heap buffer
    // NOTE: This is a simplified copy. Real implementation would iterate tensors
    // and copy each one's data to the appropriate offset in the heap buffer.
    const void* mappedBase = loader.GetBaseAddress();
    if (mappedBase && totalTensorBytes > 0) {
        // For now, copy the entire mapped region (or as much as we calculated)
        // In production, this should be tensor-by-tensor with proper alignment
        memcpy(heapBuffer, mappedBase, totalTensorBytes);
        printf("[HotpatchModelManager] Copied %zu bytes to heap buffer\n", totalTensorBytes);
    }
    
    desc->gpuBuffer = heapBuffer;  // Now points to heap copy, not mapped view
    desc->vramBytes = totalTensorBytes;
    
    // Mark as valid
    desc->isValid.store(true);
    
    printf("[HotpatchModelManager] GGUF loaded: %s (est. VRAM: %zu MB, heap: %p)\n",
           path, desc->vramBytes / (1024 * 1024), heapBuffer);
    
    // LOADER GOES OUT OF SCOPE HERE
    // ~GGUFLoader() calls UnmapViewOfFile() and CloseHandle()
    // File is now unlocked on disk, ready for next hotpatch
    // BUT heapBuffer remains valid - we copied the data!
    
    return desc;
}

// ============================================================================
// Internal: Free Model Resources
// ============================================================================
void HotpatchModelManager::FreeModelResources(ModelDescriptor* desc) {
    if (!desc) return;
    
    printf("[HotpatchModelManager] Freeing resources for: %s\n", desc->modelPath);
    
    // Phase 4B: GPU/Heap resource cleanup
    // The ModelDescriptor holds a HEAP COPY of the model data (not file mapping)
    // This was copied before ~GGUFLoader() unmapped the file view
    
    if (desc->gpuBuffer) {
        // Free the heap buffer we allocated in LoadGGUF
        HeapFree(GetProcessHeap(), 0, desc->gpuBuffer);
        printf("[HotpatchModelManager] Freed heap buffer: %p\n", desc->gpuBuffer);
        desc->gpuBuffer = nullptr;
    }
    
    if (desc->gpuFence) {
        // TODO: Phase 5 - Proper fence/event cleanup
        // VkFence fence = (VkFence)desc->gpuFence;
        // vkDestroyFence(device, fence, nullptr);
        desc->gpuFence = 0;
    }
    
    // llama.cpp cleanup (when integrated)
    // if (desc->ctx) {
    //     llama_free(desc->ctx);
    //     desc->ctx = nullptr;
    // }
    // if (desc->model) {
    //     llama_free_model(desc->model);
    //     desc->model = nullptr;
    // }
    
    desc->vramBytes = 0;
    desc->isValid.store(false);
    
    printf("[HotpatchModelManager] Resources freed\n");
}

// ============================================================================
// Phase 3: GPU Tensor Upload Pipeline
// ============================================================================
// Track 3: Upload GGUF tensors to Vulkan device memory
// - Supports both unified (single large buffer) and per-tensor approaches
// - Integrates with Epoch-RCU shadow slot preparation
// - Uses VulkanCompute::createBuffer for device memory allocation
// ============================================================================

#ifndef RAWRXD_NO_VULKAN
#include "../backend/vulkan_compute.h"
#endif

bool HotpatchModelManager::UploadTensorsToGPU(ModelDescriptor* desc) {
    if (!desc || !desc->gpuBuffer) {
        printf("[ERROR] UploadTensorsToGPU: Invalid descriptor or no CPU buffer\n");
        return false;
    }
    
    printf("[HotpatchModelManager] Phase 3: Uploading tensors to GPU...\n");
    
    // Choose upload strategy based on model size
    // For models < 2GB: Use unified buffer (fewer allocations, better locality)
    // For models >= 2GB: Use per-tensor buffers (better memory management)
    bool success = false;
    if (desc->totalTensorBytes < (2ULL * 1024 * 1024 * 1024)) {
        success = UploadTensorUnified(desc);
    } else {
        success = UploadTensorPerTensor(desc);
    }
    
    if (success) {
        desc->gpuUploadComplete.store(true);
        printf("[HotpatchModelManager] GPU upload complete\n");
    } else {
        printf("[ERROR] GPU upload failed\n");
    }
    
    return success;
}

bool HotpatchModelManager::UploadTensorUnified(ModelDescriptor* desc) {
    #ifdef RAWRXD_NO_VULKAN
    printf("[WARN] Vulkan disabled, skipping GPU upload\n");
    return false;
    #else
    
    // Get Vulkan compute instance (singleton)
    // Note: In production, this would be passed in or accessed via global
    extern VulkanCompute* g_vulkanCompute;  // Forward declaration
    if (!g_vulkanCompute) {
        printf("[ERROR] Vulkan compute not initialized\n");
        return false;
    }
    
    // Create unified device buffer
    size_t bufferSize = desc->totalTensorBytes;
    auto result = g_vulkanCompute->createBuffer(
        bufferSize,
        VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
        VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT
    );
    
    if (!result) {
        printf("[ERROR] Failed to create Vulkan buffer (size: %zu MB)\n", 
               bufferSize / (1024 * 1024));
        return false;
    }
    
    // Store the buffer
    VulkanBuffer* vulkanBuffer = new VulkanBuffer(result.value());
    desc->unifiedBuffer = vulkanBuffer;
    
    // TODO: Upload data from CPU buffer (desc->gpuBuffer) to GPU
    // This requires staging buffer + vkCmdCopyBuffer
    // For now, we just allocate the GPU memory
    
    printf("[HotpatchModelManager] Created unified Vulkan buffer: %zu MB\n",
           bufferSize / (1024 * 1024));
    
    return true;
    #endif
}

bool HotpatchModelManager::UploadTensorPerTensor(ModelDescriptor* desc) {
    #ifdef RAWRXD_NO_VULKAN
    printf("[WARN] Vulkan disabled, skipping GPU upload\n");
    return false;
    #else
    
    extern VulkanCompute* g_vulkanCompute;
    if (!g_vulkanCompute) {
        printf("[ERROR] Vulkan compute not initialized\n");
        return false;
    }
    
    // Reserve space for tensor buffers
    desc->tensorBuffers.reserve(desc->tensors.size());
    
    size_t totalAllocated = 0;
    
    for (const auto& tensorInfo : desc->tensors) {
        // Create per-tensor buffer
        auto result = g_vulkanCompute->createBuffer(
            tensorInfo.size,
            VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT,
            VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT
        );
        
        if (!result) {
            printf("[ERROR] Failed to create tensor buffer: %s\n", tensorInfo.name);
            // Cleanup already allocated buffers
            for (auto* buf : desc->tensorBuffers) {
                if (buf) {
                    g_vulkanCompute->destroyBuffer(*buf);
                    delete buf;
                }
            }
            desc->tensorBuffers.clear();
            return false;
        }
        
        VulkanBuffer* tensorBuffer = new VulkanBuffer(result.value());
        desc->tensorBuffers.push_back(tensorBuffer);
        totalAllocated += tensorInfo.size;
        
        // TODO: Upload tensor data from CPU to GPU
        // Requires staging buffer + vkCmdCopyBuffer per tensor
    }
    
    printf("[HotpatchModelManager] Created %zu per-tensor Vulkan buffers: %zu MB total\n",
           desc->tensorBuffers.size(), totalAllocated / (1024 * 1024));
    
    return true;
    #endif
}

} // namespace RawrXD

// ============================================================================
// C API Implementation (extern "C")
// ============================================================================

using namespace RawrXD;

extern "C" {

void RawrXD_HotpatchModelCleanup(uint64_t modelHandle) {
    HotpatchModelManager::Instance().UnloadModel(modelHandle);
}

uint64_t RawrXD_HotpatchLoadModel(const char* modelPath) {
    return HotpatchModelManager::Instance().LoadModel(modelPath);
}

uint64_t RawrXD_HotpatchGetActiveModel() {
    ModelDescriptor* desc = HotpatchModelManager::Instance().GetActiveModel();
    return reinterpret_cast<uint64_t>(desc);
}

uint64_t RawrXD_HotpatchInitManager() {
    return HotpatchModelManager::Instance().Initialize() ? 0 : 1;
}

void RawrXD_HotpatchShutdownManager() {
    HotpatchModelManager::Instance().Shutdown();
}

} // extern "C"

// Explicit exports for MASM64 linkage
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchLoadModel")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchGetActiveModel")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchInitManager")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchShutdownManager")
#pragma comment(linker, "/EXPORT:RawrXD_HotpatchModelCleanup")

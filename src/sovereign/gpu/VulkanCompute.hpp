// ============================================================================
// VulkanCompute.hpp - Vulkan Compute Backend for GPU Inference
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

// Vulkan device info
struct VulkanDeviceInfo {
    std::string name;
    uint32_t apiVersion;
    uint32_t driverVersion;
    uint64_t dedicatedMemory;
    uint64_t sharedMemory;
    uint32_t computeUnits;
    uint32_t maxWorkgroupSize;
    uint64_t maxBufferSize;
    bool supportsFP16;
    bool supportsInt8;
    bool supportsSubgroup;
};

// Vulkan buffer
struct VulkanBuffer {
    uint64_t id;
    void* handle;
    uint64_t size;
    uint64_t deviceAddress;
    bool isMapped;
    void* mappedPtr;
};

// Vulkan shader
struct VulkanShader {
    uint64_t id;
    void* module;
    std::string entryPoint;
    uint32_t workgroupSize[3];
};

// Vulkan compute pipeline
struct VulkanPipeline {
    uint64_t id;
    void* pipeline;
    void* layout;
    void* descriptorSet;
    VulkanShader shader;
};

// Vulkan compute backend
class VulkanCompute {
public:
    VulkanCompute();
    ~VulkanCompute();

    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Device management
    std::vector<VulkanDeviceInfo> EnumerateDevices();
    bool SelectDevice(uint32_t index);
    VulkanDeviceInfo GetDeviceInfo() const;

    // Buffer management
    VulkanBuffer CreateBuffer(uint64_t size, bool mapped = true);
    void DestroyBuffer(VulkanBuffer& buffer);
    bool WriteBuffer(VulkanBuffer& buffer, const void* data, uint64_t size, uint64_t offset = 0);
    bool ReadBuffer(const VulkanBuffer& buffer, void* data, uint64_t size, uint64_t offset = 0);

    // Shader management
    VulkanShader CreateShader(const std::string& spirvCode, const std::string& entryPoint);
    void DestroyShader(VulkanShader& shader);

    // Pipeline management
    VulkanPipeline CreatePipeline(const VulkanShader& shader, const std::vector<VulkanBuffer>& buffers);
    void DestroyPipeline(VulkanPipeline& pipeline);

    // Execution
    bool Dispatch(const VulkanPipeline& pipeline, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ);
    bool DispatchIndirect(const VulkanPipeline& pipeline, const VulkanBuffer& indirectBuffer);
    bool WaitIdle();

    // GEMV kernel (Q4_K_M)
    bool DispatchGEMV(const VulkanBuffer& weights, const VulkanBuffer& input,
                      const VulkanBuffer& output, uint32_t rows, uint32_t cols);

    // Statistics
    struct VulkanStats {
        uint64_t totalDispatches;
        uint64_t totalBufferAllocs;
        uint64_t totalBytesTransferred;
        double avgDispatchTimeMs;
    };
    VulkanStats GetStats() const { return stats_; }
    void ResetStats();

private:
    bool initialized_ = false;
    int selectedDevice_ = -1;
    VulkanStats stats_;
    
    // Vulkan handles
    void* instance_ = nullptr;
    void* physicalDevice_ = nullptr;
    void* device_ = nullptr;
    void* queue_ = nullptr;
    void* commandPool_ = nullptr;
    void* descriptorPool_ = nullptr;
    void* pipelineCache_ = nullptr;
    
    std::vector<VulkanDeviceInfo> devices_;
    std::vector<void*> commandBuffers_;
    uint32_t nextBufferId_ = 1;
    uint32_t nextShaderId_ = 1;
    uint32_t nextPipelineId_ = 1;
    
    mutable std::mutex mutex_;
    
    bool CreateInstance();
    bool EnumeratePhysicalDevices();
    bool CreateLogicalDevice();
    bool CreateCommandPool();
};

} // namespace Sovereign

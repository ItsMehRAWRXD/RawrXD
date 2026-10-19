// ============================================================================
// VulkanBackend.hpp — Deep2 Vulkan Compute Backend for Dual-GPU Inference
// Real implementation with dual-GPU device selection, FP16/INT8 compute pipelines,
// async weight streaming, and proportional memory split for R9700 + 7800 XT.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <functional>
#include <vulkan/vulkan.h>

namespace Deep2 {

// ============================================================================
// Vulkan Device Configuration
// ============================================================================
struct VulkanDevice {
    VkPhysicalDevice physicalDevice = VK_NULL_HANDLE;
    VkDevice device = VK_NULL_HANDLE;
    VkQueue computeQueue = VK_NULL_HANDLE;
    uint32_t queueFamilyIndex = UINT32_MAX;
    
    VkPhysicalDeviceProperties properties{};
    VkPhysicalDeviceMemoryProperties memProperties{};
    VkPhysicalDeviceFeatures features{};
    
    // RDNA3 specific
    bool supportsFP16 = false;
    bool supportsInt8 = false;
    bool supportsSubgroup = false;
    bool supportsAsyncCompute = false;
    
    uint64_t dedicatedVRAM = 0;
    uint64_t sharedVRAM = 0;
    uint32_t computeUnits = 0;
    uint32_t maxWorkgroupSize = 256;
    
    std::string name;
    uint32_t deviceIndex = 0;
    bool isPrimary = false;  // R9700
    bool isSecondary = false; // 7800 XT
};

struct VulkanBuffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    VkDeviceSize size = 0;
    VkDeviceAddress deviceAddress = 0;
    void* mappedPtr = nullptr;
    bool isMapped = false;
    uint32_t deviceIndex = 0; // Which GPU owns this buffer
};

struct VulkanShader {
    VkShaderModule module = VK_NULL_HANDLE;
    std::string entryPoint;
    uint32_t workgroupSize[3] = {256, 1, 1};
};

struct VulkanPipeline {
    VkPipeline pipeline = VK_NULL_HANDLE;
    VkPipelineLayout layout = VK_NULL_HANDLE;
    VkDescriptorSetLayout descSetLayout = VK_NULL_HANDLE;
    VkDescriptorPool descPool = VK_NULL_HANDLE;
    VkDescriptorSet descSet = VK_NULL_HANDLE;
    VulkanShader shader;
    std::vector<VkDescriptorSetLayoutBinding> bindings;
};

// Async command for weight streaming
struct StreamCommand {
    enum Type { UPLOAD, DOWNLOAD, COMPUTE, BARRIER } type;
    VulkanBuffer* buffer = nullptr;
    void* hostPtr = nullptr;
    VkDeviceSize size = 0;
    VkDeviceSize offset = 0;
    VulkanPipeline* pipeline = nullptr;
    uint32_t groupsX = 0, groupsY = 0, groupsZ = 0;
    std::function<void()> callback;
    std::promise<void> done;
};

class VulkanBackend {
public:
    VulkanBackend() = default;
    ~VulkanBackend() { Shutdown(); }
    
    // Initialize dual-GPU backend with proportional memory split
    bool Initialize(const std::string& primaryNameHint = "R9700",
                    const std::string& secondaryNameHint = "7800 XT");
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Device management
    const std::vector<VulkanDevice>& GetDevices() const { return devices_; }
    VulkanDevice* GetPrimaryDevice() { return primaryDevice_; }
    VulkanDevice* GetSecondaryDevice() { return secondaryDevice_; }
    size_t GetDeviceCount() const { return devices_.size(); }
    
    // Buffer management with dual-GPU placement
    VulkanBuffer CreateBuffer(VkDeviceSize size, VkBufferUsageFlags usage,
                              VkMemoryPropertyFlags properties, uint32_t deviceIndex = 0);
    void DestroyBuffer(VulkanBuffer& buffer);
    bool WriteBuffer(uint32_t deviceIndex, VulkanBuffer& buffer, const void* data, VkDeviceSize size, VkDeviceSize offset = 0);
    bool ReadBuffer(uint32_t deviceIndex, const VulkanBuffer& buffer, void* data, VkDeviceSize size, VkDeviceSize offset = 0);
    
    // Shader & Pipeline
    VulkanShader CreateShader(uint32_t deviceIndex, const std::vector<uint32_t>& spirv, const std::string& entryPoint);
    void DestroyShader(VulkanShader& shader);
    VulkanPipeline CreatePipeline(uint32_t deviceIndex, const VulkanShader& shader, const std::vector<VkDescriptorSetLayoutBinding>& bindings);
    void DestroyPipeline(VulkanPipeline& pipeline);
    
    // Execution
    bool Dispatch(uint32_t deviceIndex, const VulkanPipeline& pipeline, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ);
    bool WaitIdle(uint32_t deviceIndex);
    
    // GEMV/GEMM kernels for FP16/INT8
    bool DispatchGEMV(uint32_t deviceIndex, const VulkanBuffer& weights, const VulkanBuffer& input, const VulkanBuffer& output,
                      uint32_t rows, uint32_t cols, bool fp16 = true);
    bool DispatchGEMM(uint32_t deviceIndex, const VulkanBuffer& a, const VulkanBuffer& b, const VulkanBuffer& output,
                      uint32_t M, uint32_t N, uint32_t K, bool fp16 = true);
    
    // Async weight streaming for MoE expert offload
    void StartStreamThread();
    void StopStreamThread();
    void EnqueueUpload(uint32_t deviceIndex, VulkanBuffer& buffer, const void* hostPtr, VkDeviceSize size, VkDeviceSize offset = 0);
    void EnqueueDownload(uint32_t deviceIndex, VulkanBuffer& buffer, void* hostPtr, VkDeviceSize size, VkDeviceSize offset = 0);
    void EnqueueCompute(uint32_t deviceIndex, const VulkanPipeline& pipeline, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ);
    void WaitForStreamCompletion();
    
    // Proportional memory allocation across dual GPUs
    struct MemoryAllocation {
        uint32_t primaryDeviceIndex = 0;
        uint32_t secondaryDeviceIndex = 1;
        uint64_t primaryBytes = 0;
        uint64_t secondaryBytes = 0;
        double splitRatio = 0.66; // 2/3 to primary (R9700 32GB), 1/3 to secondary (7800 XT 16GB)
    };
    MemoryAllocation CalculateProportionalSplit(uint64_t totalBytes) const;
    
    // Statistics
    struct Stats {
        uint64_t totalDispatches = 0;
        uint64_t totalBufferAllocs = 0;
        uint64_t totalBytesTransferred = 0;
        double avgDispatchTimeMs = 0.0;
        double avgStreamTimeMs = 0.0;
        uint64_t primaryVRAMUsed = 0;
        uint64_t secondaryVRAMUsed = 0;
    };
    Stats GetStats() const { return stats_; }
    void ResetStats();

private:
    bool initialized_ = false;
    VkInstance instance_ = VK_NULL_HANDLE;
    VkDebugUtilsMessengerEXT debugMessenger_ = VK_NULL_HANDLE;
    
    std::vector<VulkanDevice> devices_;
    VulkanDevice* primaryDevice_ = nullptr;
    VulkanDevice* secondaryDevice_ = nullptr;
    
    VkPipelineCache pipelineCache_ = VK_NULL_HANDLE;
    
    // Async streaming
    std::thread streamThread_;
    std::queue<StreamCommand> streamQueue_;
    std::mutex streamMutex_;
    std::condition_variable streamCV_;
    bool streamRunning_ = false;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    // Vulkan initialization
    bool CreateInstance();
    bool EnumerateDevices(const std::string& primaryHint, const std::string& secondaryHint);
    bool CreateLogicalDevices();
    bool CreateCommandPools();
    bool CreatePipelineCache();
    
    // Device selection by name hint (R9700, 7800 XT)
    int SelectDeviceByName(const std::string& nameHint);
    
    // Shader module creation
    VkShaderModule CreateShaderModule(VkDevice device, const std::vector<uint32_t>& spirv);
    
    // Pipeline creation
    VkPipelineLayout CreatePipelineLayout(VkDevice device, const std::vector<VkDescriptorSetLayoutBinding>& bindings);
    VkDescriptorSetLayout CreateDescriptorSetLayout(VkDevice device, const std::vector<VkDescriptorSetLayoutBinding>& bindings);
    VkDescriptorPool CreateDescriptorPool(VkDevice device, const std::vector<VkDescriptorSetLayoutBinding>& bindings);
    VkDescriptorSet AllocateDescriptorSet(VkDevice device, VkDescriptorPool pool, VkDescriptorSetLayout layout);
    
    // Memory allocation with dual-GPU awareness
    bool AllocateBufferMemory(uint32_t deviceIndex, VkBuffer buffer, VkMemoryPropertyFlags properties, VkDeviceMemory& memory);
    void BindBufferMemory(uint32_t deviceIndex, VkBuffer buffer, VkDeviceMemory memory, VkDeviceSize offset = 0);
    
    // Async stream thread
    void StreamThreadFunc();
    void ProcessStreamCommand(StreamCommand& cmd);
    
    // Debug callback
    static VKAPI_ATTR VkBool32 VKAPI_CALL DebugCallback(
        VkDebugUtilsMessageSeverityFlagBitsEXT severity,
        VkDebugUtilsMessageTypeFlagsEXT type,
        const VkDebugUtilsMessengerCallbackDataEXT* callbackData,
        void* userData);
};

} // namespace Deep2
// ============================================================================
// vulkan_rocm_backend.h — Full Vulkan/ROCm GPU Backend for CLI and GUI IDE
// ============================================================================
// This header provides a unified GPU backend supporting both Vulkan and ROCm/HIP
// for maximum compatibility across AMD, NVIDIA, and Intel GPUs.
//
// Features:
// - Full Vulkan 1.3 compute pipeline with SPIR-V shaders
// - ROCm/HIP 5.x+ support for AMD GPUs
// - Unified memory management with DMA transfers
// - Multi-queue async execution
// - Speculative execution support
// - Generation logic with KV cache management
//
// ============================================================================

#pragma once

#include <windows.h>
#include <vulkan/vulkan.h>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <atomic>
#include <mutex>
#include <queue>
#include <thread>
#include <condition_variable>
#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace GPU {

// ============================================================================
// Forward Declarations
// ============================================================================
class VulkanComputeEngine;
class HIPComputeEngine;
class UnifiedMemoryManager;
class GenerationPipeline;
class SpeculativeExecutionEngine;

// ============================================================================
// Backend Type Enumeration
// ============================================================================
enum class GPUBackendType : uint8_t {
    Vulkan = 0,      // Cross-platform Vulkan compute
    HIP = 1,         // AMD ROCm/HIP
    CUDA = 2,        // NVIDIA CUDA (if available)
    Auto = 255       // Auto-detect best backend
};

// ============================================================================
// GPU Device Information
// ============================================================================
struct GPUDeviceInfo {
    uint32_t deviceId;
    std::string name;
    GPUBackendType backend;
    uint64_t vramBytes;
    uint32_t computeUnits;
    uint32_t maxWorkGroupSize;
    bool supportsFp16;
    bool supportsFp8;
    bool supportsInt8;
    uint32_t driverVersion;
    bool isDiscrete;
};

// ============================================================================
// Tensor Descriptor
// ============================================================================
struct TensorDesc {
    uint32_t dims[4];      // N, C, H, W or N, H, W, C
    uint32_t numDims;
    uint32_t elementSize; // 1, 2, 4 bytes
    uint32_t totalElements;
    uint64_t sizeBytes;
};

// ============================================================================
// GPU Buffer Handle
// ============================================================================
struct GPUBuffer {
    union {
        VkBuffer vulkanBuffer;
        void* hipPtr;
        void* cudaPtr;
    };
    VkDeviceMemory vulkanMemory;
    uint64_t size;
    bool isHostVisible;
    uint32_t refCount;
};

// ============================================================================
// Compute Shader/Kernel Descriptor
// ============================================================================
struct ComputeKernel {
    union {
        VkShaderModule vulkanShader;
        void* hipFunction;
        void* cudaFunction;
    };
    VkPipeline vulkanPipeline;
    VkPipelineLayout vulkanLayout;
    std::string entryPoint;
    uint32_t localSizeX;
    uint32_t localSizeY;
    uint32_t localSizeZ;
};

// ============================================================================
// Generation Configuration
// ============================================================================
struct GenerationConfig {
    uint32_t maxTokens;
    float temperature;
    float topP;
    uint32_t topK;
    float repetitionPenalty;
    uint32_t contextLength;
    bool useSpeculative;
    uint32_t speculativeDraftTokens;
    bool streaming;
    std::function<void(const std::string&)> onToken;
    std::function<void()> onComplete;
};

// ============================================================================
// Speculative Execution Configuration
// ============================================================================
struct SpeculativeConfig {
    uint32_t draftTokens;
    float acceptanceThreshold;
    bool useTreeAttention;
    uint32_t treeBranchingFactor;
    uint32_t maxTreeDepth;
    bool verifyInParallel;
};

// ============================================================================
// KV Cache Entry
// ============================================================================
struct KVCacheEntry {
    GPUBuffer* keyCache;
    GPUBuffer* valueCache;
    uint32_t seqLen;
    uint32_t numHeads;
    uint32_t headDim;
    uint32_t maxSeqLen;
    bool isQuantized;
    float quantScale;
};

// ============================================================================
// Unified GPU Backend Interface
// ============================================================================
class IGPUBackend {
public:
    virtual ~IGPUBackend() = default;

    // Initialization
    virtual bool Initialize() = 0;
    virtual void Shutdown() = 0;
    virtual bool IsInitialized() const = 0;

    // Device enumeration
    virtual std::vector<GPUDeviceInfo> EnumerateDevices() = 0;
    virtual bool SelectDevice(uint32_t deviceIndex) = 0;
    virtual GPUDeviceInfo GetCurrentDevice() const = 0;

    // Memory management
    virtual GPUBuffer* AllocateBuffer(uint64_t size, bool hostVisible = false) = 0;
    virtual void FreeBuffer(GPUBuffer* buffer) = 0;
    virtual void* MapBuffer(GPUBuffer* buffer) = 0;
    virtual void UnmapBuffer(GPUBuffer* buffer) = 0;
    virtual bool CopyBuffer(GPUBuffer* dst, GPUBuffer* src, uint64_t size, uint64_t dstOffset = 0, uint64_t srcOffset = 0) = 0;
    virtual bool CopyBufferHostToDevice(GPUBuffer* dst, const void* src, uint64_t size, uint64_t offset = 0) = 0;
    virtual bool CopyBufferDeviceToHost(void* dst, GPUBuffer* src, uint64_t size, uint64_t offset = 0) = 0;

    // Compute operations
    virtual bool DispatchCompute(ComputeKernel* kernel, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ,
                                  GPUBuffer** buffers, uint32_t numBuffers) = 0;
    virtual bool Synchronize() = 0;
    virtual bool Flush() = 0;

    // Tensor operations
    virtual bool MatMul(GPUBuffer* result, GPUBuffer* a, GPUBuffer* b,
                        uint32_t m, uint32_t n, uint32_t k, bool transposeB = false) = 0;
    virtual bool Softmax(GPUBuffer* result, GPUBuffer* input, uint32_t rows, uint32_t cols) = 0;
    virtual bool LayerNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* gamma, GPUBuffer* beta,
                            uint32_t rows, uint32_t cols, float epsilon = 1e-5f) = 0;
    virtual bool RMSNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* weight,
                          uint32_t rows, uint32_t cols, float epsilon = 1e-5f) = 0;
    virtual bool RoPE(GPUBuffer* result, GPUBuffer* input, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) = 0;
    virtual bool Attention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                            uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) = 0;
    virtual bool FlashAttention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                                   uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim,
                                   float scale = 1.0f) = 0;

    // KV Cache operations
    virtual bool UpdateKVCache(KVCacheEntry* cache, GPUBuffer* newKeys, GPUBuffer* newValues,
                                uint32_t startPos, uint32_t len) = 0;
    virtual bool ClearKVCache(KVCacheEntry* cache) = 0;
    virtual KVCacheEntry* CreateKVCache(uint32_t maxSeqLen, uint32_t numHeads, uint32_t headDim, bool quantized = false) = 0;
    virtual void DestroyKVCache(KVCacheEntry* cache) = 0;

    // Backend info
    virtual GPUBackendType GetType() const = 0;
    virtual const char* GetBackendName() const = 0;
    virtual uint64_t GetAvailableVRAM() const = 0;
    virtual uint64_t GetTotalVRAM() const = 0;
};

// ============================================================================
// Vulkan Backend Implementation
// ============================================================================
class VulkanBackend : public IGPUBackend {
public:
    VulkanBackend();
    ~VulkanBackend() override;

    // IGPUBackend implementation
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override { return m_initialized; }

    std::vector<GPUDeviceInfo> EnumerateDevices() override;
    bool SelectDevice(uint32_t deviceIndex) override;
    GPUDeviceInfo GetCurrentDevice() const override { return m_currentDevice; }

    GPUBuffer* AllocateBuffer(uint64_t size, bool hostVisible = false) override;
    void FreeBuffer(GPUBuffer* buffer) override;
    void* MapBuffer(GPUBuffer* buffer) override;
    void UnmapBuffer(GPUBuffer* buffer) override;
    bool CopyBuffer(GPUBuffer* dst, GPUBuffer* src, uint64_t size, uint64_t dstOffset = 0, uint64_t srcOffset = 0) override;
    bool CopyBufferHostToDevice(GPUBuffer* dst, const void* src, uint64_t size, uint64_t offset = 0) override;
    bool CopyBufferDeviceToHost(void* dst, GPUBuffer* src, uint64_t size, uint64_t offset = 0) override;

    bool DispatchCompute(ComputeKernel* kernel, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ,
                          GPUBuffer** buffers, uint32_t numBuffers) override;
    bool Synchronize() override;
    bool Flush() override;

    bool MatMul(GPUBuffer* result, GPUBuffer* a, GPUBuffer* b,
                  uint32_t m, uint32_t n, uint32_t k, bool transposeB = false) override;
    bool Softmax(GPUBuffer* result, GPUBuffer* input, uint32_t rows, uint32_t cols) override;
    bool LayerNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* gamma, GPUBuffer* beta,
                    uint32_t rows, uint32_t cols, float epsilon = 1e-5f) override;
    bool RMSNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* weight,
                  uint32_t rows, uint32_t cols, float epsilon = 1e-5f) override;
    bool RoPE(GPUBuffer* result, GPUBuffer* input, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) override;
    bool Attention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                    uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) override;
    bool FlashAttention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                           uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim,
                           float scale = 1.0f) override;

    bool UpdateKVCache(KVCacheEntry* cache, GPUBuffer* newKeys, GPUBuffer* newValues,
                        uint32_t startPos, uint32_t len) override;
    bool ClearKVCache(KVCacheEntry* cache) override;
    KVCacheEntry* CreateKVCache(uint32_t maxSeqLen, uint32_t numHeads, uint32_t headDim, bool quantized = false) override;
    void DestroyKVCache(KVCacheEntry* cache) override;

    GPUBackendType GetType() const override { return GPUBackendType::Vulkan; }
    const char* GetBackendName() const override { return "Vulkan"; }
    uint64_t GetAvailableVRAM() const override;
    uint64_t GetTotalVRAM() const override;

    // Vulkan-specific
    VkDevice GetDevice() const { return m_device; }
    VkQueue GetComputeQueue() const { return m_computeQueue; }
    VkCommandPool GetCommandPool() const { return m_commandPool; }
    uint32_t GetComputeQueueFamily() const { return m_computeQueueFamily; }

private:
    bool CreateInstance();
    bool SelectPhysicalDevice();
    bool CreateLogicalDevice();
    bool CreateCommandPool();
    bool CreateDescriptorPool();
    bool LoadComputePipelines();
    uint32_t FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
    void SubmitCommandBuffer(VkCommandBuffer cmdBuffer, VkFence fence);

    VkInstance m_instance = VK_NULL_HANDLE;
    VkPhysicalDevice m_physicalDevice = VK_NULL_HANDLE;
    VkDevice m_device = VK_NULL_HANDLE;
    VkQueue m_computeQueue = VK_NULL_HANDLE;
    VkCommandPool m_commandPool = VK_NULL_HANDLE;
    VkDescriptorPool m_descriptorPool = VK_NULL_HANDLE;
    VkFence m_fence = VK_NULL_HANDLE;

    uint32_t m_computeQueueFamily = 0;
    std::vector<GPUDeviceInfo> m_devices;
    GPUDeviceInfo m_currentDevice;
    bool m_initialized = false;

    // Compute pipelines
    VkPipeline m_matmulPipeline = VK_NULL_HANDLE;
    VkPipeline m_softmaxPipeline = VK_NULL_HANDLE;
    VkPipeline m_layernormPipeline = VK_NULL_HANDLE;
    VkPipeline m_rmsnormPipeline = VK_NULL_HANDLE;
    VkPipeline m_ropePipeline = VK_NULL_HANDLE;
    VkPipeline m_attentionPipeline = VK_NULL_HANDLE;
    VkPipeline m_flashAttentionPipeline = VK_NULL_HANDLE;

    std::mutex m_queueMutex;
    std::vector<VkCommandBuffer> m_commandBuffers;
};

// ============================================================================
// HIP/ROCm Backend Implementation
// ============================================================================
class HIPBackend : public IGPUBackend {
public:
    HIPBackend();
    ~HIPBackend() override;

    // IGPUBackend implementation
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override { return m_initialized && m_hipLib != nullptr; }

    std::vector<GPUDeviceInfo> EnumerateDevices() override;
    bool SelectDevice(uint32_t deviceIndex) override;
    GPUDeviceInfo GetCurrentDevice() const override { return m_currentDevice; }

    GPUBuffer* AllocateBuffer(uint64_t size, bool hostVisible = false) override;
    void FreeBuffer(GPUBuffer* buffer) override;
    void* MapBuffer(GPUBuffer* buffer) override;
    void UnmapBuffer(GPUBuffer* buffer) override;
    bool CopyBuffer(GPUBuffer* dst, GPUBuffer* src, uint64_t size, uint64_t dstOffset = 0, uint64_t srcOffset = 0) override;
    bool CopyBufferHostToDevice(GPUBuffer* dst, const void* src, uint64_t size, uint64_t offset = 0) override;
    bool CopyBufferDeviceToHost(void* dst, GPUBuffer* src, uint64_t size, uint64_t offset = 0) override;

    bool DispatchCompute(ComputeKernel* kernel, uint32_t groupsX, uint32_t groupsY, uint32_t groupsZ,
                          GPUBuffer** buffers, uint32_t numBuffers) override;
    bool Synchronize() override;
    bool Flush() override;

    bool MatMul(GPUBuffer* result, GPUBuffer* a, GPUBuffer* b,
                  uint32_t m, uint32_t n, uint32_t k, bool transposeB = false) override;
    bool Softmax(GPUBuffer* result, GPUBuffer* input, uint32_t rows, uint32_t cols) override;
    bool LayerNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* gamma, GPUBuffer* beta,
                    uint32_t rows, uint32_t cols, float epsilon = 1e-5f) override;
    bool RMSNorm(GPUBuffer* result, GPUBuffer* input, GPUBuffer* weight,
                  uint32_t rows, uint32_t cols, float epsilon = 1e-5f) override;
    bool RoPE(GPUBuffer* result, GPUBuffer* input, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) override;
    bool Attention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                    uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim) override;
    bool FlashAttention(GPUBuffer* result, GPUBuffer* query, GPUBuffer* key, GPUBuffer* value,
                           uint32_t batchSize, uint32_t seqLen, uint32_t numHeads, uint32_t headDim,
                           float scale = 1.0f) override;

    bool UpdateKVCache(KVCacheEntry* cache, GPUBuffer* newKeys, GPUBuffer* newValues,
                        uint32_t startPos, uint32_t len) override;
    bool ClearKVCache(KVCacheEntry* cache) override;
    KVCacheEntry* CreateKVCache(uint32_t maxSeqLen, uint32_t numHeads, uint32_t headDim, bool quantized = false) override;
    void DestroyKVCache(KVCacheEntry* cache) override;

    GPUBackendType GetType() const override { return GPUBackendType::HIP; }
    const char* GetBackendName() const override { return "HIP/ROCm"; }
    uint64_t GetAvailableVRAM() const override;
    uint64_t GetTotalVRAM() const override;

private:
    bool LoadHIPLibrary();
    bool InitializeHIPFunctions();
    bool CompileKernels();

    HMODULE m_hipLib = nullptr;
    void* m_context = nullptr;
    void* m_stream = nullptr;

    // Function pointers
    int (*m_hipInit)(unsigned int) = nullptr;
    int (*m_hipDeviceGet)(void**, int) = nullptr;
    int (*m_hipCtxCreate)(void**, unsigned int, void*) = nullptr;
    int (*m_hipCtxDestroy)(void*) = nullptr;
    int (*m_hipMalloc)(void**, size_t) = nullptr;
    int (*m_hipFree)(void*) = nullptr;
    int (*m_hipMemcpyHtoD)(void*, const void*, size_t) = nullptr;
    int (*m_hipMemcpyDtoH)(void*, void*, size_t) = nullptr;
    int (*m_hipMemcpyDtoD)(void*, void*, size_t) = nullptr;
    int (*m_hipMemset)(void*, int, size_t) = nullptr;
    int (*m_hipDeviceSynchronize)() = nullptr;
    int (*m_hipGetDeviceCount)(int*) = nullptr;
    int (*m_hipGetDeviceProperties)(void*, int) = nullptr;
    int (*m_hipMemGetInfo)(size_t*, size_t*) = nullptr;

    std::vector<GPUDeviceInfo> m_devices;
    GPUDeviceInfo m_currentDevice;
    int m_currentDeviceId = -1;
    bool m_initialized = false;

    std::mutex m_streamMutex;
};

// ============================================================================
// Backend Factory
// ============================================================================
class GPUBackendFactory {
public:
    static std::unique_ptr<IGPUBackend> CreateBackend(GPUBackendType type);
    static std::unique_ptr<IGPUBackend> CreateAutoBackend();
    static bool IsBackendAvailable(GPUBackendType type);
    static std::vector<GPUBackendType> GetAvailableBackends();
};

// ============================================================================
// Backend Manager (Singleton)
// ============================================================================
class GPUBackendManager {
public:
    static GPUBackendManager& Instance();

    bool Initialize(GPUBackendType preferredType = GPUBackendType::Auto);
    void Shutdown();
    bool IsInitialized() const;

    IGPUBackend* GetBackend();
    GPUBackendType GetCurrentBackendType() const;

    // Device management
    std::vector<GPUDeviceInfo> EnumerateAllDevices();
    bool SelectDevice(uint32_t deviceIndex);

    // Memory stats
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalVRAM() const;

private:
    GPUBackendManager() = default;
    ~GPUBackendManager() = default;
    GPUBackendManager(const GPUBackendManager&) = delete;
    GPUBackendManager& operator=(const GPUBackendManager&) = delete;

    std::unique_ptr<IGPUBackend> m_backend;
    GPUBackendType m_currentType = GPUBackendType::Auto;
    bool m_initialized = false;
    std::mutex m_mutex;
};

} // namespace GPU
} // namespace RawrXD

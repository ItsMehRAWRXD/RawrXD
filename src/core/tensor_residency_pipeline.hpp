#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <functional>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <queue>
#include <d3d12.h>
#include <dxgi1_6.h>

namespace RawrXD {
namespace Core {

// Forward declarations
class Tensor;
class TensorPool;
class GPUUploadQueue;

// Tensor residency states
enum class TensorResidency : uint32_t {
    DISK = 0,           // On disk, not loaded
    MAPPED = 1,         // Memory-mapped, CPU accessible
    UPLOADING = 2,      // DMA in progress to GPU
    GPU = 3,            // Resident in GPU memory
    PREFETCH = 4,      // Scheduled for prefetch
    EVICTING = 5       // Being evicted from GPU
};

// Tensor metadata for residency management
struct TensorResidencyMetadata {
    uint64_t tensorId;
    uint64_t fileOffset;
    uint64_t sizeBytes;
    TensorResidency state;
    std::atomic<uint32_t> refCount{0};
    std::atomic<bool> isPinned{false};
    uint64_t lastAccessTick;
    uint64_t prefetchPriority;
    
    // GPU resources
    ID3D12Resource* gpuResource{nullptr};
    D3D12_GPU_VIRTUAL_ADDRESS gpuAddress{0};
    
    // CPU mapped pointer (for zero-copy)
    void* mappedPtr{nullptr};
    HANDLE fileMappingHandle{nullptr};
};

// Zero-copy upload buffer - maps directly to GPU upload heap
class ZeroCopyUploadBuffer {
public:
    ZeroCopyUploadBuffer(ID3D12Device* device, uint64_t size);
    ~ZeroCopyUploadBuffer();
    
    // Map file region directly into upload buffer
    bool MapFileRegion(HANDLE fileHandle, uint64_t fileOffset, uint64_t size);
    void Unmap();
    
    // Get GPU virtual address for copy command
    D3D12_GPU_VIRTUAL_ADDRESS GetGPUAddress() const { return gpuAddress_; }
    ID3D12Resource* GetResource() const { return uploadResource_; }
    
    // Synchronization
    void SignalUploadComplete(ID3D12Fence* fence, uint64_t fenceValue);
    bool IsUploadComplete();
    
private:
    ID3D12Device* device_{nullptr};
    ID3D12Resource* uploadResource_{nullptr};
    D3D12_GPU_VIRTUAL_ADDRESS gpuAddress_{0};
    void* mappedPtr_{nullptr};
    uint64_t size_{0};
    
    HANDLE fileMapping_{nullptr};
    void* fileView_{nullptr};
};

// Async tensor upload queue with overlap
class AsyncTensorUploadQueue {
public:
    AsyncTensorUploadQueue(ID3D12Device* device, ID3D12CommandQueue* commandQueue);
    ~AsyncTensorUploadQueue();
    
    // Initialize with memory-mapped file
    bool Initialize(HANDLE fileHandle, uint64_t fileSize);
    
    // Queue tensor for async upload
    void QueueTensor(const TensorResidencyMetadata& metadata);
    
    // Process uploads with overlap (parse N while uploading N-1)
    void ProcessUploads();
    
    // Wait for all pending uploads
    void Flush();
    
    // Get completion statistics
    struct UploadStats {
        uint64_t totalUploaded{0};
        uint64_t uploadTimeMs{0};
        uint64_t overlapTimeMs{0};
        double throughputGBps{0.0};
    };
    UploadStats GetStats() const;
    
private:
    ID3D12Device* device_{nullptr};
    ID3D12CommandQueue* commandQueue_{nullptr};
    ID3D12CommandAllocator* commandAllocator_{nullptr};
    ID3D12GraphicsCommandList* commandList_{nullptr};
    ID3D12Fence* fence_{nullptr};
    HANDLE fenceEvent_{nullptr};
    uint64_t fenceValue_{0};
    
    HANDLE fileHandle_{nullptr};
    uint64_t fileSize_{0};
    
    // Double-buffered upload buffers for overlap
    std::unique_ptr<ZeroCopyUploadBuffer> uploadBufferCurrent_;
    std::unique_ptr<ZeroCopyUploadBuffer> uploadBufferNext_;
    
    // Upload queue
    std::queue<TensorResidencyMetadata> pendingUploads_;
    std::mutex queueMutex_;
    
    // Stats
    UploadStats stats_;
    std::chrono::high_resolution_clock::time_point startTime_;
};

// Streaming tensor loader with prefetch
class StreamingTensorLoader {
public:
    StreamingTensorLoader();
    ~StreamingTensorLoader();
    
    // Initialize with file and GPU device
    bool Initialize(const wchar_t* filePath, ID3D12Device* device, 
                    ID3D12CommandQueue* commandQueue);
    
    // Load tensor with automatic residency management
    // Returns immediately, tensor becomes resident asynchronously
    bool RequestTensor(uint64_t tensorId, uint64_t fileOffset, uint64_t size);
    
    // Prefetch tensor for future use
    void PrefetchTensor(uint64_t tensorId, uint64_t fileOffset, uint64_t size, 
                        uint64_t priority);
    
    // Wait for tensor to be GPU resident
    bool WaitForTensor(uint64_t tensorId, uint32_t timeoutMs);
    
    // Get tensor GPU address (must be resident)
    D3D12_GPU_VIRTUAL_ADDRESS GetTensorGPUAddress(uint64_t tensorId);
    
    // Evict tensor from GPU (make room for others)
    void EvictTensor(uint64_t tensorId);
    
    // Update residency based on access patterns
    void UpdateResidencyPolicy();
    
    // Get residency status
    TensorResidency GetTensorResidency(uint64_t tensorId) const;
    
private:
    // Memory-mapped file
    HANDLE fileHandle_{nullptr};
    HANDLE fileMapping_{nullptr};
    void* mappedFile_{nullptr};
    uint64_t fileSize_{0};
    
    // GPU resources
    ID3D12Device* device_{nullptr};
    ID3D12CommandQueue* commandQueue_{nullptr};
    
    // Async upload queue
    std::unique_ptr<AsyncTensorUploadQueue> uploadQueue_;
    
    // Tensor residency tracking
    std::unordered_map<uint64_t, TensorResidencyMetadata> tensors_;
    mutable std::mutex tensorsMutex_;
    
    // Prefetch queue (priority sorted)
    std::priority_queue<std::pair<uint64_t, uint64_t>> prefetchQueue_; // <priority, tensorId>
    std::mutex prefetchMutex_;
    
    // Background prefetch thread
    std::thread prefetchThread_;
    std::atomic<bool> stopPrefetch_{false};
    void PrefetchWorker();
    
    // GPU memory pool
    std::unique_ptr<TensorPool> tensorPool_;
    uint64_t gpuMemoryLimit_{0};
    uint64_t gpuMemoryUsed_{0};
    
    // Access tracking for LRU eviction
    uint64_t accessTick_{0};
};

// Tensor pool for GPU memory management
class TensorPool {
public:
    TensorPool(ID3D12Device* device, uint64_t poolSize);
    ~TensorPool();
    
    // Allocate GPU memory for tensor
    bool AllocateTensor(uint64_t tensorId, uint64_t size, 
                        ID3D12Resource** outResource, 
                        D3D12_GPU_VIRTUAL_ADDRESS* outAddress);
    
    // Free tensor memory
    void FreeTensor(uint64_t tensorId);
    
    // Get pool statistics
    struct PoolStats {
        uint64_t totalSize{0};
        uint64_t allocatedSize{0};
        uint64_t freeSize{0};
        uint32_t tensorCount{0};
        uint32_t freeBlocks{0};
    };
    PoolStats GetStats() const;
    
private:
    ID3D12Device* device_{nullptr};
    uint64_t poolSize_{0};
    
    // Simple buddy allocator for GPU memory
    struct Block {
        uint64_t offset{0};
        uint64_t size{0};
        bool allocated{false};
        uint64_t tensorId{0};
    };
    std::vector<Block> blocks_;
    mutable std::mutex blocksMutex_;
    
    ID3D12Resource* poolResource_{nullptr};
    D3D12_GPU_VIRTUAL_ADDRESS poolBaseAddress_{0};
};

// Unified tensor residency pipeline
class TensorResidencyPipeline {
public:
    TensorResidencyPipeline();
    ~TensorResidencyPipeline();
    
    // Initialize pipeline
    bool Initialize(const wchar_t* modelPath, ID3D12Device* device,
                    ID3D12CommandQueue* commandQueue, uint64_t gpuMemoryLimit);
    
    // Load model with streaming
    bool LoadModel(const wchar_t* modelPath);
    
    // Get tensor for compute (ensures GPU residency)
    // This is the main API for the inference engine
    D3D12_GPU_VIRTUAL_ADDRESS GetTensorForCompute(uint64_t tensorId,
                                                   uint64_t fileOffset,
                                                   uint64_t size,
                                                   uint32_t timeoutMs = 5000);
    
    // Prefetch tensors for upcoming layers
    void PrefetchLayerTensors(const std::vector<uint64_t>& tensorIds);
    
    // Stream compute - overlap upload and compute
    // callback is invoked when tensor is ready on GPU
    using ComputeCallback = std::function<void(uint64_t tensorId, 
                                               D3D12_GPU_VIRTUAL_ADDRESS gpuAddr)>;
    void StreamCompute(const std::vector<uint64_t>& tensorIds,
                       ComputeCallback callback);
    
    // Get pipeline statistics
    struct PipelineStats {
        uint64_t totalTensors{0};
        uint64_t residentTensors{0};
        uint64_t uploadQueueDepth{0};
        uint64_t prefetchQueueDepth{0};
        double avgUploadTimeMs{0.0};
        double avgThroughputGBps{0.0};
        uint64_t cacheHits{0};
        uint64_t cacheMisses{0};
    };
    PipelineStats GetStats() const;
    
    // Shutdown pipeline
    void Shutdown();
    
private:
    std::unique_ptr<StreamingTensorLoader> loader_;
    std::atomic<bool> initialized_{false};
    
    // Compute stream overlap
    std::thread computeThread_;
    std::queue<std::pair<std::vector<uint64_t>, ComputeCallback>> computeQueue_;
    std::mutex computeQueueMutex_;
    std::condition_variable computeCv_;
    void ComputeWorker();
};

} // namespace Core
} // namespace RawrXD

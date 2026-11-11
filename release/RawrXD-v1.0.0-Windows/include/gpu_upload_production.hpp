//=============================================================================
// RawrXD GPU Upload Module - PRODUCTION IMPLEMENTATION
// Direct GPU memory transfer with CUDA and Vulkan support
//=============================================================================

#ifndef RAWRXD_GPU_UPLOAD_HPP
#define RAWRXD_GPU_UPLOAD_HPP

#include "quantization_production.hpp"
#include <cstdint>
#include <vector>
#include <functional>
#include <memory>

namespace RawrXD {
namespace GPU {

//=============================================================================
// GPU Backend Enumeration
//=============================================================================

enum class GPUBackend {
    NONE = 0,
    CUDA = 1,
    VULKAN = 2,
    DIRECTX12 = 3,
    METAL = 4,
    OPENCL = 5
};

//============================================================================-
// GPU Device Information
//=============================================================================

struct GPUDeviceInfo {
    int device_id;
    GPUBackend backend;
    char name[256];
    size_t total_memory;
    size_t free_memory;
    size_t max_allocation_size;
    int compute_capability_major;
    int compute_capability_minor;
    bool unified_memory;  // Can use host memory directly
    bool async_upload;    // Supports async upload
};

//=============================================================================
// GPU Memory Buffer
//=============================================================================

class GPUMemoryBuffer {
public:
    GPUMemoryBuffer();
    ~GPUMemoryBuffer();
    
    // Allocate GPU memory
    bool Allocate(size_t size, GPUBackend backend, int device_id = 0);
    void Free();
    
    // Upload data from host
    bool Upload(const void* host_data, size_t size, size_t offset = 0);
    bool UploadAsync(const void* host_data, size_t size, size_t offset = 0);
    
    // Download to host
    bool Download(void* host_data, size_t size, size_t offset = 0);
    
    // Synchronization
    void Synchronize();
    bool IsUploadComplete();
    
    // Getters
    void* GetDevicePtr() { return device_ptr_; }
    size_t GetSize() const { return size_; }
    GPUBackend GetBackend() const { return backend_; }
    int GetDeviceId() const { return device_id_; }
    bool IsAllocated() const { return device_ptr_ != nullptr; }
    
private:
    void* device_ptr_;
    void* host_ptr_;  // For pinned memory
    size_t size_;
    GPUBackend backend_;
    int device_id_;
    bool is_pinned_;
    
    // Backend-specific handles
    void* cuda_ptr_;
    void* vulkan_buffer_;
    void* vulkan_memory_;
    void* command_buffer_;
    void* event_;
};

//=============================================================================
// Tensor GPU Upload Manager
//=============================================================================

class TensorGPUUploader {
public:
    using UploadCompleteCallback = std::function<void(const std::string& tensor_name, bool success)>;
    using UploadProgressCallback = std::function<void(const std::string& tensor_name, int percent)>;
    
    TensorGPUUploader();
    ~TensorGPUUploader();
    
    // Initialize with backend
    bool Initialize(GPUBackend backend, int device_id = 0);
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    GPUBackend GetBackend() const { return backend_; }
    
    // Upload tensor to GPU
    bool UploadTensor(const std::string& name,
                      const void* host_data,
                      Quantization::QuantType quant_type,
                      size_t num_elements);
    
    // Upload with dequantization (upload as F16/F32)
    bool UploadTensorDequantized(const std::string& name,
                                  const void* quantized_data,
                                  Quantization::QuantType quant_type,
                                  size_t num_elements,
                                  bool use_fp16 = true);
    
    // Async upload
    void UploadTensorAsync(const std::string& name,
                          const void* host_data,
                          Quantization::QuantType quant_type,
                          size_t num_elements);
    
    // Get uploaded tensor
    GPUMemoryBuffer* GetTensor(const std::string& name);
    bool IsTensorOnGPU(const std::string& name) const;
    void EvictTensor(const std::string& name);
    
    // Batch upload
    struct TensorUploadRequest {
        std::string name;
        const void* host_data;
        Quantization::QuantType quant_type;
        size_t num_elements;
        int priority;
    };
    
    void UploadBatch(const std::vector<TensorUploadRequest>& requests);
    void WaitForBatchComplete();
    
    // Memory management
    size_t GetTotalGPUMemory() const;
    size_t GetFreeGPUMemory() const;
    size_t GetUsedGPUMemory() const;
    void SetMemoryLimit(size_t bytes);
    void EvictToLimit();
    
    // Callbacks
    void SetUploadCompleteCallback(UploadCompleteCallback cb) { on_complete_ = cb; }
    void SetUploadProgressCallback(UploadProgressCallback cb) { on_progress_ = cb; }
    
    // Statistics
    size_t GetBytesUploaded() const { return bytes_uploaded_; }
    size_t GetBytesEvicted() const { return bytes_evicted_; }
    size_t GetUploadCount() const { return upload_count_; }
    float GetAverageUploadTimeMs() const;

private:
    bool initialized_;
    GPUBackend backend_;
    int device_id_;
    size_t memory_limit_;
    size_t memory_used_;
    
    std::unordered_map<std::string, std::unique_ptr<GPUMemoryBuffer>> tensors_;
    std::vector<std::string> upload_queue_;
    
    UploadCompleteCallback on_complete_;
    UploadProgressCallback on_progress_;
    
    size_t bytes_uploaded_;
    size_t bytes_evicted_;
    size_t upload_count_;
    double total_upload_time_ms_;
    
    // CUDA specific
    void* cuda_stream_;
    
    // Vulkan specific
    void* vulkan_device_;
    void* vulkan_queue_;
    void* vulkan_command_pool_;
};

//=============================================================================
// GPU Device Enumeration
//=============================================================================

std::vector<GPUDeviceInfo> EnumerateGPUDevices();
GPUBackend DetectBestBackend();
bool IsBackendAvailable(GPUBackend backend);

//=============================================================================
// Memory Transfer Optimization
//=============================================================================

// Enable pinned memory for faster uploads
void EnablePinnedMemory(size_t pool_size);
void DisablePinnedMemory();

// Get optimal transfer parameters
struct TransferParams {
    size_t chunk_size;
    size_t num_streams;
    bool use_pinned_memory;
    bool use_async;
};

TransferParams GetOptimalTransferParams(GPUBackend backend, size_t total_size);

} // namespace GPU
} // namespace RawrXD

#endif // RAWRXD_GPU_UPLOAD_HPP

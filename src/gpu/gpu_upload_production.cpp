//=============================================================================
// RawrXD GPU Upload Module - IMPLEMENTATION
// Direct GPU memory transfer with CUDA and Vulkan support
//=============================================================================

#include "gpu_upload_production.hpp"
#include <iostream>
#include <string>
#include <chrono>

// CUDA headers (if available)
#ifdef RAWRXD_HAS_CUDA
#include <cuda_runtime.h>
#include <cuda.h>
#endif

// Vulkan headers (if available)
#ifdef RAWRXD_HAS_VULKAN
#include <vulkan/vulkan.h>
#endif

namespace RawrXD {
namespace GPU {

//=============================================================================
// GPU Memory Buffer Implementation
//=============================================================================

GPUMemoryBuffer::GPUMemoryBuffer()
    : device_ptr_(nullptr), host_ptr_(nullptr), size_(0)
    , backend_(GPUBackend::NONE), device_id_(0), is_pinned_(false)
    , cuda_ptr_(nullptr), vulkan_buffer_(nullptr), vulkan_memory_(nullptr)
    , command_buffer_(nullptr), event_(nullptr) {
}

GPUMemoryBuffer::~GPUMemoryBuffer() {
    Free();
}

bool GPUMemoryBuffer::Allocate(size_t size, GPUBackend backend, int device_id) {
    Free();
    
    size_ = size;
    backend_ = backend;
    device_id_ = device_id;
    
    switch (backend) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                cudaError_t err = cudaSetDevice(device_id);
                if (err != cudaSuccess) return false;
                
                err = cudaMalloc(&device_ptr_, size);
                if (err != cudaSuccess) {
                    device_ptr_ = nullptr;
                    return false;
                }
                
                // Allocate pinned host memory for faster transfers
                err = cudaMallocHost(&host_ptr_, size);
                if (err == cudaSuccess) {
                    is_pinned_ = true;
                }
            }
            #else
            return false;
            #endif
            break;
            
        case GPUBackend::VULKAN:
            #ifdef RAWRXD_HAS_VULKAN
            // Vulkan allocation would go here
            // Simplified for now
            return false;
            #else
            return false;
            #endif
            break;
            
        default:
            return false;
    }
    
    return true;
}

void GPUMemoryBuffer::Free() {
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            if (device_ptr_) {
                cudaFree(device_ptr_);
                device_ptr_ = nullptr;
            }
            if (host_ptr_ && is_pinned_) {
                cudaFreeHost(host_ptr_);
                host_ptr_ = nullptr;
                is_pinned_ = false;
            }
            #endif
            break;
            
        case GPUBackend::VULKAN:
            #ifdef RAWRXD_HAS_VULKAN
            // Vulkan cleanup
            #endif
            break;
            
        default:
            break;
    }
    
    size_ = 0;
    backend_ = GPUBackend::NONE;
}

bool GPUMemoryBuffer::Upload(const void* host_data, size_t size, size_t offset) {
    if (!device_ptr_ || offset + size > size_) return false;
    
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                cudaError_t err = cudaMemcpy(
                    static_cast<uint8_t*>(device_ptr_) + offset,
                    host_data,
                    size,
                    cudaMemcpyHostToDevice
                );
                return err == cudaSuccess;
            }
            #else
            return false;
            #endif
            break;
            
        default:
            return false;
    }
    
    return false;
}

bool GPUMemoryBuffer::UploadAsync(const void* host_data, size_t size, size_t offset) {
    if (!device_ptr_ || offset + size > size_) return false;
    
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                // Use pinned memory for async transfer
                void* src = const_cast<void*>(host_data);
                if (is_pinned_ && host_ptr_) {
                    std::memcpy(host_ptr_, host_data, size);
                    src = host_ptr_;
                }
                
                cudaError_t err = cudaMemcpyAsync(
                    static_cast<uint8_t*>(device_ptr_) + offset,
                    src,
                    size,
                    cudaMemcpyHostToDevice,
                    0  // Default stream
                );
                return err == cudaSuccess;
            }
            #else
            return false;
            #endif
            break;
            
        default:
            return false;
    }
    
    return false;
}

bool GPUMemoryBuffer::Download(void* host_data, size_t size, size_t offset) {
    if (!device_ptr_ || offset + size > size_) return false;
    
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                cudaError_t err = cudaMemcpy(
                    host_data,
                    static_cast<uint8_t*>(device_ptr_) + offset,
                    size,
                    cudaMemcpyDeviceToHost
                );
                return err == cudaSuccess;
            }
            #else
            return false;
            #endif
            break;
            
        default:
            return false;
    }
    
    return false;
}

void GPUMemoryBuffer::Synchronize() {
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            cudaDeviceSynchronize();
            #endif
            break;
            
        default:
            break;
    }
}

bool GPUMemoryBuffer::IsUploadComplete() {
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                cudaError_t err = cudaStreamQuery(0);
                return err == cudaSuccess;
            }
            #else
            return true;
            #endif
            break;
            
        default:
            return true;
    }
}

//=============================================================================
// Tensor GPU Uploader Implementation
//=============================================================================

TensorGPUUploader::TensorGPUUploader()
    : initialized_(false), backend_(GPUBackend::NONE), device_id_(0)
    , memory_limit_(0), memory_used_(0), bytes_uploaded_(0)
    , bytes_evicted_(0), upload_count_(0), total_upload_time_ms_(0.0)
    , cuda_stream_(nullptr), vulkan_device_(nullptr), vulkan_queue_(nullptr)
    , vulkan_command_pool_(nullptr) {
}

TensorGPUUploader::~TensorGPUUploader() {
    Shutdown();
}

bool TensorGPUUploader::Initialize(GPUBackend backend, int device_id) {
    if (initialized_) return true;
    
    backend_ = backend;
    device_id_ = device_id;
    
    switch (backend) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                cudaError_t err = cudaSetDevice(device_id);
                if (err != cudaSuccess) {
                    std::cerr << "Failed to set CUDA device: " << cudaGetErrorString(err) << "\n";
                    return false;
                }
                
                // Create stream for async operations
                err = cudaStreamCreate(reinterpret_cast<cudaStream_t*>(&cuda_stream_));
                if (err != cudaSuccess) {
                    cuda_stream_ = nullptr;
                }
                
                // Get memory info
                size_t free, total;
                cudaMemGetInfo(&free, &total);
                memory_limit_ = total;
            }
            #else
            std::cerr << "CUDA support not compiled in\n";
            return false;
            #endif
            break;
            
        case GPUBackend::VULKAN:
            // Vulkan initialization would go here
            std::cerr << "Vulkan support not yet implemented\n";
            return false;
            
        default:
            return false;
    }
    
    initialized_ = true;
    return true;
}

void TensorGPUUploader::Shutdown() {
    if (!initialized_) return;
    
    // Free all tensors
    tensors_.clear();
    memory_used_ = 0;
    
    // Clean up backend-specific resources
    switch (backend_) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            if (cuda_stream_) {
                cudaStreamDestroy(reinterpret_cast<cudaStream_t>(cuda_stream_));
                cuda_stream_ = nullptr;
            }
            #endif
            break;
            
        default:
            break;
    }
    
    initialized_ = false;
}

bool TensorGPUUploader::UploadTensor(const std::string& name,
                                      const void* host_data,
                                      Quantization::QuantType quant_type,
                                      size_t num_elements) {
    if (!initialized_) return false;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Calculate size
    auto info = Quantization::CalculateQuantizedTensorInfo(quant_type, num_elements);
    size_t size = info.total_bytes;
    
    // Check memory limit
    if (memory_used_ + size > memory_limit_) {
        EvictToLimit();
    }
    
    // Allocate GPU buffer
    auto buffer = std::make_unique<GPUMemoryBuffer>();
    if (!buffer->Allocate(size, backend_, device_id_)) {
        return false;
    }
    
    // Upload data
    if (!buffer->Upload(host_data, size, 0)) {
        return false;
    }
    
    // Store tensor
    tensors_[name] = std::move(buffer);
    memory_used_ += size;
    bytes_uploaded_ += size;
    upload_count_++;
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    total_upload_time_ms_ += duration.count() / 1000.0;
    
    if (on_complete_) {
        on_complete_(name, true);
    }
    
    return true;
}

bool TensorGPUUploader::UploadTensorDequantized(const std::string& name,
                                                 const void* quantized_data,
                                                 Quantization::QuantType quant_type,
                                                 size_t num_elements,
                                                 bool use_fp16) {
    if (!initialized_) return false;
    
    // Dequantize to float
    std::vector<float> dequantized(num_elements);
    Quantization::DequantizeTensor(quantized_data, quant_type, 
                                   dequantized.data(), num_elements);
    
    // Upload as F32 or F16
    if (use_fp16) {
        // Convert to F16 (would need half-float conversion)
        // For now, upload as F32
        return UploadTensor(name, dequantized.data(), 
                           Quantization::QuantType::F32, num_elements);
    } else {
        return UploadTensor(name, dequantized.data(),
                           Quantization::QuantType::F32, num_elements);
    }
}

void TensorGPUUploader::UploadTensorAsync(const std::string& name,
                                          const void* host_data,
                                          Quantization::QuantType quant_type,
                                          size_t num_elements) {
    // For now, just call synchronous upload
    // Full async would require queue management
    UploadTensor(name, host_data, quant_type, num_elements);
}

GPUMemoryBuffer* TensorGPUUploader::GetTensor(const std::string& name) {
    auto it = tensors_.find(name);
    if (it != tensors_.end()) {
        return it->second.get();
    }
    return nullptr;
}

bool TensorGPUUploader::IsTensorOnGPU(const std::string& name) const {
    return tensors_.find(name) != tensors_.end();
}

void TensorGPUUploader::EvictTensor(const std::string& name) {
    auto it = tensors_.find(name);
    if (it != tensors_.end()) {
        memory_used_ -= it->second->GetSize();
        bytes_evicted_ += it->second->GetSize();
        tensors_.erase(it);
    }
}

void TensorGPUUploader::EvictToLimit() {
    // Simple LRU eviction - remove oldest tensors
    while (memory_used_ > memory_limit_ * 0.9 && !tensors_.empty()) {
        // Get first tensor (oldest)
        auto it = tensors_.begin();
        EvictTensor(it->first);
    }
}

size_t TensorGPUUploader::GetTotalGPUMemory() const {
    return memory_limit_;
}

size_t TensorGPUUploader::GetFreeGPUMemory() const {
    if (memory_limit_ > memory_used_) {
        return memory_limit_ - memory_used_;
    }
    return 0;
}

size_t TensorGPUUploader::GetUsedGPUMemory() const {
    return memory_used_;
}

void TensorGPUUploader::SetMemoryLimit(size_t bytes) {
    memory_limit_ = bytes;
    EvictToLimit();
}

float TensorGPUUploader::GetAverageUploadTimeMs() const {
    if (upload_count_ == 0) return 0.0f;
    return static_cast<float>(total_upload_time_ms_ / upload_count_);
}

//=============================================================================
// GPU Device Enumeration
//=============================================================================

std::vector<GPUDeviceInfo> EnumerateGPUDevices() {
    std::vector<GPUDeviceInfo> devices;
    
    #ifdef RAWRXD_HAS_CUDA
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err == cudaSuccess) {
        for (int i = 0; i < count; ++i) {
            cudaDeviceProp prop;
            cudaGetDeviceProperties(&prop, i);
            
            GPUDeviceInfo info{};
            info.device_id = i;
            info.backend = GPUBackend::CUDA;
            std::strncpy(info.name, prop.name, sizeof(info.name) - 1);
            info.total_memory = prop.totalGlobalMem;
            info.compute_capability_major = prop.major;
            info.compute_capability_minor = prop.minor;
            info.async_upload = true;
            info.unified_memory = (prop.managedMemory != 0);
            
            size_t free, total;
            cudaSetDevice(i);
            cudaMemGetInfo(&free, &total);
            info.free_memory = free;
            info.max_allocation_size = prop.totalGlobalMem;
            
            devices.push_back(info);
        }
    }
    #endif
    
    return devices;
}

GPUBackend DetectBestBackend() {
    #ifdef RAWRXD_HAS_CUDA
    int count = 0;
    if (cudaGetDeviceCount(&count) == cudaSuccess && count > 0) {
        return GPUBackend::CUDA;
    }
    #endif
    
    #ifdef RAWRXD_HAS_VULKAN
    // Check Vulkan
    return GPUBackend::VULKAN;
    #endif
    
    return GPUBackend::NONE;
}

bool IsBackendAvailable(GPUBackend backend) {
    switch (backend) {
        case GPUBackend::CUDA:
            #ifdef RAWRXD_HAS_CUDA
            {
                int count = 0;
                return cudaGetDeviceCount(&count) == cudaSuccess && count > 0;
            }
            #else
            return false;
            #endif
            
        case GPUBackend::VULKAN:
            #ifdef RAWRXD_HAS_VULKAN
            return true;  // Would need actual check
            #else
            return false;
            #endif
            
        default:
            return false;
    }
}

//=============================================================================
// Memory Transfer Optimization
//=============================================================================

static bool g_pinned_memory_enabled = false;
static size_t g_pinned_pool_size = 0;

void EnablePinnedMemory(size_t pool_size) {
    g_pinned_memory_enabled = true;
    g_pinned_pool_size = pool_size;
}

void DisablePinnedMemory() {
    g_pinned_memory_enabled = false;
    g_pinned_pool_size = 0;
}

TransferParams GetOptimalTransferParams(GPUBackend backend, size_t total_size) {
    TransferParams params{};
    
    switch (backend) {
        case GPUBackend::CUDA:
            params.chunk_size = 256 * 1024 * 1024;  // 256MB chunks
            params.num_streams = 4;
            params.use_pinned_memory = g_pinned_memory_enabled;
            params.use_async = true;
            break;
            
        case GPUBackend::VULKAN:
            params.chunk_size = 128 * 1024 * 1024;  // 128MB chunks
            params.num_streams = 2;
            params.use_pinned_memory = false;
            params.use_async = true;
            break;
            
        default:
            params.chunk_size = 64 * 1024 * 1024;
            params.num_streams = 1;
            params.use_pinned_memory = false;
            params.use_async = false;
            break;
    }
    
    return params;
}

} // namespace GPU
} // namespace RawrXD

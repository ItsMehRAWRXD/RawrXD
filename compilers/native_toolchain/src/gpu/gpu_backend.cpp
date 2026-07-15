// gpu_backend.cpp - GPU Backend Factory and Dispatch
// Phase 8.3 - Hardware Acceleration Abstraction

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "gpu_backend.h"
#include "vulkan/vulkan_backend_stub.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// BACKEND FACTORY
// ============================================================================

GPUBackend* GPU_BackendCreate(GPUBackendType type) {
    switch (type) {
        case GPU_BACKEND_VULKAN:
            printf("[GPU] Creating Vulkan backend...\n");
            return Vulkan_BackendCreate();
            
        case GPU_BACKEND_DIRECTML:
            printf("[GPU] DirectML backend not yet implemented\n");
            return NULL;
            
        case GPU_BACKEND_CUDA:
            printf("[GPU] CUDA backend not yet implemented\n");
            return NULL;
            
        default:
            printf("[GPU] Unknown backend type: %d\n", type);
            return NULL;
    }
}

void GPU_BackendDestroy(GPUBackend* backend) {
    if (!backend) return;
    
    if (backend->destroy) {
        backend->destroy(backend);
    }
}

// ============================================================================
// DEVICE ENUMERATION
// ============================================================================

int GPU_EnumerateDevices(GPUBackendType type, GPUDeviceInfo* devices, int max_devices) {
    switch (type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_EnumerateDevices(devices, max_devices);
            
        case GPU_BACKEND_DIRECTML:
            printf("[GPU] DirectML enumeration not yet implemented\n");
            return 0;
            
        case GPU_BACKEND_CUDA:
            printf("[GPU] CUDA enumeration not yet implemented\n");
            return 0;
            
        default:
            return 0;
    }
}

const char* GPU_GetBackendName(GPUBackendType type) {
    switch (type) {
        case GPU_BACKEND_VULKAN: return "Vulkan Compute";
        case GPU_BACKEND_DIRECTML: return "DirectML";
        case GPU_BACKEND_CUDA: return "CUDA";
        default: return "Unknown";
    }
}

// ============================================================================
// TENSOR MANAGEMENT
// ============================================================================

GPUTensor* GPU_TensorCreate(GPUBackend* backend, const uint32_t* dims, uint32_t n_dims, GPUDataType dtype) {
    if (!backend) return NULL;
    
    GPUTensor* tensor = (GPUTensor*)calloc(1, sizeof(GPUTensor));
    if (!tensor) return NULL;
    
    tensor->n_dims = n_dims;
    tensor->dtype = dtype;
    
    size_t total_elements = 1;
    for (uint32_t i = 0; i < n_dims; i++) {
        tensor->dims[i] = dims[i];
        total_elements *= dims[i];
    }
    
    // Calculate size based on data type
    size_t element_size = 0;
    switch (dtype) {
        case GPU_FLOAT32: element_size = 4; break;
        case GPU_FLOAT16: element_size = 2; break;
        case GPU_INT32: element_size = 4; break;
        case GPU_INT16: element_size = 2; break;
        case GPU_Q4_0:
        case GPU_Q4_1: element_size = 1; break;  // Approximate
        case GPU_Q8_0: element_size = 1; break;
        default: element_size = 4;
    }
    
    tensor->size = total_elements * element_size;
    
    // Allocate device memory
    if (backend->allocate) {
        tensor->device_data = backend->allocate(backend, tensor->size);
        if (!tensor->device_data) {
            free(tensor);
            return NULL;
        }
    }
    
    return tensor;
}

void GPU_TensorDestroy(GPUBackend* backend, GPUTensor* tensor) {
    if (!tensor) return;
    
    if (backend && backend->free && tensor->device_data) {
        backend->free(backend, tensor->device_data);
    }
    
    free(tensor);
}

GPUStatus GPU_TensorUpload(GPUBackend* backend, GPUTensor* tensor, const void* data) {
    if (!backend || !tensor || !data) return GPU_ERROR_NULL_POINTER;
    if (!backend->upload) return GPU_ERROR_UNSUPPORTED;
    
    return backend->upload(backend, tensor, data);
}

GPUStatus GPU_TensorDownload(GPUBackend* backend, GPUTensor* tensor, void* data) {
    if (!backend || !tensor || !data) return GPU_ERROR_NULL_POINTER;
    if (!backend->download) return GPU_ERROR_UNSUPPORTED;
    
    return backend->download(backend, tensor, data);
}

// ============================================================================
// KERNEL DISPATCH (Placeholder implementations)
// ============================================================================

GPUStatus GPU_RMSNorm(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                      const GPUTensor* weight, float epsilon, uint32_t n_elements) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    // Dispatch to backend-specific implementation
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_RMSNorm(backend, output, input, weight, epsilon, n_elements);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_RoPE(GPUBackend* backend, GPUTensor* query, GPUTensor* key,
                   uint32_t n_heads, uint32_t head_dim, uint32_t position, float freq_base) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_RoPE(backend, query, key, n_heads, head_dim, position, freq_base);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_Attention(GPUBackend* backend, GPUTensor* output,
                        const GPUTensor* query, const GPUTensor* key, const GPUTensor* value,
                        uint32_t n_heads, uint32_t seq_len, uint32_t head_dim) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_Attention(backend, output, query, key, value, n_heads, seq_len, head_dim);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_MatMul(GPUBackend* backend, GPUTensor* output,
                     const GPUTensor* a, const GPUTensor* b,
                     uint32_t m, uint32_t n, uint32_t k, GPUDataType compute_type) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_MatMul(backend, output, a, b, m, n, k, compute_type);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_Softmax(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                      uint32_t n_elements) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_Softmax(backend, output, input, n_elements);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_SwiGLU(GPUBackend* backend, GPUTensor* output,
                     const GPUTensor* gate, const GPUTensor* up, uint32_t n_elements) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_SwiGLU(backend, output, gate, up, n_elements);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_Add(GPUBackend* backend, GPUTensor* output,
                  const GPUTensor* a, const GPUTensor* b, uint32_t n_elements) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    
    switch (backend->type) {
        case GPU_BACKEND_VULKAN:
            return Vulkan_Add(backend, output, a, b, n_elements);
        default:
            return GPU_ERROR_UNSUPPORTED;
    }
}

GPUStatus GPU_Dequantize(GPUBackend* backend, GPUTensor* output,
                         const GPUTensor* input, GPUDataType target_type) {
    if (!backend) return GPU_ERROR_NULL_POINTER;
    return GPU_ERROR_UNSUPPORTED;  // Not yet implemented
}

// ============================================================================
// UTILITY
// ============================================================================

const char* GPU_GetErrorString(GPUStatus status) {
    switch (status) {
        case GPU_SUCCESS: return "Success";
        case GPU_ERROR: return "General error";
        case GPU_ERROR_NULL_POINTER: return "Null pointer";
        case GPU_ERROR_OUT_OF_MEMORY: return "Out of memory";
        case GPU_ERROR_DEVICE_NOT_FOUND: return "Device not found";
        case GPU_ERROR_SHADER_COMPILE: return "Shader compilation failed";
        case GPU_ERROR_KERNEL_LAUNCH: return "Kernel launch failed";
        case GPU_ERROR_UNSUPPORTED: return "Operation not supported";
        default: return "Unknown error";
    }
}

void GPU_GetDeviceStats(GPUBackend* backend, uint64_t* vram_used, uint64_t* vram_free) {
    if (!backend) {
        if (vram_used) *vram_used = 0;
        if (vram_free) *vram_free = 0;
        return;
    }
    
    if (vram_used) *vram_used = 0;  // Would track actual usage
    if (vram_free) *vram_free = backend->device_info.vram_free;
}
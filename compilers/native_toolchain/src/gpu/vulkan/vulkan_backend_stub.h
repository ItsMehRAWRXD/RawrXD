/*
 * Phase 8.3: Vulkan Backend Stub Header
 * 
 * Stub declarations for testing GPU backend interface
 * No actual Vulkan dependencies
 */

#ifndef VULKAN_BACKEND_STUB_H
#define VULKAN_BACKEND_STUB_H

#include "../gpu_backend.h"

#ifdef __cplusplus
extern "C" {
#endif

// Backend lifecycle
GPUBackend* Vulkan_BackendCreate(void);
void Vulkan_BackendDestroy(GPUBackend* backend);

// Device enumeration
int Vulkan_EnumerateDevices(GPUDeviceInfo* devices, int max_devices);

// Memory
void* Vulkan_Allocate(GPUBackend* backend, size_t size);
void Vulkan_Free(GPUBackend* backend, void* ptr);
GPUStatus Vulkan_Upload(GPUBackend* backend, GPUTensor* tensor, const void* data);
GPUStatus Vulkan_Download(GPUBackend* backend, GPUTensor* tensor, void* data);

// Synchronization
GPUStatus Vulkan_Synchronize(GPUBackend* backend);

// Kernels
GPUStatus Vulkan_RMSNorm(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                         const GPUTensor* weight, float epsilon, uint32_t n_elements);
GPUStatus Vulkan_RoPE(GPUBackend* backend, GPUTensor* query, GPUTensor* key,
                      uint32_t n_heads, uint32_t head_dim, uint32_t position, float freq_base);
GPUStatus Vulkan_Attention(GPUBackend* backend, GPUTensor* output,
                             const GPUTensor* query, const GPUTensor* key, const GPUTensor* value,
                             uint32_t n_heads, uint32_t seq_len, uint32_t head_dim);
GPUStatus Vulkan_MatMul(GPUBackend* backend, GPUTensor* output,
                          const GPUTensor* a, const GPUTensor* b,
                          uint32_t m, uint32_t n, uint32_t k, GPUDataType compute_type);
GPUStatus Vulkan_Softmax(GPUBackend* backend, GPUTensor* output, const GPUTensor* input,
                         uint32_t n_elements);
GPUStatus Vulkan_SwiGLU(GPUBackend* backend, GPUTensor* output,
                          const GPUTensor* gate, const GPUTensor* up, uint32_t n_elements);
GPUStatus Vulkan_Add(GPUBackend* backend, GPUTensor* output,
                     const GPUTensor* a, const GPUTensor* b, uint32_t n_elements);

#ifdef __cplusplus
}
#endif

#endif // VULKAN_BACKEND_STUB_H

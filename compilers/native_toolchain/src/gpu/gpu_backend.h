// gpu_backend.h - GPU Backend Abstraction Layer
// Phase 8.3 - Hardware Acceleration for Transformer Inference
// Supports: Vulkan Compute (primary), DirectML, CUDA

#ifndef GPU_BACKEND_H
#define GPU_BACKEND_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// EXPORT MACROS
// ============================================================================

#ifdef GPU_BACKEND_EXPORTS
#define GPU_BACKEND_API __declspec(dllexport)
#else
#define GPU_BACKEND_API __declspec(dllimport)
#endif

// ============================================================================
// STATUS CODES
// ============================================================================

typedef enum {
    GPU_SUCCESS = 0,
    GPU_ERROR = -1,
    GPU_ERROR_NULL_POINTER = -2,
    GPU_ERROR_OUT_OF_MEMORY = -3,
    GPU_ERROR_DEVICE_NOT_FOUND = -4,
    GPU_ERROR_SHADER_COMPILE = -5,
    GPU_ERROR_KERNEL_LAUNCH = -6,
    GPU_ERROR_UNSUPPORTED = -7
} GPUStatus;

// ============================================================================
// BACKEND TYPES
// ============================================================================

typedef enum {
    GPU_BACKEND_VULKAN = 0,     // Primary: Vulkan Compute
    GPU_BACKEND_DIRECTML = 1,   // Windows: DirectML
    GPU_BACKEND_CUDA = 2,       // Optional: NVIDIA CUDA
    GPU_BACKEND_COUNT
} GPUBackendType;

typedef enum {
    GPU_FLOAT32 = 0,
    GPU_FLOAT16 = 1,
    GPU_INT32 = 2,
    GPU_INT16 = 3,
    GPU_Q4_0 = 4,       // 4-bit quantized
    GPU_Q4_1 = 5,
    GPU_Q8_0 = 6        // 8-bit quantized
} GPUDataType;

// ============================================================================
// DEVICE INFO
// ============================================================================

typedef struct {
    char name[256];
    uint32_t vendor_id;
    uint32_t device_id;
    uint64_t vram_size;
    uint64_t vram_free;
    uint32_t compute_units;
    uint32_t max_workgroup_size;
    int supports_fp16;
    int supports_int8;
} GPUDeviceInfo;

// ============================================================================
// TENSOR HANDLE
// ============================================================================

typedef struct {
    void* device_data;
    void* staging_data;
    size_t size;
    GPUDataType dtype;
    uint32_t dims[4];
    uint32_t n_dims;
    int is_on_gpu;
} GPUTensor;

// ============================================================================
// BACKEND CONTEXT
// ============================================================================

typedef struct GPUBackend GPUBackend;

struct GPUBackend {
    GPUBackendType type;
    GPUDeviceInfo device_info;
    
    // Device management
    void* device;
    void* context;
    void* command_queue;
    
    // Memory management
    void* (*allocate)(GPUBackend* backend, size_t size);
    void (*free)(GPUBackend* backend, void* ptr);
    GPUStatus (*upload)(GPUBackend* backend, GPUTensor* tensor, const void* data);
    GPUStatus (*download)(GPUBackend* backend, GPUTensor* tensor, void* data);
    
    // Synchronization
    GPUStatus (*synchronize)(GPUBackend* backend);
    
    // Backend-specific cleanup
    void (*destroy)(GPUBackend* backend);
};

// ============================================================================
// KERNEL SIGNATURES
// ============================================================================

typedef struct {
    uint32_t x, y, z;
} GPUWorkgroupSize;

// ============================================================================
// API FUNCTIONS
// ============================================================================

// Backend factory
GPU_BACKEND_API GPUBackend* GPU_BackendCreate(GPUBackendType type);
GPU_BACKEND_API void GPU_BackendDestroy(GPUBackend* backend);

// Device enumeration
GPU_BACKEND_API int GPU_EnumerateDevices(GPUBackendType type, GPUDeviceInfo* devices, int max_devices);
GPU_BACKEND_API const char* GPU_GetBackendName(GPUBackendType type);

// Tensor management
GPU_BACKEND_API GPUTensor* GPU_TensorCreate(GPUBackend* backend, const uint32_t* dims, uint32_t n_dims, GPUDataType dtype);
GPU_BACKEND_API void GPU_TensorDestroy(GPUBackend* backend, GPUTensor* tensor);
GPU_BACKEND_API GPUStatus GPU_TensorUpload(GPUBackend* backend, GPUTensor* tensor, const void* data);
GPU_BACKEND_API GPUStatus GPU_TensorDownload(GPUBackend* backend, GPUTensor* tensor, void* data);

// ============================================================================
// TRANSFORMER KERNELS (G12-G14)
// ============================================================================

// RMSNorm: output = input * weight / sqrt(mean(input^2) + eps)
GPU_BACKEND_API GPUStatus GPU_RMSNorm(GPUBackend* backend,
                                       GPUTensor* output,
                                       const GPUTensor* input,
                                       const GPUTensor* weight,
                                       float epsilon,
                                       uint32_t n_elements);

// RoPE (Rotary Position Embedding)
GPU_BACKEND_API GPUStatus GPU_RoPE(GPUBackend* backend,
                                    GPUTensor* query,
                                    GPUTensor* key,
                                    uint32_t n_heads,
                                    uint32_t head_dim,
                                    uint32_t position,
                                    float freq_base);

// Multi-head Attention
GPU_BACKEND_API GPUStatus GPU_Attention(GPUBackend* backend,
                                         GPUTensor* output,
                                         const GPUTensor* query,
                                         const GPUTensor* key,
                                         const GPUTensor* value,
                                         uint32_t n_heads,
                                         uint32_t seq_len,
                                         uint32_t head_dim);

// Matrix Multiplication (supports quantized)
GPU_BACKEND_API GPUStatus GPU_MatMul(GPUBackend* backend,
                                      GPUTensor* output,
                                      const GPUTensor* a,
                                      const GPUTensor* b,
                                      uint32_t m, uint32_t n, uint32_t k,
                                      GPUDataType compute_type);

// Softmax
GPU_BACKEND_API GPUStatus GPU_Softmax(GPUBackend* backend,
                                       GPUTensor* output,
                                       const GPUTensor* input,
                                       uint32_t n_elements);

// SwiGLU FFN activation
GPU_BACKEND_API GPUStatus GPU_SwiGLU(GPUBackend* backend,
                                      GPUTensor* output,
                                      const GPUTensor* gate,
                                      const GPUTensor* up,
                                      uint32_t n_elements);

// Element-wise Add
GPU_BACKEND_API GPUStatus GPU_Add(GPUBackend* backend,
                                   GPUTensor* output,
                                   const GPUTensor* a,
                                   const GPUTensor* b,
                                   uint32_t n_elements);

// Quantized decompression
GPU_BACKEND_API GPUStatus GPU_Dequantize(GPUBackend* backend,
                                          GPUTensor* output,
                                          const GPUTensor* input,
                                          GPUDataType target_type);

// ============================================================================
// UTILITY
// ============================================================================

GPU_BACKEND_API const char* GPU_GetErrorString(GPUStatus status);
GPU_BACKEND_API void GPU_GetDeviceStats(GPUBackend* backend, uint64_t* vram_used, uint64_t* vram_free);

#ifdef __cplusplus
}
#endif

#endif // GPU_BACKEND_H
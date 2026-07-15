//==============================================================================
// Titan_KernelIntegration.h
// C API for Titan Kernel Integration with Sovereign
//
// Date: July 10, 2026
// Status: PRODUCTION
//==============================================================================

#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
// Kernel Identifiers (64-bit hashes)
//==============================================================================

#define KERNEL_RMSNORM_F32          0x524D534E4F524D00ULL
#define KERNEL_LAYERNORM_F32        0x4C415945524E4F00ULL
#define KERNEL_ROPE_APPLY           0x524F504550504C00ULL
#define KERNEL_RESIDUAL_ADD         0x5245534944554100ULL
#define KERNEL_Q4K_DEQUANT          0x51344B44455100ULL
#define KERNEL_Q4Q8_MATMUL          0x513451384D4D00ULL
#define KERNEL_FLASH_ATTENTION      0x464C415348415400ULL
#define KERNEL_MATMUL_INTRINSICS    0x4D4D494E545200ULL
#define KERNEL_FLASHATTN_INTRINSICS 0x4641494E545200ULL

//==============================================================================
// Descriptor Structures
//==============================================================================

#pragma pack(push, 8)

typedef struct {
    uint64_t kernelName;
    uint32_t gridDimX;
    uint32_t gridDimY;
    uint32_t gridDimZ;
    uint32_t blockDimX;
    uint32_t blockDimY;
    uint32_t blockDimZ;
    uint32_t sharedMemSize;
    uint64_t stream;
    uint64_t inputBuffer;
    uint64_t inputSize;
    uint64_t outputBuffer;
    uint64_t outputSize;
    uint32_t paramCount;
    uint64_t paramData;
    uint32_t launchStatus;
    uint64_t executionTimeUs;
} GPU_KERNEL_DESCRIPTOR;

typedef struct {
    uint32_t operationType;
    uint64_t sourceBuffer;
    uint64_t destBuffer;
    uint64_t transferSize;
    uint64_t startTimeUs;
    uint64_t endTimeUs;
    uint32_t throughputMBps;
    uint32_t status;
    uint32_t errorCode;
    uint64_t callbackFunc;
    uint64_t callbackData;
    uint64_t pinnedMemoryId;
    uint64_t stagingBufferId;
} GPU_COPY_OPERATION;

// Parameter structures
typedef struct {
    float* input;
    float* output;
    float* weight;
    size_t n_elements;
    float epsilon;
} RMSNormParams;

typedef struct {
    float* input;
    float* output;
    float* gamma;
    float* beta;
    size_t n_elements;
    float epsilon;
} LayerNormParams;

typedef struct {
    float* tensor;
    float* freq_cache;
    size_t seq_len;
    size_t head_dim;
    size_t num_heads;
} RoPEParams;

typedef struct {
    float* input;
    float* residual;
    float* output;
    size_t n_elements;
    float scale_factor;
} ResidualAddParams;

typedef struct {
    const void* tensor_data;
    float* output;
    size_t num_elements;
    const void* tensor_info;
} Q4KDequantParams;

typedef struct {
    const void* A;
    const void* B;
    float* C;
    size_t m;
    size_t n;
    size_t k;
} Q4Q8MatMulParams;

typedef struct {
    float* Q;
    float* K;
    float* V;
    float* output;
    size_t seq_len;
    size_t head_dim;
} FlashAttentionParams;

#pragma pack(pop)

//==============================================================================
// C API Functions
//==============================================================================

// Initialize the kernel system (must be called before any kernel execution)
int Titan_InitializeKernelSystem(void);

// Execute a compute kernel (dispatches to real Sovereign kernels)
int Titan_ExecuteComputeKernel(GPU_KERNEL_DESCRIPTOR* desc, void* resultBuffer, size_t resultSize);

// Perform a copy operation
int Titan_PerformCopy(GPU_COPY_OPERATION* op, uint32_t flags);

// Get kernel version string
const char* Titan_GetKernelVersion(void);

// Check if a specific kernel is available
bool Titan_IsKernelAvailable(uint64_t kernelName);

// Get performance stats for a kernel
bool Titan_GetKernelStats(uint64_t kernelName, uint64_t* avgTimeUs, uint64_t* totalCalls);

//==============================================================================
// Error Codes
//==============================================================================

#define TITAN_SUCCESS               0
#define TITAN_ERROR_INIT_FAILED     1
#define TITAN_ERROR_KERNEL_MISSING  2
#define TITAN_ERROR_INVALID_PARAM   87
#define TITAN_ERROR_INVALID_HANDLE  6
#define TITAN_ERROR_INVALID_DATA    13
#define TITAN_ERROR_BAD_DRIVER      115
#define TITAN_ERROR_PROC_NOT_FOUND  127

#ifdef __cplusplus
}
#endif

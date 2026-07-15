// =============================================================================
// sovereign_hybrid_scheduler.h
// Hybrid Auto Scheduler - Header
// Phase 17: Hybrid Auto / AMX Optimizations
// =============================================================================

#ifndef SOVEREIGN_HYBRID_SCHEDULER_H
#define SOVEREIGN_HYBRID_SCHEDULER_H

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Workload Types
// =============================================================================

typedef enum {
    SOVEREIGN_WORKLOAD_ATTENTION_QK = 0,
    SOVEREIGN_WORKLOAD_ATTENTION_SOFTMAX_V = 1,
    SOVEREIGN_WORKLOAD_FFN_UP_PROJECTION = 2,
    SOVEREIGN_WORKLOAD_FFN_DOWN_PROJECTION = 3,
    SOVEREIGN_WORKLOAD_EMBEDDING_LOOKUP = 4,
    SOVEREIGN_WORKLOAD_RMS_NORM = 5,
    SOVEREIGN_WORKLOAD_ROPE = 6,
    SOVEREIGN_WORKLOAD_UNKNOWN = 7
} SovereignWorkloadType;

// =============================================================================
// Compute Paths
// =============================================================================

typedef enum {
    SOVEREIGN_PATH_AMX_TILE = 0,
    SOVEREIGN_PATH_AVX512_VNNI = 1,
    SOVEREIGN_PATH_AVX512_FMA = 2,
    SOVEREIGN_PATH_AVX2_FMA = 3,
    SOVEREIGN_PATH_SCALAR = 4,
    SOVEREIGN_PATH_GPU_COMPUTE = 5,
    SOVEREIGN_PATH_COUNT = 6
} SovereignComputePath;

// =============================================================================
// CPU Feature Flags
// =============================================================================

#define SOVEREIGN_CPU_AMX_TILE      0x01
#define SOVEREIGN_CPU_AMX_BF16      0x02
#define SOVEREIGN_CPU_AVX512F       0x04
#define SOVEREIGN_CPU_AVX512_VNNI   0x08
#define SOVEREIGN_CPU_AVX2          0x10
#define SOVEREIGN_CPU_FMA           0x20

// =============================================================================
// API Functions
// =============================================================================

// Initialize the hybrid scheduler and detect CPU features
__declspec(dllexport) void Sovereign_Hybrid_Init(void);

// Select optimal compute path for a workload
// Returns: SovereignComputePath value
__declspec(dllexport) int Sovereign_Hybrid_SelectPath(int workloadType,
                                                       uint32_t batchSize,
                                                       uint32_t seqLen,
                                                       uint32_t headDim);

// Record performance metrics for adaptive path selection
__declspec(dllexport) void Sovereign_Hybrid_RecordMetrics(int workloadType,
                                                           int usedPath,
                                                           float latencyMs,
                                                           int success);

// Print performance statistics
__declspec(dllexport) void Sovereign_Hybrid_PrintStats(void);

// Get detected CPU features as bit flags
__declspec(dllexport) int Sovereign_Hybrid_GetCPUFeatures(void);

// =============================================================================
// AMX Kernel Exports (from Sovereign_AMX_Kernels.asm)
// =============================================================================

// Detect AMX support
// Returns: 0 = success, non-zero = error code
__declspec(dllexport) int Sovereign_AMX_Detect(void);

// Initialize AMX tile configuration
// Returns: 0 = success
__declspec(dllexport) int Sovereign_AMX_Init(void);

// AMX Attention Q×K^T kernel
// RCX = Q matrix, RDX = K matrix, R8 = output, R9 = seq_len, [RSP+0x28] = head_dim
__declspec(dllexport) int Sovereign_AMX_AttentionQK(void* q, void* k, void* output,
                                                     uint32_t seqLen, uint32_t headDim);

// AMX FFN GEMM kernel
// RCX = input, RDX = weights, R8 = output, R9 = batch, [RSP+0x28] = in_feat, [RSP+0x30] = out_feat
__declspec(dllexport) int Sovereign_AMX_FFN_GEMM(void* input, void* weights, void* output,
                                                    uint32_t batchSize, uint32_t inFeatures,
                                                    uint32_t outFeatures);

// Release AMX resources
__declspec(dllexport) void Sovereign_AMX_Cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_HYBRID_SCHEDULER_H

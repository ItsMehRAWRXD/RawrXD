// rawramxd_fabric.h - RawRamXD Fabric Integration Layer
// Phase 8.2 - VRAM Residency, RAM Spill, Predictive Prefetch, Tensor Migration
// NO DEPENDENCIES - Pure Win32 API

#ifndef RAWRAMXD_FABRIC_H
#define RAWRAMXD_FABRIC_H

#include <stdint.h>
#include <stddef.h>

// Windows types for handles
#ifndef _WIN32
    typedef void* HANDLE;
    typedef struct _CRITICAL_SECTION *PCRITICAL_SECTION;
    typedef PCRITICAL_SECTION CRITICAL_SECTION;
#else
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// EXPORT MACROS
// ============================================================================

#ifdef RAWRAMXD_FABRIC_EXPORTS
#define RAWRAMXD_FABRIC_API __declspec(dllexport)
#else
#define RAWRAMXD_FABRIC_API __declspec(dllimport)
#endif

// ============================================================================
// STATUS CODES
// ============================================================================

typedef enum {
    RAWRAMXD_SUCCESS = 0,
    RAWRAMXD_ERROR = -1,
    RAWRAMXD_ERROR_NULL_POINTER = -2,
    RAWRAMXD_ERROR_OUT_OF_MEMORY = -3,
    RAWRAMXD_ERROR_GPU_NOT_AVAILABLE = -4,
    RAWRAMXD_ERROR_TENSOR_NOT_FOUND = -5,
    RAWRAMXD_ERROR_MIGRATION_FAILED = -6,
    RAWRAMXD_ERROR_RESIDENCY_FAILED = -7
} RawRamXDStatus;

// ============================================================================
// MEMORY TIERS
// ============================================================================

typedef enum {
    MEMORY_TIER_CPU = 0,        // System RAM
    MEMORY_TIER_GPU_VRAM = 1,   // GPU Video RAM
    MEMORY_TIER_NUMA_NODE = 2,  // NUMA-local memory
    MEMORY_TIER_DISK_CACHE = 3  // Disk-backed cache
} MemoryTier;

// ============================================================================
// TENSOR RESIDENCY
// ============================================================================

typedef enum {
    RESIDENCY_CPU_ONLY = 0,           // CPU resident only
    RESIDENCY_GPU_ONLY = 1,           // GPU resident only
    RESIDENCY_CPU_GPU_MIRROR = 2,     // Both CPU and GPU
    RESIDENCY_GPU_WITH_CPU_SPILL = 3, // GPU primary, CPU backup
    RESIDENCY_PREDICTED = 4           // Predicted future access
} ResidencyMode;

typedef struct {
    const char* tensor_name;
    void* cpu_data;
    void* gpu_data;
    size_t size;
    MemoryTier current_tier;
    ResidencyMode mode;
    
    // Access tracking
    uint64_t last_access_time;
    uint64_t access_count;
    float access_frequency;
    
    // Migration state
    int is_migrating;
    int migration_priority;
    
    // Predictive prefetch
    int prefetch_score;
    uint64_t predicted_next_access;
} TensorResidency;

// ============================================================================
// FABRIC CONTEXT
// ============================================================================

typedef struct {
    // Memory pools
    void* cpu_pool;
    void* gpu_pool;
    size_t cpu_pool_size;
    size_t gpu_pool_size;
    size_t cpu_used;
    size_t gpu_used;
    
    // Tensor registry
    TensorResidency* tensors;
    int n_tensors;
    int max_tensors;
    
    // GPU context (if available)
    void* gpu_context;
    int gpu_available;
    size_t gpu_vram_size;
    size_t gpu_vram_free;
    
    // Migration queue
    struct {
        TensorResidency** pending;
        int n_pending;
        int max_pending;
    } migration_queue;
    
    // Prefetch predictor
    struct {
        uint64_t* access_history;
        int history_size;
        int history_pos;
        float* prediction_weights;
    } predictor;
    
    // Statistics
    uint64_t total_migrations;
    uint64_t total_prefetches;
    uint64_t cache_hits;
    uint64_t cache_misses;
    float avg_migration_time_ms;
    
    // Threading
    HANDLE hWorkerThread;
    HANDLE hMigrationEvent;
    int worker_running;
    
    // Synchronization
    CRITICAL_SECTION cs;
} RawRamXDFabric;

// ============================================================================
// FABRIC LIFECYCLE
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDFabric* RawRamXD_FabricCreate(void);
RAWRAMXD_FABRIC_API void RawRamXD_FabricDestroy(RawRamXDFabric* fabric);
RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_FabricInitialize(RawRamXDFabric* fabric);

// ============================================================================
// TENSOR REGISTRATION
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RegisterTensor(
    RawRamXDFabric* fabric,
    const char* name,
    void* cpu_data,
    size_t size,
    ResidencyMode mode
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_UnregisterTensor(
    RawRamXDFabric* fabric,
    const char* name
);

RAWRAMXD_FABRIC_API TensorResidency* RawRamXD_GetTensorResidency(
    RawRamXDFabric* fabric,
    const char* name
);

// ============================================================================
// VRAM RESIDENCY (G8)
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_AllocateGPU(
    RawRamXDFabric* fabric,
    size_t size,
    void** gpu_ptr
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_FreeGPU(
    RawRamXDFabric* fabric,
    void* gpu_ptr
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SetResidency(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    ResidencyMode mode
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PromoteToGPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_GetGPUStats(
    RawRamXDFabric* fabric,
    size_t* total_vram,
    size_t* free_vram,
    size_t* used_vram
);

// ============================================================================
// RAM SPILL (G9)
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SpillToCPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RestoreFromCPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SetSpillThreshold(
    RawRamXDFabric* fabric,
    float gpu_threshold_percent
);

RAWRAMXD_FABRIC_API int RawRamXD_ShouldSpill(
    RawRamXDFabric* fabric,
    size_t requested_size
);

// ============================================================================
// PREDICTIVE PREFETCH (G10)
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RecordAccess(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PredictNextAccess(
    RawRamXDFabric* fabric,
    char* predicted_tensor,
    size_t max_len
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PrefetchTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_EnablePrefetching(
    RawRamXDFabric* fabric,
    int enable
);

RAWRAMXD_FABRIC_API float RawRamXD_GetPredictionAccuracy(
    RawRamXDFabric* fabric
);

// ============================================================================
// TENSOR MIGRATION (G11)
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_MigrateTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier target_tier
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_MigrateAsync(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier target_tier
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_WaitForMigration(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_BatchMigrate(
    RawRamXDFabric* fabric,
    const char** tensor_names,
    int n_tensors,
    MemoryTier target_tier
);

// ============================================================================
// ACCESS PATTERNS
// ============================================================================

RAWRAMXD_FABRIC_API void* RawRamXD_AccessTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier* actual_tier
);

RAWRAMXD_FABRIC_API void* RawRamXD_AccessTensorForCompute(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    int prefer_gpu
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_ReleaseTensorAccess(
    RawRamXDFabric* fabric,
    const char* tensor_name
);

// ============================================================================
// STATISTICS
// ============================================================================

RAWRAMXD_FABRIC_API void RawRamXD_GetStats(
    RawRamXDFabric* fabric,
    uint64_t* total_migrations,
    uint64_t* total_prefetches,
    uint64_t* cache_hits,
    uint64_t* cache_misses,
    float* hit_rate
);

RAWRAMXD_FABRIC_API void RawRamXD_PrintStats(
    RawRamXDFabric* fabric
);

RAWRAMXD_FABRIC_API void RawRamXD_ResetStats(
    RawRamXDFabric* fabric
);

// ============================================================================
// INTEGRATION WITH SOVEREIGN RUNTIME
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_AttachToRuntime(
    RawRamXDFabric* fabric,
    void* sovereign_runtime
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RegisterModelTensors(
    RawRamXDFabric* fabric,
    void* model_context
);

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_OptimizeForInference(
    RawRamXDFabric* fabric,
    int n_layers,
    int batch_size
);

#ifdef __cplusplus
}
#endif

#endif // RAWRAMXD_FABRIC_H
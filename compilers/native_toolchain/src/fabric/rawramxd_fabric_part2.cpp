// rawramxd_fabric_part2.cpp - RawRamXD Fabric Implementation (Part 2)
// Phase 8.2 - RAM Spill, Predictive Prefetch, Tensor Migration
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include "rawramxd_fabric.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Shared utilities (also defined in rawramxd_fabric.cpp)
static uint64_t get_timestamp_ms(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000LL / freq.QuadPart);
}

// ============================================================================
// G9: RAM SPILL
// ============================================================================

static float g_spill_threshold = 90.0f;

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SpillToCPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    TensorResidency* tensor = NULL;
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
            tensor = &fabric->tensors[i];
            break;
        }
    }
    
    if (!tensor) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
    }
    
    if (!tensor->gpu_data) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_SUCCESS; // Already on CPU
    }
    
    // Copy data from GPU to CPU (if not already mirrored)
    if (tensor->mode != RESIDENCY_CPU_GPU_MIRROR) {
        memcpy(tensor->cpu_data, tensor->gpu_data, tensor->size);
    }
    
    // Free GPU memory
    RawRamXD_FreeGPU(fabric, tensor->gpu_data);
    tensor->current_tier = MEMORY_TIER_CPU;
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RestoreFromCPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    TensorResidency* tensor = NULL;
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
            tensor = &fabric->tensors[i];
            break;
        }
    }
    
    if (!tensor) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
    }
    
    if (tensor->gpu_data) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_SUCCESS; // Already on GPU
    }
    
    // Allocate GPU memory
    void* gpu_ptr = NULL;
    RawRamXDStatus status = RawRamXD_AllocateGPU(fabric, tensor->size, &gpu_ptr);
    if (status != RAWRAMXD_SUCCESS) {
        LeaveCriticalSection(&fabric->cs);
        return status;
    }
    
    // Copy data from CPU to GPU
    memcpy(gpu_ptr, tensor->cpu_data, tensor->size);
    tensor->gpu_data = gpu_ptr;
    tensor->current_tier = MEMORY_TIER_GPU_VRAM;
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SetSpillThreshold(
    RawRamXDFabric* fabric,
    float gpu_threshold_percent
) {
    if (!fabric) return RAWRAMXD_ERROR_NULL_POINTER;
    if (gpu_threshold_percent < 0.0f || gpu_threshold_percent > 100.0f) {
        return RAWRAMXD_ERROR;
    }
    
    g_spill_threshold = gpu_threshold_percent;
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API int RawRamXD_ShouldSpill(
    RawRamXDFabric* fabric,
    size_t requested_size
) {
    if (!fabric) return 0;
    
    if (!fabric->gpu_available) return 0;
    
    float used_percent = 100.0f * (float)(fabric->gpu_vram_size - fabric->gpu_vram_free + requested_size) 
                         / (float)fabric->gpu_vram_size;
    
    return used_percent > g_spill_threshold;
}

// ============================================================================
// G10: PREDICTIVE PREFETCH
// ============================================================================

static int g_prefetch_enabled = 1;

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RecordAccess(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    // Find tensor
    int tensor_idx = -1;
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
            tensor_idx = i;
            break;
        }
    }
    
    if (tensor_idx < 0) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
    }
    
    TensorResidency* tensor = &fabric->tensors[tensor_idx];
    
    // Update access tracking
    uint64_t now = get_timestamp_ms();
    tensor->last_access_time = now;
    tensor->access_count++;
    
    // Calculate access frequency (accesses per second)
    if (tensor->access_count > 1) {
        float elapsed_sec = (now - fabric->predictor.access_history[0]) / 1000.0f;
        if (elapsed_sec > 0) {
            tensor->access_frequency = tensor->access_count / elapsed_sec;
        }
    }
    
    // Record in history
    fabric->predictor.access_history[fabric->predictor.history_pos] = tensor_idx;
    fabric->predictor.history_pos = (fabric->predictor.history_pos + 1) % fabric->predictor.history_size;
    
    // Update prediction weights based on access patterns
    // Simple heuristic: tensors accessed recently are more likely to be accessed again
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (i == tensor_idx) continue;
        
        // Check if this tensor was accessed in sequence
        int in_sequence = 0;
        for (int h = 0; h < 10 && h < fabric->predictor.history_size; h++) {
            int idx = (fabric->predictor.history_pos - h - 1 + fabric->predictor.history_size) 
                      % fabric->predictor.history_size;
            if (fabric->predictor.access_history[idx] == i) {
                in_sequence = 1;
                break;
            }
        }
        
        if (in_sequence) {
            fabric->predictor.prediction_weights[i] += 0.1f;
            if (fabric->predictor.prediction_weights[i] > 1.0f) {
                fabric->predictor.prediction_weights[i] = 1.0f;
            }
        }
    }
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PredictNextAccess(
    RawRamXDFabric* fabric,
    char* predicted_tensor,
    size_t max_len
) {
    if (!fabric || !predicted_tensor) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    // Find tensor with highest prediction weight
    int best_idx = -1;
    float best_weight = 0.0f;
    
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->predictor.prediction_weights[i] > best_weight) {
            // Only predict tensors not already on GPU
            if (fabric->tensors[i].current_tier != MEMORY_TIER_GPU_VRAM) {
                best_weight = fabric->predictor.prediction_weights[i];
                best_idx = i;
            }
        }
    }
    
    if (best_idx >= 0) {
        strncpy(predicted_tensor, fabric->tensors[best_idx].tensor_name, max_len - 1);
        predicted_tensor[max_len - 1] = '\0';
        
        // Decay weight after prediction
        fabric->predictor.prediction_weights[best_idx] *= 0.5f;
    } else {
        predicted_tensor[0] = '\0';
    }
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PrefetchTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    if (!g_prefetch_enabled) return RAWRAMXD_SUCCESS;
    
    // Simply promote to GPU
    RawRamXDStatus status = RawRamXD_PromoteToGPU(fabric, tensor_name);
    
    if (status == RAWRAMXD_SUCCESS) {
        fabric->total_prefetches++;
    }
    
    return status;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_EnablePrefetching(
    RawRamXDFabric* fabric,
    int enable
) {
    g_prefetch_enabled = enable;
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API float RawRamXD_GetPredictionAccuracy(
    RawRamXDFabric* fabric
) {
    if (!fabric) return 0.0f;
    
    uint64_t total = fabric->cache_hits + fabric->cache_misses;
    if (total == 0) return 0.0f;
    
    return (float)fabric->cache_hits / (float)total;
}

// ============================================================================
// G11: TENSOR MIGRATION
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_MigrateTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier target_tier
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    uint64_t start_time = get_timestamp_ms();
    
    RawRamXDStatus status;
    
    switch (target_tier) {
        case MEMORY_TIER_CPU:
            status = RawRamXD_SpillToCPU(fabric, tensor_name);
            break;
            
        case MEMORY_TIER_GPU_VRAM:
            status = RawRamXD_RestoreFromCPU(fabric, tensor_name);
            break;
            
        default:
            status = RAWRAMXD_ERROR;
            break;
    }
    
    if (status == RAWRAMXD_SUCCESS) {
        fabric->total_migrations++;
        
        // Update average migration time
        uint64_t elapsed = get_timestamp_ms() - start_time;
        fabric->avg_migration_time_ms = 
            (fabric->avg_migration_time_ms * (fabric->total_migrations - 1) + elapsed) 
            / fabric->total_migrations;
    }
    
    return status;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_MigrateAsync(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier target_tier
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    // Find tensor
    TensorResidency* tensor = NULL;
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
            tensor = &fabric->tensors[i];
            break;
        }
    }
    
    if (!tensor) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
    }
    
    // Add to migration queue
    if (fabric->migration_queue.n_pending < fabric->migration_queue.max_pending) {
        tensor->is_migrating = 1;
        tensor->migration_priority = (target_tier == MEMORY_TIER_GPU_VRAM) ? 1 : 0;
        fabric->migration_queue.pending[fabric->migration_queue.n_pending++] = tensor;
        
        // Signal worker thread
        SetEvent(fabric->hMigrationEvent);
    }
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_WaitForMigration(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    if (!fabric || !tensor_name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    // Poll until migration completes
    int max_wait_ms = 10000; // 10 second timeout
    int waited_ms = 0;
    
    while (waited_ms < max_wait_ms) {
        EnterCriticalSection(&fabric->cs);
        
        TensorResidency* tensor = NULL;
        for (int i = 0; i < fabric->n_tensors; i++) {
            if (fabric->tensors[i].tensor_name && 
                strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
                tensor = &fabric->tensors[i];
                break;
            }
        }
        
        if (!tensor || !tensor->is_migrating) {
            LeaveCriticalSection(&fabric->cs);
            return RAWRAMXD_SUCCESS;
        }
        
        LeaveCriticalSection(&fabric->cs);
        
        Sleep(10);
        waited_ms += 10;
    }
    
    return RAWRAMXD_ERROR_MIGRATION_FAILED;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_BatchMigrate(
    RawRamXDFabric* fabric,
    const char** tensor_names,
    int n_tensors,
    MemoryTier target_tier
) {
    if (!fabric || !tensor_names) return RAWRAMXD_ERROR_NULL_POINTER;
    
    RawRamXDStatus last_status = RAWRAMXD_SUCCESS;
    
    for (int i = 0; i < n_tensors; i++) {
        RawRamXDStatus status = RawRamXD_MigrateTensor(fabric, tensor_names[i], target_tier);
        if (status != RAWRAMXD_SUCCESS) {
            last_status = status;
        }
    }
    
    return last_status;
}

// ============================================================================
// ACCESS PATTERNS
// ============================================================================

RAWRAMXD_FABRIC_API void* RawRamXD_AccessTensor(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    MemoryTier* actual_tier
) {
    if (!fabric || !tensor_name) return NULL;
    
    // Record access for prediction
    RawRamXD_RecordAccess(fabric, tensor_name);
    
    EnterCriticalSection(&fabric->cs);
    
    TensorResidency* tensor = NULL;
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, tensor_name) == 0) {
            tensor = &fabric->tensors[i];
            break;
        }
    }
    
    if (!tensor) {
        LeaveCriticalSection(&fabric->cs);
        fabric->cache_misses++;
        return NULL;
    }
    
    // Check if we need to restore from spill
    if (tensor->current_tier == MEMORY_TIER_CPU && tensor->mode == RESIDENCY_GPU_WITH_CPU_SPILL) {
        // Async restore
        RawRamXD_RestoreFromCPU(fabric, tensor_name);
    }
    
    // Return appropriate pointer
    void* data = NULL;
    if (tensor->current_tier == MEMORY_TIER_GPU_VRAM && tensor->gpu_data) {
        data = tensor->gpu_data;
        if (actual_tier) *actual_tier = MEMORY_TIER_GPU_VRAM;
        fabric->cache_hits++;
    } else {
        data = tensor->cpu_data;
        if (actual_tier) *actual_tier = MEMORY_TIER_CPU;
        fabric->cache_hits++;
    }
    
    LeaveCriticalSection(&fabric->cs);
    
    return data;
}

RAWRAMXD_FABRIC_API void* RawRamXD_AccessTensorForCompute(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    int prefer_gpu
) {
    MemoryTier tier;
    void* data = RawRamXD_AccessTensor(fabric, tensor_name, &tier);
    
    if (!data) return NULL;
    
    // If we prefer GPU but tensor is on CPU, try to migrate
    if (prefer_gpu && tier == MEMORY_TIER_CPU && fabric->gpu_available) {
        RawRamXDStatus status = RawRamXD_RestoreFromCPU(fabric, tensor_name);
        if (status == RAWRAMXD_SUCCESS) {
            // Re-access to get GPU pointer
            data = RawRamXD_AccessTensor(fabric, tensor_name, &tier);
        }
    }
    
    return data;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_ReleaseTensorAccess(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    // In this implementation, access is non-exclusive
    // Real implementation might track readers/writers
    return RAWRAMXD_SUCCESS;
}
// rawramxd_fabric.cpp - RawRamXD Fabric Implementation
// Phase 8.2 - VRAM Residency, RAM Spill, Predictive Prefetch, Tensor Migration
// NO DEPENDENCIES - Pure Win32 API

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define RAWRAMXD_FABRIC_EXPORTS

#include "rawramxd_fabric.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define MAX_TENSORS 4096
#define MAX_TENSOR_NAME_LEN 256
#define PREFETCH_HISTORY_SIZE 1024
#define MIGRATION_QUEUE_SIZE 256
#define GPU_MEMORY_THRESHOLD_PERCENT 90.0f

// ============================================================================
// INTERNAL UTILITIES
// ============================================================================

static uint64_t get_timestamp_ns(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (uint64_t)(count.QuadPart * 1000000000LL / freq.QuadPart);
}

static uint64_t get_timestamp_ms(void) {
    return get_timestamp_ns() / 1000000;
}

static void* aligned_alloc(size_t size, size_t alignment) {
    return _aligned_malloc(size, alignment);
}

static void aligned_free(void* ptr) {
    _aligned_free(ptr);
}

// ============================================================================
// FABRIC LIFECYCLE
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDFabric* RawRamXD_FabricCreate(void) {
    RawRamXDFabric* fabric = (RawRamXDFabric*)malloc(sizeof(RawRamXDFabric));
    if (!fabric) {
        return NULL;
    }
    
    memset(fabric, 0, sizeof(RawRamXDFabric));
    
    // Initialize tensor registry
    fabric->max_tensors = MAX_TENSORS;
    fabric->tensors = (TensorResidency*)calloc(MAX_TENSORS, sizeof(TensorResidency));
    if (!fabric->tensors) {
        free(fabric);
        return NULL;
    }
    
    // Initialize migration queue
    fabric->migration_queue.max_pending = MIGRATION_QUEUE_SIZE;
    fabric->migration_queue.pending = (TensorResidency**)calloc(MIGRATION_QUEUE_SIZE, sizeof(TensorResidency*));
    if (!fabric->migration_queue.pending) {
        free(fabric->tensors);
        free(fabric);
        return NULL;
    }
    
    // Initialize predictor
    fabric->predictor.history_size = PREFETCH_HISTORY_SIZE;
    fabric->predictor.access_history = (uint64_t*)calloc(PREFETCH_HISTORY_SIZE, sizeof(uint64_t));
    fabric->predictor.prediction_weights = (float*)calloc(MAX_TENSORS, sizeof(float));
    if (!fabric->predictor.access_history || !fabric->predictor.prediction_weights) {
        free(fabric->migration_queue.pending);
        free(fabric->tensors);
        free(fabric);
        return NULL;
    }
    
    // Initialize synchronization
    InitializeCriticalSection(&fabric->cs);
    
    // Create migration event
    fabric->hMigrationEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    return fabric;
}

RAWRAMXD_FABRIC_API void RawRamXD_FabricDestroy(RawRamXDFabric* fabric) {
    if (!fabric) return;
    
    // Stop worker thread
    fabric->worker_running = 0;
    if (fabric->hMigrationEvent) {
        SetEvent(fabric->hMigrationEvent);
    }
    if (fabric->hWorkerThread) {
        WaitForSingleObject(fabric->hWorkerThread, 5000);
        CloseHandle(fabric->hWorkerThread);
    }
    
    // Free GPU memory
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].gpu_data) {
            // Would free GPU memory here
            fabric->tensors[i].gpu_data = NULL;
        }
        if (fabric->tensors[i].tensor_name) {
            free((void*)fabric->tensors[i].tensor_name);
        }
    }
    
    // Cleanup
    DeleteCriticalSection(&fabric->cs);
    if (fabric->hMigrationEvent) {
        CloseHandle(fabric->hMigrationEvent);
    }
    
    free(fabric->predictor.prediction_weights);
    free(fabric->predictor.access_history);
    free(fabric->migration_queue.pending);
    free(fabric->tensors);
    free(fabric);
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_FabricInitialize(RawRamXDFabric* fabric) {
    if (!fabric) return RAWRAMXD_ERROR_NULL_POINTER;
    
    // Detect GPU availability
    // In a real implementation, this would query CUDA/Vulkan
    fabric->gpu_available = 0; // Default to CPU-only for now
    fabric->gpu_vram_size = 0;
    fabric->gpu_vram_free = 0;
    
    // Get system memory info
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    
    fabric->cpu_pool_size = memStatus.ullTotalPhys;
    fabric->cpu_used = 0;
    
    printf("[RawRamXD] Fabric initialized\n");
    printf("  CPU Memory: %llu MB\n", fabric->cpu_pool_size / (1024 * 1024));
    printf("  GPU Available: %s\n", fabric->gpu_available ? "Yes" : "No");
    
    return RAWRAMXD_SUCCESS;
}

// ============================================================================
// TENSOR REGISTRATION
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_RegisterTensor(
    RawRamXDFabric* fabric,
    const char* name,
    void* cpu_data,
    size_t size,
    ResidencyMode mode
) {
    if (!fabric || !name || !cpu_data) {
        return RAWRAMXD_ERROR_NULL_POINTER;
    }
    
    EnterCriticalSection(&fabric->cs);
    
    // Check if tensor already exists
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, name) == 0) {
            LeaveCriticalSection(&fabric->cs);
            return RAWRAMXD_ERROR; // Already registered
        }
    }
    
    // Find free slot
    if (fabric->n_tensors >= fabric->max_tensors) {
        LeaveCriticalSection(&fabric->cs);
        return RAWRAMXD_ERROR_OUT_OF_MEMORY;
    }
    
    TensorResidency* tensor = &fabric->tensors[fabric->n_tensors++];
    
    // Initialize tensor
    tensor->tensor_name = _strdup(name);
    tensor->cpu_data = cpu_data;
    tensor->gpu_data = NULL;
    tensor->size = size;
    tensor->current_tier = MEMORY_TIER_CPU;
    tensor->mode = mode;
    tensor->last_access_time = get_timestamp_ms();
    tensor->access_count = 0;
    tensor->access_frequency = 0.0f;
    tensor->is_migrating = 0;
    tensor->migration_priority = 0;
    tensor->prefetch_score = 0;
    
    // Update CPU usage
    fabric->cpu_used += size;
    
    LeaveCriticalSection(&fabric->cs);
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_UnregisterTensor(
    RawRamXDFabric* fabric,
    const char* name
) {
    if (!fabric || !name) return RAWRAMXD_ERROR_NULL_POINTER;
    
    EnterCriticalSection(&fabric->cs);
    
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, name) == 0) {
            // Free GPU memory if allocated
            if (fabric->tensors[i].gpu_data) {
                // Would free GPU memory
                fabric->gpu_used -= fabric->tensors[i].size;
            }
            
            // Update CPU usage
            fabric->cpu_used -= fabric->tensors[i].size;
            
            // Free name
            free((void*)fabric->tensors[i].tensor_name);
            
            // Shift remaining tensors
            memmove(&fabric->tensors[i], &fabric->tensors[i + 1],
                   (fabric->n_tensors - i - 1) * sizeof(TensorResidency));
            fabric->n_tensors--;
            
            LeaveCriticalSection(&fabric->cs);
            return RAWRAMXD_SUCCESS;
        }
    }
    
    LeaveCriticalSection(&fabric->cs);
    return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
}

RAWRAMXD_FABRIC_API TensorResidency* RawRamXD_GetTensorResidency(
    RawRamXDFabric* fabric,
    const char* name
) {
    if (!fabric || !name) return NULL;
    
    EnterCriticalSection(&fabric->cs);
    
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].tensor_name && 
            strcmp(fabric->tensors[i].tensor_name, name) == 0) {
            TensorResidency* result = &fabric->tensors[i];
            LeaveCriticalSection(&fabric->cs);
            return result;
        }
    }
    
    LeaveCriticalSection(&fabric->cs);
    return NULL;
}

// ============================================================================
// G8: VRAM RESIDENCY
// ============================================================================

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_AllocateGPU(
    RawRamXDFabric* fabric,
    size_t size,
    void** gpu_ptr
) {
    if (!fabric || !gpu_ptr) return RAWRAMXD_ERROR_NULL_POINTER;
    
    if (!fabric->gpu_available) {
        return RAWRAMXD_ERROR_GPU_NOT_AVAILABLE;
    }
    
    // Check if we have enough VRAM
    if (fabric->gpu_vram_free < size) {
        return RAWRAMXD_ERROR_OUT_OF_MEMORY;
    }
    
    // In a real implementation, this would allocate GPU memory via CUDA/Vulkan
    // For now, allocate CPU memory as placeholder
    *gpu_ptr = aligned_alloc(size, 64);
    if (!*gpu_ptr) {
        return RAWRAMXD_ERROR_OUT_OF_MEMORY;
    }
    
    fabric->gpu_vram_free -= size;
    fabric->gpu_used += size;
    
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_FreeGPU(
    RawRamXDFabric* fabric,
    void* gpu_ptr
) {
    if (!fabric || !gpu_ptr) return RAWRAMXD_ERROR_NULL_POINTER;
    
    // Find tensor with this GPU pointer
    EnterCriticalSection(&fabric->cs);
    
    for (int i = 0; i < fabric->n_tensors; i++) {
        if (fabric->tensors[i].gpu_data == gpu_ptr) {
            aligned_free(gpu_ptr);
            fabric->gpu_used -= fabric->tensors[i].size;
            fabric->gpu_vram_free += fabric->tensors[i].size;
            fabric->tensors[i].gpu_data = NULL;
            fabric->tensors[i].current_tier = MEMORY_TIER_CPU;
            
            LeaveCriticalSection(&fabric->cs);
            return RAWRAMXD_SUCCESS;
        }
    }
    
    LeaveCriticalSection(&fabric->cs);
    return RAWRAMXD_ERROR_TENSOR_NOT_FOUND;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_SetResidency(
    RawRamXDFabric* fabric,
    const char* tensor_name,
    ResidencyMode mode
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
    
    tensor->mode = mode;
    
    // Handle mode transitions
    switch (mode) {
        case RESIDENCY_GPU_ONLY:
        case RESIDENCY_GPU_WITH_CPU_SPILL:
            if (!tensor->gpu_data && fabric->gpu_available) {
                // Allocate GPU memory
                void* gpu_ptr = NULL;
                RawRamXDStatus status = RawRamXD_AllocateGPU(fabric, tensor->size, &gpu_ptr);
                if (status == RAWRAMXD_SUCCESS) {
                    tensor->gpu_data = gpu_ptr;
                    tensor->current_tier = MEMORY_TIER_GPU_VRAM;
                    
                    // Copy data to GPU
                    memcpy(gpu_ptr, tensor->cpu_data, tensor->size);
                }
            }
            break;
            
        case RESIDENCY_CPU_ONLY:
            if (tensor->gpu_data) {
                RawRamXD_FreeGPU(fabric, tensor->gpu_data);
            }
            tensor->current_tier = MEMORY_TIER_CPU;
            break;
            
        default:
            break;
    }
    
    LeaveCriticalSection(&fabric->cs);
    return RAWRAMXD_SUCCESS;
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_PromoteToGPU(
    RawRamXDFabric* fabric,
    const char* tensor_name
) {
    return RawRamXD_SetResidency(fabric, tensor_name, RESIDENCY_GPU_WITH_CPU_SPILL);
}

RAWRAMXD_FABRIC_API RawRamXDStatus RawRamXD_GetGPUStats(
    RawRamXDFabric* fabric,
    size_t* total_vram,
    size_t* free_vram,
    size_t* used_vram
) {
    if (!fabric) return RAWRAMXD_ERROR_NULL_POINTER;
    
    if (total_vram) *total_vram = fabric->gpu_vram_size;
    if (free_vram) *free_vram = fabric->gpu_vram_free;
    if (used_vram) *used_vram = fabric->gpu_used;
    
    return RAWRAMXD_SUCCESS;
}
// =============================================================================
// sovereign_thread_pool.h
// Phase 19: Scaling & Concurrency Optimization
// High-performance work-stealing thread pool for inference scaling
// =============================================================================

#ifndef SOVEREIGN_THREAD_POOL_H
#define SOVEREIGN_THREAD_POOL_H

#include <inttypes.h>
#include <stddef.h>

// Define fixed-width types if not available
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration
// =============================================================================

#define SOVEREIGN_MAX_THREADS 64
#define SOVEREIGN_TASK_QUEUE_SIZE 1024
#define SOVEREIGN_CACHE_LINE_SIZE 64

// =============================================================================
// Task Definition
// =============================================================================

typedef void (*SovereignTaskFunc)(void* user_data, uint32_t thread_id);

typedef struct {
    SovereignTaskFunc func;
    void* user_data;
    uint32_t priority;      // 0 = highest
    uint32_t affinity_hint; // Preferred NUMA node
} SovereignTask;

// =============================================================================
// Thread Pool Handle
// =============================================================================

typedef struct SovereignThreadPool* SovereignThreadPoolHandle;
typedef struct SovereignTaskWaitHandleImpl* SovereignTaskWaitHandle;

typedef enum {
    SOVEREIGN_TASK_STATE_PENDING = 0,
    SOVEREIGN_TASK_STATE_RUNNING = 1,
    SOVEREIGN_TASK_STATE_COMPLETED = 2
} SovereignTaskState;

// =============================================================================
// Statistics
// =============================================================================

typedef struct {
    uint64_t tasks_submitted;
    uint64_t tasks_completed;
    uint64_t tasks_stolen;      // Work stealing events
    uint64_t idle_spins;        // Thread idle cycles
    uint64_t queue_overflows;   // Task queue full events
    double avg_latency_us;      // Task execution latency
    double throughput_tasks_per_sec;
} SovereignThreadPoolStats;

// =============================================================================
// API Functions
// =============================================================================

// Initialize thread pool with specified number of threads
// Returns NULL on failure
__declspec(dllexport) SovereignThreadPoolHandle Sovereign_ThreadPool_Init(
    uint32_t num_threads,
    uint32_t numa_node_mask    // Bitmask of allowed NUMA nodes (0 = all)
);

// Shutdown thread pool and cleanup resources
__declspec(dllexport) void Sovereign_ThreadPool_Shutdown(
    SovereignThreadPoolHandle pool
);

// Submit task to thread pool
// Returns 0 on success, non-zero if queue full
__declspec(dllexport) int Sovereign_ThreadPool_Submit(
    SovereignThreadPoolHandle pool,
    const SovereignTask* task
);

// Submit task and receive a per-task wait handle.
// Returns 0 on success, non-zero if queue full or invalid args.
__declspec(dllexport) int Sovereign_ThreadPool_SubmitWithHandle(
    SovereignThreadPoolHandle pool,
    const SovereignTask* task,
    SovereignTaskWaitHandle* out_handle
);

// Submit batch of tasks (more efficient than individual submits)
__declspec(dllexport) int Sovereign_ThreadPool_SubmitBatch(
    SovereignThreadPoolHandle pool,
    const SovereignTask* tasks,
    uint32_t count
);

// Wait for all tasks to complete
__declspec(dllexport) void Sovereign_ThreadPool_WaitAll(
    SovereignThreadPoolHandle pool
);

// Wait on a specific task handle only.
// timeout_ms: 0 = infinite, >0 = timeout in milliseconds.
// Returns: 0 = completed, 1 = timeout, <0 = error.
__declspec(dllexport) int Sovereign_ThreadPool_WaitTask(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle,
    uint32_t timeout_ms
);

// Get current state of a specific task handle.
// Returns 0 on success, <0 on error.
__declspec(dllexport) int Sovereign_ThreadPool_GetTaskState(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle,
    uint32_t* out_state
);

// Release a task wait handle.
// Safe to call before or after completion.
__declspec(dllexport) void Sovereign_ThreadPool_ReleaseTaskHandle(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle
);

// Get current thread ID within pool (0 to num_threads-1)
// Returns -1 if called from non-pool thread
__declspec(dllexport) int Sovereign_ThreadPool_GetThreadID(
    SovereignThreadPoolHandle pool
);

// Get thread pool statistics
__declspec(dllexport) void Sovereign_ThreadPool_GetStats(
    SovereignThreadPoolHandle pool,
    SovereignThreadPoolStats* stats
);

// Reset statistics counters
__declspec(dllexport) void Sovereign_ThreadPool_ResetStats(
    SovereignThreadPoolHandle pool
);

// Set thread affinity for current thread
__declspec(dllexport) int Sovereign_ThreadPool_SetAffinity(
    uint32_t cpu_id
);

// Get optimal thread count for current hardware
__declspec(dllexport) uint32_t Sovereign_ThreadPool_GetHardwareThreads(void);

// Get NUMA node count
__declspec(dllexport) uint32_t Sovereign_ThreadPool_GetNumaNodes(void);

// =============================================================================
// Convenience Macros
// =============================================================================

#define SOVEREIGN_PARALLEL_FOR(pool, start, end, body) \
    do { \
        uint32_t _sovereign_range = (end) - (start); \
        uint32_t _sovereign_threads = Sovereign_ThreadPool_GetHardwareThreads(); \
        uint32_t _sovereign_chunk = (_sovereign_range + _sovereign_threads - 1) / _sovereign_threads; \
        for (uint32_t _sovereign_t = 0; _sovereign_t < _sovereign_threads; _sovereign_t++) { \
            uint32_t _sovereign_s = (start) + _sovereign_t * _sovereign_chunk; \
            uint32_t _sovereign_e = _sovereign_s + _sovereign_chunk; \
            if (_sovereign_e > (end)) _sovereign_e = (end); \
            SovereignTask _sovereign_task = { \
                .func = [](void* data, uint32_t tid) { \
                    uint32_t* range = (uint32_t*)data; \
                    for (uint32_t i = range[0]; i < range[1]; i++) { body; } \
                }, \
                .user_data = (uint32_t[]){_sovereign_s, _sovereign_e}, \
                .priority = 0, \
                .affinity_hint = 0 \
            }; \
            Sovereign_ThreadPool_Submit(pool, &_sovereign_task); \
        } \
        Sovereign_ThreadPool_WaitAll(pool); \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif // SOVEREIGN_THREAD_POOL_H

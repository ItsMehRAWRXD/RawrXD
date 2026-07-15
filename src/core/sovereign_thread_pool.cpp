// =============================================================================
// sovereign_thread_pool.cpp
// Phase 19: Scaling & Concurrency Optimization
// Simplified working thread pool implementation
// =============================================================================

#include "sovereign_thread_pool.h"
#include <windows.h>
#include <process.h>
#include <atomic>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <new>

struct TaskCompletion {
    std::atomic<uint32_t> state{SOVEREIGN_TASK_STATE_PENDING};
    std::atomic<uint32_t> ref_count{1};
    std::mutex mutex;
    std::condition_variable cv;
};

static void TaskCompletion_AddRef(TaskCompletion* completion) {
    if (completion) {
        completion->ref_count.fetch_add(1, std::memory_order_relaxed);
    }
}

static void TaskCompletion_Release(TaskCompletion* completion) {
    if (completion && completion->ref_count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        delete completion;
    }
}

// =============================================================================
// Task Queue (simple locked queue for reliability)
// =============================================================================

struct QueuedTask {
    SovereignTask task;
    TaskCompletion* completion;
};

struct TaskQueue {
    static const uint32_t CAPACITY = SOVEREIGN_TASK_QUEUE_SIZE;
    
    QueuedTask tasks[CAPACITY];
    std::atomic<uint32_t> head{0};
    std::atomic<uint32_t> tail{0};
    std::atomic<uint32_t> size{0};
    mutable std::mutex mutex;
    
    // Default constructor
    TaskQueue() = default;
    
    // Delete copy
    TaskQueue(const TaskQueue&) = delete;
    TaskQueue& operator=(const TaskQueue&) = delete;
    
    bool Push(const SovereignTask& task, TaskCompletion* completion) {
        std::lock_guard<std::mutex> lock(mutex);
        uint32_t current_size = size.load(std::memory_order_relaxed);
        if (current_size >= CAPACITY) {
            return false;  // Queue full
        }
        
        uint32_t idx = tail.load(std::memory_order_relaxed) % CAPACITY;
        tasks[idx].task = task;
        tasks[idx].completion = completion;
        tail.store(tail.load() + 1, std::memory_order_release);
        size.fetch_add(1, std::memory_order_release);
        return true;
    }
    
    bool Pop(QueuedTask& task) {
        std::lock_guard<std::mutex> lock(mutex);
        uint32_t current_size = size.load(std::memory_order_acquire);
        if (current_size == 0) {
            return false;  // Queue empty
        }
        
        uint32_t idx = head.load(std::memory_order_relaxed) % CAPACITY;
        task = tasks[idx];
        head.store(head.load() + 1, std::memory_order_release);
        size.fetch_sub(1, std::memory_order_release);
        return true;
    }
    
    uint32_t Size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return size.load(std::memory_order_acquire);
    }
};

// =============================================================================
// Thread Pool Structures
// =============================================================================

struct ThreadContext {
    TaskQueue queue;
    std::atomic<uint64_t> tasks_completed{0};
    std::atomic<uint64_t> tasks_stolen{0};
    std::atomic<uint64_t> idle_spins{0};
    HANDLE thread_handle{nullptr};
    uint32_t thread_id{0};
    uint32_t numa_node{0};
    std::atomic<bool> running{false};
    std::atomic<bool> should_exit{false};
    
    // Default constructor
    ThreadContext() = default;
    
    // Delete copy
    ThreadContext(const ThreadContext&) = delete;
    ThreadContext& operator=(const ThreadContext&) = delete;
};

struct SovereignThreadPool {
    std::deque<ThreadContext> threads;
    std::atomic<uint32_t> active_threads{0};
    std::atomic<bool> shutdown{false};
    std::atomic<uint64_t> global_tasks_submitted{0};
    std::atomic<uint64_t> global_queue_overflows{0};
    
    HANDLE completion_event{nullptr};
    CRITICAL_SECTION stats_lock;
    
    double avg_latency_us{0.0};
    uint64_t latency_samples{0};
};

// =============================================================================
// Worker Thread Function
// =============================================================================

struct ThreadInitData {
    SovereignThreadPool* pool;
    uint32_t thread_id;
};

static unsigned __stdcall WorkerThreadFunc(void* param) {
    ThreadInitData* init_data = (ThreadInitData*)param;
    SovereignThreadPool* pool = init_data->pool;
    uint32_t my_id = init_data->thread_id;
    delete init_data;
    
    ThreadContext& my_context = pool->threads[my_id];
    my_context.thread_id = my_id;
    
    while (!my_context.should_exit.load(std::memory_order_acquire)) {
        QueuedTask queued_task{};
        bool got_task = false;
        
        // Try to get from own queue
        if (my_context.queue.Pop(queued_task)) {
            got_task = true;
        } else {
            // Try to steal from other threads
            uint32_t num_threads = pool->active_threads.load(std::memory_order_acquire);
            for (uint32_t i = 1; i < num_threads && !got_task; i++) {
                uint32_t victim = (my_id + i) % num_threads;
                if (victim != my_id && pool->threads[victim].queue.Pop(queued_task)) {
                    got_task = true;
                    my_context.tasks_stolen.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        
        if (got_task) {
            TaskCompletion* completion = queued_task.completion;
            if (completion) {
                completion->state.store(SOVEREIGN_TASK_STATE_RUNNING, std::memory_order_release);
            }

            my_context.running.store(true, std::memory_order_release);
            
            // Execute task
            LARGE_INTEGER start, end, freq;
            QueryPerformanceCounter(&start);
            QueryPerformanceFrequency(&freq);
            
            queued_task.task.func(queued_task.task.user_data, my_id);
            
            QueryPerformanceCounter(&end);
            double latency_us = ((end.QuadPart - start.QuadPart) * 1e6) / freq.QuadPart;
            
            my_context.tasks_completed.fetch_add(1, std::memory_order_relaxed);
            my_context.running.store(false, std::memory_order_release);
            
            // Update latency statistics
            EnterCriticalSection(&pool->stats_lock);
            pool->latency_samples++;
            pool->avg_latency_us += (latency_us - pool->avg_latency_us) / pool->latency_samples;
            LeaveCriticalSection(&pool->stats_lock);

            if (completion) {
                {
                    std::lock_guard<std::mutex> lock(completion->mutex);
                    completion->state.store(SOVEREIGN_TASK_STATE_COMPLETED, std::memory_order_release);
                }
                completion->cv.notify_all();
                TaskCompletion_Release(completion);
            }
        } else {
            // No work - yield CPU
            my_context.idle_spins.fetch_add(1, std::memory_order_relaxed);
            Sleep(1);  // 1ms sleep to prevent busy-waiting
        }
    }
    
    return 0;
}

// =============================================================================
// Public API Implementation
// =============================================================================

__declspec(dllexport) SovereignThreadPoolHandle Sovereign_ThreadPool_Init(
    uint32_t num_threads,
    uint32_t numa_node_mask) {
    
    if (num_threads == 0) {
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        num_threads = sys_info.dwNumberOfProcessors;
    }
    
    if (num_threads > SOVEREIGN_MAX_THREADS) {
        num_threads = SOVEREIGN_MAX_THREADS;
    }
    
    SovereignThreadPool* pool = new SovereignThreadPool();
    if (!pool) return nullptr;
    
    InitializeCriticalSection(&pool->stats_lock);
    pool->completion_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    
    pool->threads.resize(num_threads);
    pool->active_threads.store(num_threads, std::memory_order_release);
    
    // Create worker threads
    for (uint32_t i = 0; i < num_threads; i++) {
        pool->threads[i].thread_id = i;
        
        // Assign NUMA node if mask provided
        if (numa_node_mask != 0) {
            pool->threads[i].numa_node = i % 32;
        } else {
            pool->threads[i].numa_node = UINT32_MAX;
        }
        
        // Create init data for this thread
        ThreadInitData* init_data = new ThreadInitData{pool, i};
        
        // Create thread
        pool->threads[i].thread_handle = (HANDLE)_beginthreadex(
            nullptr, 0, WorkerThreadFunc, init_data, 0, nullptr
        );
        
        if (!pool->threads[i].thread_handle) {
            delete init_data;
            Sovereign_ThreadPool_Shutdown(pool);
            return nullptr;
        }
    }
    
    return pool;
}

__declspec(dllexport) void Sovereign_ThreadPool_Shutdown(SovereignThreadPoolHandle pool) {
    if (!pool) return;
    
    // Signal shutdown
    pool->shutdown.store(true, std::memory_order_release);
    
    // Signal all threads to exit
    for (auto& thread : pool->threads) {
        thread.should_exit.store(true, std::memory_order_release);
    }
    
    // Wait for all threads to complete
    for (auto& thread : pool->threads) {
        if (thread.thread_handle) {
            WaitForSingleObject(thread.thread_handle, INFINITE);
            CloseHandle(thread.thread_handle);
        }
    }
    
    if (pool->completion_event) {
        CloseHandle(pool->completion_event);
    }
    
    DeleteCriticalSection(&pool->stats_lock);
    delete pool;
}

__declspec(dllexport) int Sovereign_ThreadPool_Submit(
    SovereignThreadPoolHandle pool,
    const SovereignTask* task) {
    
    if (!pool || !task) return -1;
    
    // Find thread with smallest queue
    uint32_t num_threads = pool->active_threads.load(std::memory_order_acquire);
    uint32_t best_thread = 0;
    uint32_t min_size = UINT32_MAX;
    
    for (uint32_t i = 0; i < num_threads; i++) {
        uint32_t size = pool->threads[i].queue.Size();
        if (size < min_size) {
            min_size = size;
            best_thread = i;
        }
    }
    
    if (pool->threads[best_thread].queue.Push(*task, nullptr)) {
        pool->global_tasks_submitted.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }
    
    pool->global_queue_overflows.fetch_add(1, std::memory_order_relaxed);
    return -1;
}

__declspec(dllexport) int Sovereign_ThreadPool_SubmitWithHandle(
    SovereignThreadPoolHandle pool,
    const SovereignTask* task,
    SovereignTaskWaitHandle* out_handle) {

    if (!pool || !task || !out_handle) return -1;

    TaskCompletion* completion = new (std::nothrow) TaskCompletion();
    if (!completion) {
        return -1;
    }

    TaskCompletion_AddRef(completion); // Queue/worker reference

    uint32_t num_threads = pool->active_threads.load(std::memory_order_acquire);
    uint32_t best_thread = 0;
    uint32_t min_size = UINT32_MAX;

    for (uint32_t i = 0; i < num_threads; i++) {
        uint32_t size = pool->threads[i].queue.Size();
        if (size < min_size) {
            min_size = size;
            best_thread = i;
        }
    }

    if (pool->threads[best_thread].queue.Push(*task, completion)) {
        pool->global_tasks_submitted.fetch_add(1, std::memory_order_relaxed);
        *out_handle = (SovereignTaskWaitHandle)completion;
        return 0;
    }

    pool->global_queue_overflows.fetch_add(1, std::memory_order_relaxed);
    TaskCompletion_Release(completion); // queue ref
    TaskCompletion_Release(completion); // user ref
    return -1;
}

__declspec(dllexport) int Sovereign_ThreadPool_SubmitBatch(
    SovereignThreadPoolHandle pool,
    const SovereignTask* tasks,
    uint32_t count) {
    
    if (!pool || !tasks || count == 0) return -1;
    
    int failed = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (Sovereign_ThreadPool_Submit(pool, &tasks[i]) != 0) {
            failed++;
        }
    }
    
    return failed;
}

__declspec(dllexport) void Sovereign_ThreadPool_WaitAll(SovereignThreadPoolHandle pool) {
    if (!pool) return;

    // Snapshot the submitted count at entry so concurrent producers
    // cannot keep this wait alive indefinitely.
    const uint64_t target_submitted =
        pool->global_tasks_submitted.load(std::memory_order_acquire);

    // Wait until tasks submitted up to the snapshot are completed.
    while (true) {
        uint64_t completed = 0;
        
        for (auto& thread : pool->threads) {
            completed += thread.tasks_completed.load(std::memory_order_acquire);
        }

        if (completed >= target_submitted) {
            break;
        }
        
        Sleep(1);  // Short sleep to prevent busy-waiting
    }
}

__declspec(dllexport) int Sovereign_ThreadPool_GetThreadID(SovereignThreadPoolHandle pool) {
    (void)pool;
    return -1;  // Simplified - would need TLS for actual implementation
}

__declspec(dllexport) int Sovereign_ThreadPool_WaitTask(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle,
    uint32_t timeout_ms) {
    (void)pool;
    if (!handle) return -1;

    TaskCompletion* completion = (TaskCompletion*)handle;
    if (completion->state.load(std::memory_order_acquire) == SOVEREIGN_TASK_STATE_COMPLETED) {
        return 0;
    }

    std::unique_lock<std::mutex> lock(completion->mutex);
    if (timeout_ms == 0) {
        completion->cv.wait(lock, [completion] {
            return completion->state.load(std::memory_order_acquire) == SOVEREIGN_TASK_STATE_COMPLETED;
        });
        return 0;
    }

    const bool completed = completion->cv.wait_for(
        lock,
        std::chrono::milliseconds(timeout_ms),
        [completion] {
            return completion->state.load(std::memory_order_acquire) == SOVEREIGN_TASK_STATE_COMPLETED;
        }
    );

    return completed ? 0 : 1;
}

__declspec(dllexport) int Sovereign_ThreadPool_GetTaskState(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle,
    uint32_t* out_state) {
    (void)pool;
    if (!handle || !out_state) return -1;

    TaskCompletion* completion = (TaskCompletion*)handle;
    *out_state = completion->state.load(std::memory_order_acquire);
    return 0;
}

__declspec(dllexport) void Sovereign_ThreadPool_ReleaseTaskHandle(
    SovereignThreadPoolHandle pool,
    SovereignTaskWaitHandle handle) {
    (void)pool;
    if (!handle) return;

    TaskCompletion* completion = (TaskCompletion*)handle;
    TaskCompletion_Release(completion);
}

__declspec(dllexport) void Sovereign_ThreadPool_GetStats(
    SovereignThreadPoolHandle pool,
    SovereignThreadPoolStats* stats) {
    
    if (!pool || !stats) return;
    
    memset(stats, 0, sizeof(*stats));
    
    stats->tasks_submitted = pool->global_tasks_submitted.load();
    stats->queue_overflows = pool->global_queue_overflows.load();
    
    for (auto& thread : pool->threads) {
        stats->tasks_completed += thread.tasks_completed.load();
        stats->tasks_stolen += thread.tasks_stolen.load();
        stats->idle_spins += thread.idle_spins.load();
    }
    
    EnterCriticalSection(&pool->stats_lock);
    stats->avg_latency_us = pool->avg_latency_us;
    LeaveCriticalSection(&pool->stats_lock);
    
    // Calculate throughput
    double total_time_sec = stats->avg_latency_us * stats->tasks_completed / 1e6;
    if (total_time_sec > 0) {
        stats->throughput_tasks_per_sec = stats->tasks_completed / total_time_sec;
    }
}

__declspec(dllexport) uint32_t Sovereign_ThreadPool_GetHardwareThreads(void) {
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);
    return sys_info.dwNumberOfProcessors;
}

__declspec(dllexport) uint32_t Sovereign_ThreadPool_GetNumaNodes(void) {
    // Simplified - return 1 for single NUMA node systems
    // In production, would use GetNumaHighestNodeNumber() + 1
    return 1;
}

// ============================================================================
// c7_multi_thread_scheduler.hpp - Multi-Threaded Layer Execution
// ============================================================================
// Parallel transformer execution using thread-per-layer or work-stealing.
// Designed for:
//   - Multi-core CPUs (4-64 cores)
//   - Layer-parallel execution (each layer on different thread)
//   - Pipeline parallelism (multiple tokens in flight)
//   - Telemetry per thread (MASM-compatible phase IDs)
//
// Architecture:
//   LayerScheduler
//     → ThreadPool (worker threads)
//     → TaskQueue (layer execution tasks)
//     → Synchronization (barriers for sequential consistency)
//     → Telemetry (per-thread phase logging)
// ============================================================================

#pragma once

#include "optimized_transformer_layer.hpp"
#include "kv_cache.hpp"
#include <cstdint.h>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <future>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Forward Declarations
// ============================================================================
class LayerScheduler;
class ThreadPool;
struct LayerTask;

// ============================================================================
// Execution Mode
// ============================================================================
enum class ExecutionMode {
    SEQUENTIAL = 0,       // Single-threaded (baseline)
    LAYER_PARALLEL = 1, // One thread per layer (synchronous barriers)
    PIPELINE = 2,         // Pipeline parallelism (multiple tokens)
    WORK_STEALING = 3,    // Dynamic task distribution
};

// ============================================================================
// Task Types
// ============================================================================
enum class TaskType {
    LAYER_FORWARD = 0,
    ATTENTION_ONLY = 1,
    MLP_ONLY = 2,
    NORM_ONLY = 3,
    QKV_PROJECTION = 4,
    OUTPUT_PROJECTION = 5,
};

// ============================================================================
// Layer Task
// ============================================================================
struct LayerTask {
    uint32_t layer_idx = 0;
    TaskType type = TaskType::LAYER_FORWARD;
    
    // Input/output buffers
    const float* input = nullptr;
    float* output = nullptr;
    
    // Sequence info
    uint32_t seq_len = 0;
    uint32_t position = 0;
    
    // KV cache (shared across layers, thread-safe access)
    KVCache* kv_cache = nullptr;
    
    // Synchronization
    std::atomic<bool>* completion_flag = nullptr;
    std::promise<bool>* completion_promise = nullptr;
    
    // Telemetry
    uint64_t submit_cycles = 0;
    uint64_t start_cycles = 0;
    uint64_t end_cycles = 0;
    uint32_t thread_id = 0;
};

// ============================================================================
// Thread Pool (Worker Threads)
// ============================================================================
class ThreadPool {
public:
    ThreadPool();
    explicit ThreadPool(uint32_t num_threads);
    ~ThreadPool();
    
    // Disable copy/move
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;
    
    // Initialize with N threads
    bool Initialize(uint32_t num_threads);
    
    // Shutdown gracefully
    void Shutdown();
    
    // Submit task to queue
    // Returns future for result
    std::future<bool> Submit(LayerTask task);
    
    // Submit task with priority (lower = higher priority)
    std::future<bool> SubmitPriority(LayerTask task, uint32_t priority);
    
    // Wait for all tasks to complete
    void WaitAll();
    
    // Getters
    uint32_t GetNumThreads() const { return m_num_threads; }
    uint32_t GetActiveTasks() const { return m_active_tasks.load(); }
    bool IsInitialized() const { return m_initialized; }
    
    // Per-thread telemetry access
    void SetTelemetryCallback(std::function<void(uint32_t thread_id, uint32_t phase)> callback);

private:
    // Worker thread function
    void WorkerLoop(uint32_t thread_id);
    
    // Execute single task
    bool ExecuteTask(LayerTask& task, uint32_t thread_id);
    
    // Thread state
    struct WorkerThread {
        std::thread handle;
        uint32_t id = 0;
        std::atomic<bool> active{false};
        uint64_t tasks_executed = 0;
        uint64_t total_cycles = 0;
    };
    
    std::vector<std::unique_ptr<WorkerThread>> m_workers;
    uint32_t m_num_threads = 0;
    std::atomic<bool> m_shutdown{false};
    std::atomic<bool> m_initialized{false};
    std::atomic<uint32_t> m_active_tasks{0};
    
    // Task queue with priority
    struct PrioritizedTask {
        LayerTask task;
        uint32_t priority = 0;
        
        bool operator>(const PrioritizedTask& other) const {
            return priority > other.priority;  // Min-heap (lower = higher priority)
        }
    };
    
    std::priority_queue<PrioritizedTask, std::vector<PrioritizedTask>, std::greater<>> m_task_queue;
    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    
    // Telemetry callback
    std::function<void(uint32_t, uint32_t)> m_telemetry_callback;
};

// ============================================================================
// Layer Scheduler (Main Interface)
// ============================================================================
class LayerScheduler {
public:
    LayerScheduler();
    ~LayerScheduler();
    
    // Configuration
    struct Config {
        ExecutionMode mode = ExecutionMode::LAYER_PARALLEL;
        uint32_t num_threads = 0;  // 0 = auto-detect
        uint32_t pipeline_depth = 1;  // For PIPELINE mode
        bool enable_telemetry = true;
        bool pin_threads = true;  // Pin threads to cores
    };
    
    // Initialize with layers and config
    bool Initialize(
        std::vector<std::unique_ptr<OptimizedTransformerLayer>>&& layers,
        const Config& config
    );
    
    // Execute all layers for single token
    // Blocks until complete
    bool ExecuteSequential(
        const float* input,
        float* output,
        KVCache& kv_cache,
        uint32_t seq_len,
        uint32_t position
    );
    
    // Execute with layer parallelism
    // Layers run in parallel where possible
    bool ExecuteLayerParallel(
        const float* input,
        float* output,
        KVCache& kv_cache,
        uint32_t seq_len,
        uint32_t position
    );
    
    // Execute with pipeline parallelism
    // Multiple tokens in flight
    bool ExecutePipeline(
        const std::vector<float*>& inputs,   // One per pipeline stage
        std::vector<float*>& outputs,
        KVCache& kv_cache,
        uint32_t seq_len,
        uint32_t position
    );
    
    // Generic execute (uses configured mode)
    bool Execute(
        const float* input,
        float* output,
        KVCache& kv_cache,
        uint32_t seq_len,
        uint32_t position
    );
    
    // Shutdown
    void Shutdown();
    
    // Getters
    ExecutionMode GetMode() const { return m_config.mode; }
    uint32_t GetNumLayers() const { return static_cast<uint32_t>(m_layers.size()); }
    uint32_t GetNumThreads() const { return m_thread_pool.GetNumThreads(); }
    
    // Performance stats
    struct PerfStats {
        uint64_t total_executions = 0;
        uint64_t total_cycles = 0;
        uint64_t total_layer_cycles = 0;
        double avg_parallel_efficiency = 0.0;  // 1.0 = perfect parallelization
        
        float GetAvgLatencyMs(float cpu_ghz = 3.0f) const {
            return total_cycles / (total_executions * cpu_ghz * 1e6f);
        }
    };
    
    PerfStats GetPerfStats() const { return m_perf_stats; }
    void ResetPerfStats() { m_perf_stats = PerfStats(); }
    
    // Thread pool access (for advanced usage)
    ThreadPool& GetThreadPool() { return m_thread_pool; }

private:
    // Layer storage
    std::vector<std::unique_ptr<OptimizedTransformerLayer>> m_layers;
    Config m_config;
    
    // Thread pool
    ThreadPool m_thread_pool;
    
    // Performance tracking
    mutable PerfStats m_perf_stats;
    
    // Internal execution helpers
    bool ExecuteLayerSync(uint32_t layer_idx, const float* input, float* output,
                          KVCache& kv_cache, uint32_t seq_len, uint32_t position);
    
    bool ExecuteLayerAsync(uint32_t layer_idx, const float* input, float* output,
                           KVCache& kv_cache, uint32_t seq_len, uint32_t position,
                           std::future<bool>& out_future);
    
    // Barrier for layer synchronization
    class LayerBarrier {
    public:
        explicit LayerBarrier(uint32_t count);
        void Wait();
        void Reset();
    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        uint32_t m_threshold;
        uint32_t m_count{0};
        uint32_t m_generation{0};
    };
    
    std::unique_ptr<LayerBarrier> m_barrier;
};

// ============================================================================
// Pipeline Stage (for PIPELINE mode)
// ============================================================================
struct PipelineStage {
    uint32_t stage_id = 0;
    uint32_t token_position = 0;
    
    // Buffers
    std::vector<float> input;
    std::vector<float> output;
    
    // State
    std::atomic<bool> ready{false};
    std::atomic<bool> complete{false};
    
    // Timing
    uint64_t submit_cycles = 0;
    uint64_t complete_cycles = 0;
};

// ============================================================================
// Multi-Model Scheduler (for C8)
// ============================================================================
class MultiModelScheduler {
public:
    // Schedule multiple models on same thread pool
    // Useful for multi-model inference (e.g., draft + target)
    
    struct ModelHandle {
        uint32_t model_id = 0;
        LayerScheduler* scheduler = nullptr;
    };
    
    bool Initialize(uint32_t num_threads);
    ModelHandle RegisterModel(std::vector<std::unique_ptr<OptimizedTransformerLayer>>&& layers);
    bool ExecuteModel(ModelHandle handle, const float* input, float* output,
                      KVCache& kv_cache, uint32_t seq_len, uint32_t position);
    
private:
    std::vector<std::unique_ptr<LayerScheduler>> m_schedulers;
    ThreadPool m_shared_thread_pool;
};

// ============================================================================
// Telemetry Integration
// ============================================================================

// Per-thread telemetry buffer (lock-free)
struct ThreadTelemetryBuffer {
    static constexpr size_t BUFFER_SIZE = 1024;
    
    struct Event {
        uint64_t cycles = 0;
        uint32_t phase = 0;
        uint32_t layer_idx = 0;
        uint32_t detail = 0;
    };
    
    std::array<Event, BUFFER_SIZE> events;
    std::atomic<size_t> write_idx{0};
    
    void Log(uint32_t phase, uint32_t layer_idx = 0, uint32_t detail = 0);
    void Flush(std::vector<Event>& out);
};

// Global telemetry manager
class TelemetryManager {
public:
    static TelemetryManager& Instance();
    
    void RegisterThread(uint32_t thread_id);
    void LogEvent(uint32_t thread_id, uint32_t phase, uint32_t layer_idx = 0, uint32_t detail = 0);
    void FlushAll();
    
private:
    std::unordered_map<uint32_t, std::unique_ptr<ThreadTelemetryBuffer>> m_thread_buffers;
    std::mutex m_mutex;
};

} // namespace Runtime
} // namespace RawrXD

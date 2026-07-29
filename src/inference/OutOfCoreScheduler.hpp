#pragma once
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <deque>
#include <queue>
#include <functional>
#include <chrono>
#include <memory>
#include <unordered_map>
#include <map>

#ifdef _WIN32
#include <windows.h>
#endif

// Forward declarations for Vulkan
struct VkDevice_T; typedef VkDevice_T* VkDevice;
struct VkQueue_T; typedef VkQueue_T* VkQueue;
struct VkCommandBuffer_T; typedef VkCommandBuffer_T* VkCommandBuffer;
struct VkFence_T; typedef VkFence_T* VkFence;
struct VkBuffer_T; typedef VkBuffer_T* VkBuffer;

namespace RawrXD {
namespace Inference {

// Layer execution state
enum class LayerState : uint8_t {
    IDLE = 0,           // Not loaded
    PREFETCHING = 1,    // Being loaded from SSD/RAM
    READY_GPU0 = 2,     // Ready on GPU0
    READY_GPU1 = 3,     // Ready on GPU1
    READY_RAM = 4,      // Ready in RAM
    EXECUTING = 5,      // Currently running
    EVICTING = 6        // Being moved to lower tier
};

// Layer metadata for 671B model
struct LayerInfo {
    uint32_t layer_id;
    size_t weight_size_bytes;
    size_t kv_cache_size_bytes;
    
    // Current location
    LayerState state;
    void* cpu_ptr;
    VkBuffer gpu_buffer;
    uint32_t gpu_device; // 0 = R9700, 1 = 7800XT
    
    // Timing info
    std::chrono::microseconds compute_time_us;
    std::chrono::microseconds transfer_time_us;
    uint64_t execution_count;
    uint64_t last_token_id;
    
    // Dependencies
    std::vector<uint32_t> input_layers;
    std::vector<uint32_t> output_layers;
};

// Execution plan for a token
struct TokenExecutionPlan {
    uint64_t token_id;
    std::vector<uint32_t> layer_order;
    
    // Which GPU handles which layers (2:1 split)
    uint32_t gpu0_layer_start;
    uint32_t gpu0_layer_end;
    uint32_t gpu1_layer_start;
    uint32_t gpu1_layer_end;
    
    // Prefetch window
    uint32_t prefetch_ahead;
    
    // Async I/O handles
    std::vector<HANDLE> pending_io_handles;
};

// Configuration for out-of-core execution
struct OutOfCoreConfig {
    // Model dimensions (671B)
    uint32_t num_layers = 80;
    uint32_t num_heads = 64;
    uint32_t head_dim = 128;
    uint32_t hidden_dim = 8192;
    uint32_t vocab_size = 32000;
    
    // Memory budgets
    size_t gpu0_budget_bytes = 28ULL * 1024 * 1024 * 1024;  // 28GB
    size_t gpu1_budget_bytes = 14ULL * 1024 * 1024 * 1024;  // 14GB
    size_t ram_budget_bytes = 56ULL * 1024 * 1024 * 1024;   // 56GB
    
    // Tensor split ratio (2:1 for R9700:7800XT)
    float gpu0_split_ratio = 0.667f;
    float gpu1_split_ratio = 0.333f;
    
    // Scheduling
    uint32_t max_concurrent_layers = 4;
    uint32_t prefetch_lookahead = 3;
    bool enable_async_prefetch = true;
    bool enable_overlap_compute_transfer = true;
    
    // KV cache management
    uint32_t max_context_length = 128 * 1024;  // 128K context
    bool enable_kv_cache_compression = true;
    float kv_cache_quantization_bits = 8.0f;  // FP8 for KV cache
    
    // Performance tuning
    uint32_t num_worker_threads = 4;
    std::chrono::milliseconds scheduling_quantum_ms{10};
};

// Performance metrics
struct OutOfCoreMetrics {
    uint64_t tokens_processed;
    uint64_t layers_executed;
    uint64_t gpu0_layer_executions;
    uint64_t gpu1_layer_executions;
    uint64_t prefetch_hits;
    uint64_t prefetch_misses;
    uint64_t eviction_count;
    
    double avg_token_latency_ms;
    double avg_layer_latency_ms;
    double avg_prefetch_latency_ms;
    double throughput_tps;
    
    // Memory pressure
    float gpu0_pressure;
    float gpu1_pressure;
    float ram_pressure;
};

// Out-of-core scheduler for 671B models on limited GPU memory
class OutOfCoreScheduler {
public:
    explicit OutOfCoreScheduler(const OutOfCoreConfig& config);
    ~OutOfCoreScheduler();
    
    // Initialize with Vulkan devices
    bool Initialize(VkDevice gpu0, VkDevice gpu1, VkQueue queue0, VkQueue queue1);
    void Shutdown();
    
    // Load model weights (from SSD)
    bool LoadModelWeights(const std::string& weight_path);
    
    // Schedule token generation
    uint64_t ScheduleToken(uint64_t previous_token_id);
    
    // Wait for token completion
    bool WaitForToken(uint64_t token_id, uint32_t timeout_ms);
    
    // Get next ready layer for execution
    bool GetNextLayerToExecute(uint32_t& layer_id, uint32_t& gpu_device);
    
    // Mark layer execution complete
    void MarkLayerComplete(uint32_t layer_id);
    
    // Prefetch layers for upcoming tokens
    void PrefetchLayers(uint64_t upcoming_token_id);
    
    // Emergency memory relief
    void TriggerMemoryPressureRelief(uint32_t gpu_device);
    
    // Statistics
    OutOfCoreMetrics GetMetrics() const;
    std::string GetStatusReport() const;
    
    // Dynamic configuration
    void SetPrefetchLookahead(uint32_t lookahead);
    void SetTensorSplitRatio(float gpu0_ratio);
    
private:
    OutOfCoreConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    // Vulkan handles
    VkDevice gpu0_device_;
    VkDevice gpu1_device_;
    VkQueue gpu0_queue_;
    VkQueue gpu1_queue_;
    
    // Layer registry
    mutable std::mutex layers_mutex_;
    std::vector<std::unique_ptr<LayerInfo>> layers_;
    std::unordered_map<uint32_t, LayerInfo*> layer_map_;
    
    // Execution queue
    mutable std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<uint32_t> ready_queue_;  // Layers ready to execute
    std::queue<uint32_t> prefetch_queue_;
    
    // Token tracking
    mutable std::mutex tokens_mutex_;
    std::unordered_map<uint64_t, TokenExecutionPlan> token_plans_;
    uint64_t next_token_id_ = 1;
    
    // Memory tracking per tier
    mutable std::mutex memory_mutex_;
    size_t gpu0_used_bytes_ = 0;
    size_t gpu1_used_bytes_ = 0;
    size_t ram_used_bytes_ = 0;
    
    // Worker threads
    std::vector<std::thread> worker_threads_;
    std::thread prefetch_thread_;
    std::thread eviction_thread_;
    
    // Metrics
    mutable std::mutex metrics_mutex_;
    OutOfCoreMetrics metrics_;
    
    // Internal methods
    void WorkerLoop();
    
    // Layer size calculations
    size_t CalculateLayerWeightSize(uint32_t layer_id) const;
    size_t CalculateLayerKVCacheSize(uint32_t layer_id) const;
    uint32_t CalculateGpu0LayerCount() const;
    uint32_t CalculateGpu1LayerCount() const;
    void PrefetchLoop();
    void EvictionLoop();
    
    bool LoadLayerToGpu(uint32_t layer_id, uint32_t gpu_device);
    bool EvictLayer(uint32_t layer_id);
    bool TransferLayerBetweenGpus(uint32_t layer_id, uint32_t src_gpu, uint32_t dst_gpu);
    
    void UpdateLayerState(uint32_t layer_id, LayerState new_state);
    LayerState GetLayerState(uint32_t layer_id) const;
    
    uint32_t CalculateGpu0LayerCount() const;
    uint32_t CalculateGpu1LayerCount() const;
    
    bool CanFitInGpu0(size_t bytes) const;
    bool CanFitInGpu1(size_t bytes) const;
    bool CanFitInRam(size_t bytes) const;
    
    std::vector<uint32_t> FindEvictionCandidates(uint32_t gpu_device, size_t required_bytes);
    
    void ExecuteLayerOnGpu(uint32_t layer_id, uint32_t gpu_device);
    void SubmitVulkanCommands(uint32_t layer_id, uint32_t gpu_device);
    
    void UpdateMetricsPostExecution(uint32_t layer_id, uint32_t gpu_device, 
                                       std::chrono::microseconds duration);
};

// Global scheduler instance
OutOfCoreScheduler& GetOutOfCoreScheduler();

} // namespace Inference
} // namespace RawrXD

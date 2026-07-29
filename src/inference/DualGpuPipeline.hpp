#pragma once
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <queue>
#include <functional>
#include <chrono>
#include <memory>
#include <future>

#ifdef _WIN32
#include <windows.h>
#endif

// Vulkan forward declarations
struct VkDevice_T; typedef VkDevice_T* VkDevice;
struct VkQueue_T; typedef VkQueue_T* VkQueue;
struct VkCommandBuffer_T; typedef VkCommandBuffer_T* VkCommandBuffer;
struct VkCommandPool_T; typedef VkCommandPool_T* VkCommandPool;
struct VkFence_T; typedef VkFence_T* VkFence;
struct VkSemaphore_T; typedef VkSemaphore_T* VkSemaphore;
struct VkBuffer_T; typedef VkBuffer_T* VkBuffer;
struct VkDescriptorSet_T; typedef VkDescriptorSet_T* VkDescriptorSet;
struct VkDescriptorSetLayout_T; typedef VkDescriptorSetLayout_T* VkDescriptorSetLayout;
struct VkPipeline_T; typedef VkPipeline_T* VkPipeline;
struct VkPipelineLayout_T; typedef VkPipelineLayout_T* VkPipelineLayout;

namespace RawrXD {
namespace Inference {

// Tensor operation types for dual GPU pipeline
enum class TensorOpType : uint8_t {
    LINEAR = 0,         // GEMM: Y = X @ W + B
    ATTENTION_QKV = 1,  // QKV projection
    ATTENTION_OUT = 2,  // Attention output projection
    FFN_GATE = 3,       // FFN gate projection
    FFN_UP = 4,         // FFN up projection
    FFN_DOWN = 5,       // FFN down projection
    RMSNORM = 6,        // Root mean square normalization
    RESIDUAL_ADD = 7,   // Residual connection
    ALL_REDUCE = 8,     // Cross-GPU all-reduce
    ALL_GATHER = 9      // Cross-GPU all-gather
};

// GPU device info
struct GpuDeviceInfo {
    uint32_t device_id;      // 0 = R9700, 1 = 7800XT
    VkDevice device;
    VkQueue compute_queue;
    VkQueue transfer_queue;
    VkCommandPool cmd_pool;
    
    // Memory info
    size_t total_memory_bytes;
    size_t available_memory_bytes;
    
    // Performance characteristics
    float compute_score;     // Relative compute performance
    float memory_bandwidth;  // GB/s
    
    // PCI-e info for P2P transfers
    bool p2p_accessible;     // Can access other GPU memory directly
    HANDLE dma_handle;       // Windows DMA handle for P2P
};

// Tensor shard info for 2:1 split
struct TensorShard {
    uint32_t gpu_device;     // Which GPU owns this shard
    uint32_t shard_id;       // Shard index (0 or 1)
    uint32_t num_shards;     // Total shards (2)
    
    // Dimensions
    uint32_t rows;           // Output dimension
    uint32_t cols;           // Input dimension
    uint32_t row_offset;     // Starting row in full tensor
    uint32_t col_offset;     // Starting col in full tensor
    
    // Data
    VkBuffer buffer;
    void* cpu_ptr;
    size_t size_bytes;
};

// Pipeline stage for a transformer layer
struct PipelineStage {
    uint32_t layer_id;
    uint32_t stage_id;       // Stage within layer
    TensorOpType op_type;
    
    // Input/output tensors
    TensorShard input;
    TensorShard output;
    
    // Weights (sharded)
    std::vector<TensorShard> weights;
    TensorShard bias;
    
    // Execution
    VkCommandBuffer cmd_buffer;
    VkFence fence;
    VkSemaphore signal_semaphore;
    
    // Dependencies
    std::vector<uint32_t> wait_stages;
    std::vector<VkSemaphore> wait_semaphores;
};

// Cross-GPU synchronization primitive
struct GpuSyncPoint {
    uint32_t stage_id;
    std::atomic<uint32_t> gpu0_done{0};
    std::atomic<uint32_t> gpu1_done{0};
    std::condition_variable cv;
    std::mutex mutex;
    
    void WaitForBoth() {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return gpu0_done.load() && gpu1_done.load(); });
    }
    
    void SignalGpu0() {
        gpu0_done = 1;
        cv.notify_all();
    }
    
    void SignalGpu1() {
        gpu1_done = 1;
        cv.notify_all();
    }
    
    void Reset() {
        gpu0_done = 0;
        gpu1_done = 0;
    }
};

// Configuration for dual GPU pipeline
struct DualGpuConfig {
    // Tensor split ratio (2:1 for R9700:7800XT)
    float gpu0_weight_ratio = 0.667f;
    float gpu1_weight_ratio = 0.333f;
    
    // Pipeline depth
    uint32_t num_pipeline_stages = 4;
    uint32_t num_concurrent_layers = 2;
    
    // Synchronization
    bool enable_async_execution = true;
    bool enable_p2p_transfer = true;      // GPU direct P2P
    bool enable_overlap = true;           // Overlap compute and transfer
    
    // Performance tuning
    uint32_t cmd_buffer_count = 8;
    uint32_t max_inflight_ops = 16;
    std::chrono::microseconds sync_timeout_us{10000};
    
    // Memory
    size_t gpu0_reserved_bytes = 2ULL * 1024 * 1024 * 1024;  // 2GB headroom
    size_t gpu1_reserved_bytes = 1ULL * 1024 * 1024 * 1024;  // 1GB headroom
};

// Performance metrics
struct DualGpuMetrics {
    uint64_t ops_submitted;
    uint64_t ops_completed;
    uint64_t gpu0_ops;
    uint64_t gpu1_ops;
    uint64_t p2p_transfers;
    uint64_t cpu_fallback_transfers;
    
    double avg_gpu0_latency_us;
    double avg_gpu1_latency_us;
    double avg_p2p_latency_us;
    double pipeline_efficiency;  // 0.0 - 1.0
    
    // Load balancing
    float gpu0_utilization;
    float gpu1_utilization;
    float load_imbalance;        // |gpu0 - gpu1| / max
};

// Dual GPU tensor parallelism pipeline
class DualGpuPipeline {
public:
    explicit DualGpuPipeline(const DualGpuConfig& config);
    ~DualGpuPipeline();
    
    // Initialize with Vulkan devices
    bool Initialize(VkDevice gpu0, VkDevice gpu1, 
                     VkQueue queue0, VkQueue queue1,
                     uint32_t queue_family_index);
    void Shutdown();
    
    // Create sharded tensors for 2:1 split
    bool CreateShardedTensor(uint32_t rows, uint32_t cols, uint32_t elem_size,
                              std::vector<TensorShard>& shards);
    
    // Submit operation to pipeline
    uint64_t SubmitOp(TensorOpType op_type,
                      const std::vector<TensorShard>& inputs,
                      std::vector<TensorShard>& outputs,
                      const std::vector<TensorShard>& weights);
    
    // Wait for operation completion
    bool WaitForOp(uint64_t op_id, uint32_t timeout_ms);
    
    // Execute all-reduce across GPUs (for gradient sync)
    bool AllReduce(const TensorShard& input, TensorShard& output);
    
    // Execute all-gather across GPUs (for activations)
    bool AllGather(const std::vector<TensorShard>& inputs, TensorShard& output);
    
    // P2P transfer between GPUs
    bool TransferGpuToGpu(uint32_t src_gpu, uint32_t dst_gpu,
                          const TensorShard& src, TensorShard& dst);
    
    // Synchronize both GPUs
    void Synchronize();
    
    // Get next available command buffer
    VkCommandBuffer AcquireCommandBuffer(uint32_t gpu_device);
    void SubmitCommandBuffer(uint32_t gpu_device, VkCommandBuffer cmd);
    
    // Statistics
    DualGpuMetrics GetMetrics() const;
    std::string GetPipelineReport() const;
    
    // Dynamic configuration
    void SetSplitRatio(float gpu0_ratio);
    void EnableP2P(bool enable);
    
private:
    DualGpuConfig config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    // GPU devices
    GpuDeviceInfo gpu0_info_;
    GpuDeviceInfo gpu1_info_;
    
    // Command management
    mutable std::mutex cmd_mutex_;
    std::vector<VkCommandBuffer> gpu0_cmd_buffers_;
    std::vector<VkCommandBuffer> gpu1_cmd_buffers_;
    std::queue<VkCommandBuffer> gpu0_available_;
    std::queue<VkCommandBuffer> gpu1_available_;
    
    // Operation tracking
    mutable std::mutex ops_mutex_;
    uint64_t next_op_id_ = 1;
    std::unordered_map<uint64_t, std::promise<bool>> op_promises_;
    std::unordered_map<uint64_t, std::future<bool>> op_futures_;
    
    // Pipeline stages
    mutable std::mutex pipeline_mutex_;
    std::vector<PipelineStage> stages_;
    std::queue<uint32_t> ready_queue_;
    std::condition_variable pipeline_cv_;
    
    // Cross-GPU sync
    std::vector<GpuSyncPoint> sync_points_;
    
    // Worker threads
    std::thread gpu0_worker_;
    std::thread gpu1_worker_;
    std::thread scheduler_thread_;
    
    // Metrics
    mutable std::mutex metrics_mutex_;
    DualGpuMetrics metrics_;
    
    // Internal methods
    void Gpu0WorkerLoop();
    void Gpu1WorkerLoop();
    void SchedulerLoop();
    
    bool InitializeCommandBuffers();
    void CleanupCommandBuffers();
    
    bool SetupP2PTransfer();
    void TeardownP2PTransfer();
    
    void ExecuteStage(PipelineStage& stage);
    void ExecuteOnGpu0(PipelineStage& stage);
    void ExecuteOnGpu1(PipelineStage& stage);
    
    void RecordGemmCommand(VkCommandBuffer cmd, const TensorShard& A, 
                           const TensorShard& B, const TensorShard& C,
                           uint32_t gpu_device);
    void RecordRmsNormCommand(VkCommandBuffer cmd, const TensorShard& input,
                              const TensorShard& output, const TensorShard& weight,
                              uint32_t gpu_device);
    void RecordAttentionCommand(VkCommandBuffer cmd, const TensorShard& q,
                                 const TensorShard& k, const TensorShard& v,
                                 const TensorShard& output,
                                 uint32_t gpu_device);
    
    void UpdateMetrics(const PipelineStage& stage, 
                       std::chrono::microseconds duration);
    
    uint32_t CalculateGpu0Rows(uint32_t total_rows) const;
    uint32_t CalculateGpu1Rows(uint32_t total_rows) const;
    
    bool CheckP2PSupport();
};

// Global pipeline instance
DualGpuPipeline& GetDualGpuPipeline();

} // namespace Inference
} // namespace RawrXD

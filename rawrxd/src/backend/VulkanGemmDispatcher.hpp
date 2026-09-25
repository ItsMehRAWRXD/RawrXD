#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <optional>
#include <future>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>

// Vulkan includes
#define VK_ENABLE_BETA_EXTENSIONS
#include <vulkan/vulkan.h>

namespace rawrxd::backend {

// ─── Forward Declarations ───
class VulkanDevice;
class VulkanBuffer;
class VulkanShaderModule;

// ─── Data Type Enumerations ───
enum class VulkanDataType {
    FP32,
    FP16,
    BF16,
    INT8,
    INT4,      // 4-bit weights (packed)
    Q4_0,      // llama.cpp Q4_0 quantization
    Q4_K,      // llama.cpp Q4_K quantization
    Q6_K,      // llama.cpp Q6_K quantization
    Q8_0,      // llama.cpp Q8_0 quantization
    Q8_K,      // llama.cpp Q8_K quantization
    Count
};

// ─── GEMM Shape Descriptor ───
struct GemmShape {
    uint32_t M{ 0 };  // Batch / output rows
    uint32_t N{ 0 };  // Output columns
    uint32_t K{ 0 };  // Inner dimension
    uint32_t batch_count{ 1 };
    bool trans_a{ false };
    bool trans_b{ false };

    bool operator==(const GemmShape& other) const {
        return M == other.M && N == other.N && K == other.K &&
               batch_count == other.batch_count &&
               trans_a == other.trans_a && trans_b == other.trans_b;
    }
};

struct GemmShapeHash {
    size_t operator()(const GemmShape& s) const {
        return std::hash<uint64_t>{}(
            (static_cast<uint64_t>(s.M) << 48) |
            (static_cast<uint64_t>(s.N) << 32) |
            (static_cast<uint64_t>(s.K) << 16) |
            (static_cast<uint64_t>(s.batch_count))
        );
    }
};

// ─── Tile Configuration ───
// Automatically selected based on GPU properties and matrix dimensions
struct TileConfig {
    uint32_t tile_m{ 64 };
    uint32_t tile_n{ 64 };
    uint32_t tile_k{ 32 };
    uint32_t subgroup_size{ 32 };
    uint32_t workgroup_size_x{ 8 };
    uint32_t workgroup_size_y{ 8 };
    uint32_t vector_width{ 4 };      // Vector load width (1, 2, 4, 8)
    bool use_shared_memory{ true };
    bool use_subgroup_shuffle{ true };
    bool unroll_k{ true };
    uint32_t prefetch_distance{ 2 };
};

// ─── Fused Operation Configuration ───
enum class ActivationType {
    None,
    ReLU,
    GELU,
    SiLU,
    Tanh,
    Sigmoid,
    Softmax,
    Count
};

struct FusedConfig {
    ActivationType activation{ ActivationType::None };
    bool add_bias{ false };
    bool residual_add{ false };
    float activation_alpha{ 0.0f };  // e.g., leaky ReLU alpha
    float scale{ 1.0f };             // Output scaling
};

// ─── Performance Metrics ───
struct GemmPerformanceMetrics {
    float tflops{ 0.0f };
    float bandwidth_gbps{ 0.0f };
    float latency_ms{ 0.0f };
    uint32_t tiles_dispatched{ 0 };
    uint32_t warps_occupied{ 0 };
    float occupancy{ 0.0f };
    uint64_t bytes_read{ 0 };
    uint64_t bytes_written{ 0 };
    uint32_t pipeline_stalls{ 0 };
};

// ─── Dispatch Configuration ───
struct DispatchConfig {
    uint32_t num_queues{ 2 };           // Number of compute queues to use
    bool enable_async{ true };
    bool enable_profiling{ false };
    uint32_t command_buffer_pool_size{ 64 };
    VkFenceCreateFlags fence_flags{ 0 };
    uint32_t timeout_ms{ 10000 };
};

// ─── Vulkan GEMM Dispatcher ───
// Production-grade matrix multiplication dispatcher with automatic optimization
// surpassing naive implementations through tile selection, kernel specialization,
// and multi-queue parallelism.
class VulkanGemmDispatcher {
public:
    explicit VulkanGemmDispatcher(std::shared_ptr<VulkanDevice> device);
    ~VulkanGemmDispatcher();

    // Non-copyable
    VulkanGemmDispatcher(const VulkanGemmDispatcher&) = delete;
    VulkanGemmDispatcher& operator=(const VulkanGemmDispatcher&) = delete;

    // ─── Initialization ───

    bool Initialize(const DispatchConfig& config = {});
    void Shutdown();

    // ─── Core GEMM API ───

    // Single GEMM: C = alpha * op(A) * op(B) + beta * C
    bool DispatchGemm(
        const VulkanBuffer& A,        // M x K (or K x M if transposed)
        const VulkanBuffer& B,        // K x N (or N x K if transposed)
        VulkanBuffer& C,              // M x N
        VulkanDataType dtype,
        float alpha = 1.0f,
        float beta = 0.0f,
        const GemmShape& shape = {});

    // Fused GEMM: C = activation(alpha * A * B + bias) + residual
    bool DispatchFusedGemm(
        const VulkanBuffer& A,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        const VulkanBuffer* bias,       // Optional: N elements
        const VulkanBuffer* residual,   // Optional: M x N elements
        VulkanDataType dtype,
        const FusedConfig& fused,
        float alpha = 1.0f,
        const GemmShape& shape = {});

    // Batched GEMM for multiple independent matrices
    bool DispatchBatchedGemm(
        const std::vector<const VulkanBuffer*>& A,
        const std::vector<const VulkanBuffer*>& B,
        std::vector<VulkanBuffer*>& C,
        VulkanDataType dtype,
        float alpha = 1.0f,
        float beta = 0.0f,
        const GemmShape& shape = {});

    // Strided Batched GEMM (single buffers with stride offsets)
    bool DispatchStridedBatchedGemm(
        const VulkanBuffer& A,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        uint32_t batch_count,
        uint32_t stride_a,
        uint32_t stride_b,
        uint32_t stride_c,
        VulkanDataType dtype,
        float alpha = 1.0f,
        float beta = 0.0f,
        const GemmShape& shape = {});

    // ─── Async API ───

    std::future<bool> DispatchGemmAsync(
        const VulkanBuffer& A,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        VulkanDataType dtype,
        float alpha = 1.0f,
        float beta = 0.0f,
        const GemmShape& shape = {});

    // Wait for all pending operations to complete
    void Synchronize();

    // ─── Quantized GEMM ───

    // Q4_K GEMM with dequantization on GPU
    bool DispatchQ4KGemm(
        const VulkanBuffer& A_q4,      // Quantized weights
        const VulkanBuffer& scales,      // Per-block scales
        const VulkanBuffer& B,          // FP16/FP32 activations
        VulkanBuffer& C,
        const GemmShape& shape = {});

    // Q6_K GEMM
    bool DispatchQ6KGemm(
        const VulkanBuffer& A_q6,
        const VulkanBuffer& scales,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        const GemmShape& shape = {});

    // Q8_K GEMM (fast path for 8-bit inference)
    bool DispatchQ8KGemm(
        const VulkanBuffer& A_q8,
        const VulkanBuffer& scales,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        const GemmShape& shape = {});

    // ─── Performance ───

    GemmPerformanceMetrics GetLastMetrics() const { return last_metrics_; }
    void EnableProfiling(bool enable) { profiling_enabled_ = enable; }

    // Auto-tune tile configuration for specific shape
    TileConfig AutoTune(const GemmShape& shape, VulkanDataType dtype);

    // Benchmark different tile configurations
    std::vector<std::pair<TileConfig, float>> BenchmarkTiles(
        const GemmShape& shape,
        VulkanDataType dtype,
        uint32_t iterations = 100);

    // ─── Pipeline Cache ───

    void ClearPipelineCache();
    size_t GetPipelineCacheSize() const;
    bool SavePipelineCache(const std::string& filename);
    bool LoadPipelineCache(const std::string& filename);

    // ─── Device Queries ───

    uint32_t GetOptimalSubgroupSize() const;
    uint32_t GetSharedMemorySize() const;
    uint32_t GetMaxWorkgroupSize() const;
    std::string GetDeviceName() const;

private:
    // ─── Internal Pipeline Management ───

    struct PipelineKey {
        GemmShape shape;
        VulkanDataType dtype;
        FusedConfig fused;
        TileConfig tile;

        bool operator==(const PipelineKey& other) const {
            return shape == other.shape && dtype == other.dtype &&
                   fused.activation == other.fused.activation &&
                   fused.add_bias == other.fused.add_bias &&
                   fused.residual_add == other.fused.residual_add &&
                   tile.tile_m == other.tile.tile_m &&
                   tile.tile_n == other.tile.tile_n;
        }
    };

    struct PipelineKeyHash {
        size_t operator()(const PipelineKey& k) const {
            size_t h = GemmShapeHash{}(k.shape);
            h ^= std::hash<int>{}(static_cast<int>(k.dtype)) << 1;
            h ^= std::hash<int>{}(static_cast<int>(k.fused.activation)) << 2;
            return h;
        }
    };

    struct PipelineState {
        VkPipeline pipeline{ VK_NULL_HANDLE };
        VkPipelineLayout layout{ VK_NULL_HANDLE };
        VkDescriptorSetLayout descriptor_layout{ VK_NULL_HANDLE };
        VkShaderModule shader{ VK_NULL_HANDLE };
        TileConfig tile;
        uint64_t hit_count{ 0 };
        float avg_latency_ms{ 0.0f };
    };

    bool CreatePipeline(const PipelineKey& key, PipelineState& state);
    bool CompileShader(const PipelineKey& key, std::vector<uint32_t>& spirv);
    std::string GenerateShaderSource(const PipelineKey& key);

    // ─── Tile Selection ───

    TileConfig SelectOptimalTile(const GemmShape& shape, VulkanDataType dtype);
    TileConfig SelectTileForSmallMatrix(const GemmShape& shape);
    TileConfig SelectTileForLargeMatrix(const GemmShape& shape);
    TileConfig SelectTileForQuantized(const GemmShape& shape, VulkanDataType qtype);

    // ─── Dispatch Internals ───

    bool RecordGemmCommands(
        VkCommandBuffer cmd,
        const PipelineState& pipeline,
        const VulkanBuffer& A,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        const VulkanBuffer* bias,
        const VulkanBuffer* residual,
        float alpha,
        float beta,
        const GemmShape& shape);

    bool RecordQuantizedGemmCommands(
        VkCommandBuffer cmd,
        const PipelineState& pipeline,
        const VulkanBuffer& A_quant,
        const VulkanBuffer& scales,
        const VulkanBuffer& B,
        VulkanBuffer& C,
        const GemmShape& shape);

    VkDescriptorSet AllocateDescriptorSet(VkDescriptorSetLayout layout);
    void FreeDescriptorSet(VkDescriptorSet set);

    // ─── Queue Management ───

    struct QueueState {
        VkQueue queue{ VK_NULL_HANDLE };
        VkCommandPool cmd_pool{ VK_NULL_HANDLE };
        std::vector<VkCommandBuffer> cmd_buffers;
        std::vector<VkFence> fences;
        uint32_t current_buffer{ 0 };
        std::mutex mutex;
    };

    uint32_t SelectQueue(const GemmShape& shape);
    bool AcquireCommandBuffer(uint32_t queue_idx, VkCommandBuffer& cmd, VkFence& fence);
    bool SubmitCommandBuffer(uint32_t queue_idx, VkCommandBuffer cmd, VkFence fence);

    // ─── Profiling ───

    void BeginProfiling(VkCommandBuffer cmd);
    void EndProfiling(VkCommandBuffer cmd);
    GemmPerformanceMetrics CalculateMetrics(
        const GemmShape& shape,
        VulkanDataType dtype,
        float elapsed_ms);

    // ─── Shader Code Generation ───

    std::string GenerateGemmShader(const PipelineKey& key);
    std::string GenerateQuantizedGemmShader(const PipelineKey& key);
    std::string GenerateFusedEpilogue(const FusedConfig& fused);

    // ─── Members ───

    std::shared_ptr<VulkanDevice> device_;
    DispatchConfig config_;

    VkDevice vk_device_{ VK_NULL_HANDLE };
    VkPhysicalDevice vk_physical_device_{ VK_NULL_HANDLE };
    VkPipelineCache pipeline_cache_{ VK_NULL_HANDLE };

    // Pipeline cache
    std::unordered_map<PipelineKey, PipelineState, PipelineKeyHash> pipelines_;
    mutable std::mutex pipeline_mutex_;

    // Queues
    std::vector<QueueState> queues_;
    std::atomic<uint32_t> next_queue_{ 0 };

    // Descriptor pool
    VkDescriptorPool descriptor_pool_{ VK_NULL_HANDLE };
    std::vector<VkDescriptorSet> free_descriptors_;
    mutable std::mutex descriptor_mutex_;

    // Performance
    GemmPerformanceMetrics last_metrics_;
    std::atomic<bool> profiling_enabled_{ false };
    VkQueryPool query_pool_{ VK_NULL_HANDLE };

    // Auto-tuning database
    std::unordered_map<GemmShape, TileConfig, GemmShapeHash> tuned_tiles_;
    mutable std::mutex tune_mutex_;

    // Async thread pool
    std::vector<std::thread> async_threads_;
    std::queue<std::packaged_task<bool()>> async_tasks_;
    std::mutex async_mutex_;
    std::condition_variable async_cv_;
    std::atomic<bool> async_shutdown_{ false };
};

// ─── Helper Functions ───

inline size_t VulkanDataTypeSize(VulkanDataType dtype) {
    switch (dtype) {
        case VulkanDataType::FP32: return 4;
        case VulkanDataType::FP16: return 2;
        case VulkanDataType::BF16: return 2;
        case VulkanDataType::INT8: return 1;
        case VulkanDataType::INT4: return 1;  // Packed 2 per byte
        case VulkanDataType::Q4_0: return 18; // 16 weights + 2 half-scale
        case VulkanDataType::Q4_K: return 96; // Block size dependent
        case VulkanDataType::Q6_K: return 128;
        case VulkanDataType::Q8_0: return 34; // 32 weights + 2 scale
        case VulkanDataType::Q8_K: return 128;
        default: return 4;
    }
}

inline uint32_t GetSubgroupSizeForTile(const TileConfig& tile) {
    return tile.subgroup_size;
}

// Compute required workgroup count for given shape and tile
inline uint32_t ComputeWorkgroups(uint32_t dim, uint32_t tile) {
    return (dim + tile - 1) / tile;
}

} // namespace rawrxd::backend

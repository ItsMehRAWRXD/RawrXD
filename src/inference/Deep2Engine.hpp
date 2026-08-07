#pragma once

// Windows macro pollution prevention
#ifndef NOMINMAX
#define NOMINMAX
#endif

// Standard C++ headers FIRST
#include <cstdint>
#include <cstddef>
#include <string>
#include <memory>
#include <vector>
#include <functional>
#include <chrono>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <deque>
#include <queue>

// Vulkan forward declarations (works with or without Vulkan SDK)
#ifdef RAWR_ENABLE_VULKAN
    #ifdef _WIN32
        // Try multiple Vulkan SDK locations
        #if __has_include(<vulkan/vulkan.h>)
            #include <vulkan/vulkan.h>
        #elif __has_include(<C:/VulkanSDK/1.4.328.1/Include/vulkan/vulkan.h>)
            #include <C:/VulkanSDK/1.4.328.1/Include/vulkan/vulkan.h>
        #elif __has_include(<D:/VulkanSDK/1.4.328.1/Include/vulkan/vulkan.h>)
            #include <D:/VulkanSDK/1.4.328.1/Include/vulkan/vulkan.h>
        #else
            // Vulkan SDK not found - disable Vulkan support
            #undef RAWR_ENABLE_VULKAN
            #define RAWR_ENABLE_VULKAN 0
        #endif
    #endif
#else
    // Minimal forward declarations when Vulkan is not available
    typedef struct VkDevice_T* VkDevice;
    typedef struct VkQueue_T* VkQueue;
#endif

namespace RawrXD {
namespace Memory {
    class SequentialBlowoffValve;
}
namespace Inference {
    class OutOfCoreScheduler;
    class DualGpuPipeline;
}
namespace Kernels {
    class VulkanComputeKernels;
}
}

namespace RawrXD {
namespace Inference {

//=============================================================================
// Deep2Engine Configuration
//=============================================================================

struct Deep2EngineConfig {
    // Model configuration (671B)
    uint32_t num_layers = 80;
    uint32_t num_heads = 64;
    uint32_t head_dim = 128;
    uint32_t hidden_dim = 8192;
    uint32_t vocab_size = 32000;
    uint32_t max_context_length = 128 * 1024;  // 128K
    
    // GPU configuration
    float gpu0_split_ratio = 0.667f;  // 2:1 split
    float gpu1_split_ratio = 0.333f;
    
    // Memory budgets
    size_t gpu0_budget_bytes = 28ULL * 1024 * 1024 * 1024;  // 28GB
    size_t gpu1_budget_bytes = 14ULL * 1024 * 1024 * 1024;  // 14GB
    size_t ram_budget_bytes = 56ULL * 1024 * 1024 * 1024;   // 56GB
    std::string ssd_cache_path = "D:\\RawrXD_Cache\\";
    
    // Performance tuning
    uint32_t batch_size = 1;
    uint32_t num_concurrent_tokens = 1;
    bool enable_async_prefetch = true;
    bool enable_overlap = true;
    bool enable_kv_cache_compression = true;
    float kv_cache_quantization = 8.0f;  // FP8
    
    // Paths
    std::string model_weights_path;
    std::string tokenizer_path;
};

//=============================================================================
// Token Generation Result
//=============================================================================

struct GenerationResult {
    uint32_t token_id;
    float logit;
    float probability;
    std::chrono::steady_clock::time_point generation_time;
    
    // Performance metrics
    double latency_ms;
    double ttfb_ms;  // Time to first byte
    double throughput_tps;
    
    // Memory stats
    size_t gpu0_memory_used;
    size_t gpu1_memory_used;
    size_t ram_memory_used;
};

//=============================================================================
// Deep2Engine - Production Inference Engine
//=============================================================================

class Deep2Engine {
public:
    explicit Deep2Engine(const Deep2EngineConfig& config);
    ~Deep2Engine();
    
    // Initialize the full inference stack
    bool Initialize(VkDevice gpu0, VkDevice gpu1, VkQueue queue0, VkQueue queue1);
    void Shutdown();
    
    // Load model
    bool LoadModel(const std::string& model_path);
    bool LoadTokenizer(const std::string& tokenizer_path);
    
    // Token generation
    uint64_t GenerateToken(const std::vector<uint32_t>& input_tokens);
    bool WaitForToken(uint64_t token_id, uint32_t timeout_ms);
    GenerationResult GetTokenResult(uint64_t token_id);
    
    // Batch generation
    std::vector<uint64_t> GenerateTokensBatch(const std::vector<std::vector<uint32_t>>& input_batches);
    
    // Streaming generation
    using TokenCallback = std::function<void(uint32_t token_id, const GenerationResult& result)>;
    void GenerateStream(const std::vector<uint32_t>& input_tokens, TokenCallback callback);
    
    // Context management
    bool ExtendContext(const std::vector<uint32_t>& new_tokens);
    bool ClearContext();
    uint32_t GetContextLength() const;
    
    // Performance
    double GetThroughputTps() const;
    double GetAverageLatencyMs() const;
    std::string GetPerformanceReport() const;
    
    // Memory management
    void TriggerGarbageCollection();
    void CompactMemory();
    std::string GetMemoryReport() const;
    
    // Status
    bool IsInitialized() const { return initialized_; }
    bool IsGenerating() const { return generating_; }
    
private:
    Deep2EngineConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> generating_{false};
    std::atomic<bool> shutdown_{false};
    
    // Subsystems
    std::unique_ptr<Memory::SequentialBlowoffValve> blowoff_valve_;
    std::unique_ptr<OutOfCoreScheduler> scheduler_;
    std::unique_ptr<DualGpuPipeline> pipeline_;
    std::unique_ptr<Kernels::VulkanComputeKernels> kernels_;
    
    // Vulkan handles
    VkDevice gpu0_device_;
    VkDevice gpu1_device_;
    VkQueue gpu0_queue_;
    VkQueue gpu1_queue_;
    
    // Model state
    std::vector<uint32_t> context_tokens_;
    std::vector<float> kv_cache_gpu0_;
    std::vector<float> kv_cache_gpu1_;
    
    // Token tracking
    mutable std::mutex tokens_mutex_;
    std::unordered_map<uint64_t, GenerationResult> token_results_;
    uint64_t next_token_id_ = 1;
    
    // Performance tracking
    mutable std::mutex perf_mutex_;
    std::deque<double> latency_history_;
    std::deque<double> throughput_history_;
    uint64_t total_tokens_generated_ = 0;
    std::chrono::steady_clock::time_point start_time_;
    
    // Worker thread
    std::thread generation_thread_;
    std::condition_variable generation_cv_;
    mutable std::mutex generation_mutex_;
    std::queue<std::pair<uint64_t, std::vector<uint32_t>>> generation_queue_;
    
    // Internal methods
    void GenerationWorkerLoop();
    
    bool ExecuteTransformerLayer(uint32_t layer_id, 
                                  const std::vector<float>& input,
                                  std::vector<float>& output);
    
    bool ExecuteAttention(uint32_t layer_id,
                          const std::vector<float>& q,
                          const std::vector<float>& k,
                          const std::vector<float>& v,
                          std::vector<float>& output);
    
    bool ExecuteFFN(uint32_t layer_id,
                    const std::vector<float>& input,
                    std::vector<float>& output);
    
    uint32_t SampleToken(const std::vector<float>& logits);
    
    void UpdatePerformanceMetrics(const GenerationResult& result);
    
    bool InitializeSubsystems();
    void ShutdownSubsystems();
};

//=============================================================================
// Global Engine Access
//=============================================================================

Deep2Engine& GetDeep2Engine();
bool InitializeDeep2Engine(const Deep2EngineConfig& config);
void ShutdownDeep2Engine();

} // namespace Inference
} // namespace RawrXD

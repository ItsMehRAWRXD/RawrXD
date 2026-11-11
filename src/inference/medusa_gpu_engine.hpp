// ============================================================================
// Medusa GPU Engine - High-Performance Speculative Decoding
// ============================================================================
// Uses RX 7800 XT Vulkan compute for 100+ tok/s generation
// ============================================================================

#pragma once
#include <vulkan/vulkan.h>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Medusa Configuration
// ============================================================================
struct MedusaConfig {
    // Tree structure
    uint32_t num_heads = 4;           // Number of Medusa heads
    uint32_t tokens_per_head = 8;       // Tokens per head
    uint32_t max_depth = 32;            // Max tree depth
    
    // Performance
    uint32_t batch_size = 64;           // Process 64 candidates at once
    float acceptance_threshold = 0.6f;  // Min probability to accept
    float temperature = 0.7f;
    
    // Memory
    uint32_t max_context = 32768;         // 32K context window
    size_t vram_budget_mb = 14000;      // Leave 2GB for system
};

// ============================================================================
// GPU Buffer Management
// ============================================================================
struct GPUBuffer {
    VkBuffer buffer = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;
    void* mapped = nullptr;
    size_t size = 0;
    
    bool Allocate(VkDevice device, VkPhysicalDevice phys_device, size_t sz, 
                  VkBufferUsageFlags usage, VkMemoryPropertyFlags props);
    void Free(VkDevice device);
};

// ============================================================================
// Medusa Tree Node
// ============================================================================
struct MedusaNode {
    int32_t token_id = -1;
    float cumulative_prob = 0.0f;
    uint32_t parent_idx = 0;
    uint32_t depth = 0;
    bool verified = false;
};

// ============================================================================
// Main Medusa Engine
// ============================================================================
class MedusaGPUEngine {
public:
    MedusaGPUEngine();
    ~MedusaGPUEngine();
    
    // Initialize with Vulkan device
    bool Initialize(const MedusaConfig& config);
    void Shutdown();
    
    // Load model weights to GPU
    bool LoadModelWeights(const std::string& gguf_path, int ngl = 999);
    
    // Generate with Medusa speculative decoding
    std::vector<int32_t> Generate(const std::vector<int32_t>& prompt, 
                                   uint32_t max_new_tokens,
                                   std::function<void(const std::string&)> callback = nullptr);
    
    // Streaming generation
    void GenerateStreaming(const std::vector<int32_t>& prompt,
                          uint32_t max_new_tokens,
                          std::function<void(int32_t, const std::string&)> on_token);
    
    // Performance metrics
    float GetCurrentTPS() const { return current_tps_.load(); }
    float GetAverageLatency() const { return avg_latency_ms_.load(); }
    uint64_t GetTokensGenerated() const { return tokens_generated_.load(); }
    
    // Context management
    void SetContextWindow(uint32_t tokens);
    void ClearCache();
    
private:
    // Vulkan setup
    bool InitializeVulkan();
    bool CreateComputePipelines();
    bool CreateDescriptorSets();
    
    // Core operations
    bool RunMedusaForward(const std::vector<int32_t>& tokens, 
                          std::vector<float>& logits_out,
                          std::vector<std::vector<float>>& head_logits);
    std::vector<int32_t> BuildMedusaTree(const std::vector<float>& target_logits,
                                         const std::vector<std::vector<float>>& head_logits);
    bool VerifyCandidatesGPU(const std::vector<MedusaNode>& candidates,
                            std::vector<bool>& accepted);
    
    // Memory management
    bool AllocateKVCache(uint32_t max_tokens);
    void UpdateKVCache(const std::vector<int32_t>& new_tokens);
    
    // Shader dispatch
    void DispatchMatMul(const GPUBuffer& weights, const GPUBuffer& input, 
                        GPUBuffer& output, uint32_t M, uint32_t N, uint32_t K);
    void DispatchAttention(const GPUBuffer& q, const GPUBuffer& k, const GPUBuffer& v,
                          GPUBuffer& out, uint32_t seq_len, uint32_t head_dim);
    void DispatchSoftmax(GPUBuffer& logits, uint32_t count);
    
    // Vulkan handles
    VkInstance instance_ = VK_NULL_HANDLE;
    VkPhysicalDevice physical_device_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue compute_queue_ = VK_NULL_HANDLE;
    VkCommandPool cmd_pool_ = VK_NULL_HANDLE;
    VkDescriptorPool desc_pool_ = VK_NULL_HANDLE;
    
    // Compute pipelines
    VkPipeline matmul_pipeline_ = VK_NULL_HANDLE;
    VkPipeline attention_pipeline_ = VK_NULL_HANDLE;
    VkPipeline softmax_pipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout pipeline_layout_ = VK_NULL_HANDLE;
    
    // GPU memory
    GPUBuffer kv_cache_k_;
    GPUBuffer kv_cache_v_;
    GPUBuffer weight_buffer_;
    GPUBuffer input_buffer_;
    GPUBuffer output_buffer_;
    
    // Model state
    MedusaConfig config_;
    bool model_loaded_ = false;
    uint32_t vocab_size_ = 32000;
    uint32_t hidden_size_ = 4096;
    uint32_t num_layers_ = 32;
    
    // Performance tracking
    std::atomic<float> current_tps_{0.0f};
    std::atomic<float> avg_latency_ms_{0.0f};
    std::atomic<uint64_t> tokens_generated_{0};
    std::atomic<uint64_t> tokens_accepted_{0};
    std::atomic<uint64_t> tokens_rejected_{0};
    
    // Threading
    std::mutex vulkan_mutex_;
    std::thread metrics_thread_;
    std::atomic<bool> running_{false};
};

// ============================================================================
// Factory Function
// ============================================================================
std::unique_ptr<MedusaGPUEngine> CreateMedusaEngine(const MedusaConfig& config);

} // namespace Inference
} // namespace RawrXD

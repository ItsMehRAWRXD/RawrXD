// Dual GPU Inference Integration Header
// Connects DualGPUOrchestrator with RawrXD inference engine

#pragma once

#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <atomic>

namespace RawrXD {
namespace Inference {

// Inference configuration
struct InferenceConfig {
    int num_layers = 32;
    int num_heads = 32;
    int head_dim = 128;
    int max_seq_len = 8192;
    int vocab_size = 32000;
    
    // Parallelism settings
    int tensor_parallel_size = 1;
    int pipeline_parallel_size = 1;
    bool enable_layer_sharding = true;
    
    // Memory settings
    size_t kv_cache_size_per_gpu = 1024 * 1024 * 1024; // 1GB default
};

// Inference request
struct InferenceRequest {
    const void* input_tokens;
    int num_tokens;
    int max_new_tokens;
    float temperature = 1.0f;
    float top_p = 0.9f;
    int top_k = 40;
};

// Inference result
struct InferenceResult {
    bool success;
    int gpu_id; // -1 for multi-GPU
    void* output_tokens;
    int num_output_tokens;
    uint64_t compute_time_ms;
    std::string error_message;
};

// GPU inference metrics
struct GPUInferenceMetrics {
    int gpu_id;
    uint64_t tokens_processed;
    size_t kv_cache_size;
    size_t model_weights_size;
    float utilization_percent;
    bool is_active;
};

// Dual GPU inference context
class DualGPUInferenceContext {
public:
    DualGPUInferenceContext();
    ~DualGPUInferenceContext();
    
    // Lifecycle
    bool Initialize(const InferenceConfig& config);
    void Shutdown();
    bool IsInitialized() const { return impl_ && impl_->initialized_; }
    
    // Inference
    InferenceResult RunInference(const InferenceRequest& request);
    
    // KV Cache management
    bool AllocateKVCache(int gpu_id, size_t cache_size);
    bool DistributeKVCache(size_t total_cache_size);
    void* GetKVCache(int gpu_id) const;
    
    // Model weights
    bool LoadModelWeights(int gpu_id, const void* weights, size_t size);
    bool DistributeModelWeights(const void* weights, size_t total_size);
    
    // Performance
    std::vector<GPUInferenceMetrics> GetMetrics() const;
    void PrintMetrics() const;
    
    // Configuration
    int GetNumGPUs() const;
    bool IsDualGPUMode() const { return GetNumGPUs() >= 2; }
    
private:
    bool InitializeCPU(const InferenceConfig& config);
    void ShardModelLayers(int num_layers, int num_gpus);
    
    InferenceResult RunSingleGPUInference(const InferenceRequest& request, int gpu_id);
    InferenceResult RunDualGPUInference(const InferenceRequest& request);
    
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace Inference
} // namespace RawrXD

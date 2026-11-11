// Dual GPU Inference Integration
// Connects DualGPUOrchestrator with RawrXD inference engine

#include "dual_gpu_inference_integration.hpp"
#include "dual_gpu_orchestrator.hpp"
#include "rawrxd_inference.h"
#include <cstring>
#include <algorithm>

namespace RawrXD {
namespace Inference {

// ============================================================================
// DualGPUInferenceContext Implementation
// ============================================================================

class DualGPUInferenceContext::Impl {
public:
    struct GPUContext {
        int device_id;
        void* kv_cache;
        size_t kv_cache_size;
        void* model_weights;
        size_t model_weights_size;
        bool is_active;
        uint64_t tokens_processed;
    };
    
    std::vector<GPUContext> gpu_contexts_;
    std::atomic<bool> initialized_{false};
    
    // Model sharding info
    struct LayerShard {
        int start_layer;
        int end_layer;
        int gpu_id;
    };
    std::vector<LayerShard> layer_shards_;
    
    // Tensor parallelism config
    int tensor_parallel_size_ = 1;
    int pipeline_parallel_size_ = 1;
};

DualGPUInferenceContext::DualGPUInferenceContext() 
    : impl_(std::make_unique<Impl>()) {}

DualGPUInferenceContext::~DualGPUInferenceContext() {
    Shutdown();
}

bool DualGPUInferenceContext::Initialize(const InferenceConfig& config) {
    if (impl_->initialized_) return true;
    
    auto& orchestrator = GPU::DualGPUOrchestrator::Instance();
    if (!orchestrator.Initialize()) {
        return false;
    }
    
    auto devices = orchestrator.GetDeviceInfo();
    int num_gpus = static_cast<int>(devices.size());
    
    if (num_gpus == 0) {
        // CPU fallback
        return InitializeCPU(config);
    }
    
    // Initialize contexts for each GPU
    for (int i = 0; i < num_gpus; ++i) {
        Impl::GPUContext ctx;
        ctx.device_id = i;
        ctx.kv_cache = nullptr;
        ctx.kv_cache_size = 0;
        ctx.model_weights = nullptr;
        ctx.model_weights_size = 0;
        ctx.is_active = true;
        ctx.tokens_processed = 0;
        
        impl_->gpu_contexts_.push_back(ctx);
    }
    
    // Shard model layers across GPUs
    if (num_gpus >= 2 && config.enable_layer_sharding) {
        ShardModelLayers(config.num_layers, num_gpus);
    }
    
    impl_->tensor_parallel_size_ = config.tensor_parallel_size;
    impl_->pipeline_parallel_size_ = config.pipeline_parallel_size;
    
    impl_->initialized_ = true;
    return true;
}

void DualGPUInferenceContext::Shutdown() {
    if (!impl_->initialized_) return;
    
    // Free all GPU memory
    auto& orchestrator = GPU::DualGPUOrchestrator::Instance();
    
    for (auto& ctx : impl_->gpu_contexts_) {
        if (ctx.kv_cache) {
            orchestrator.FreeMemory(ctx.kv_cache);
            ctx.kv_cache = nullptr;
        }
        if (ctx.model_weights) {
            orchestrator.FreeMemory(ctx.model_weights);
            ctx.model_weights = nullptr;
        }
    }
    
    impl_->gpu_contexts_.clear();
    impl_->layer_shards_.clear();
    impl_->initialized_ = false;
}

bool DualGPUInferenceContext::InitializeCPU(const InferenceConfig& config) {
    // CPU fallback implementation
    Impl::GPUContext ctx;
    ctx.device_id = -1; // CPU
    ctx.is_active = true;
    impl_->gpu_contexts_.push_back(ctx);
    return true;
}

void DualGPUInferenceContext::ShardModelLayers(int num_layers, int num_gpus) {
    impl_->layer_shards_.clear();
    
    int layers_per_gpu = num_layers / num_gpus;
    int remainder = num_layers % num_gpus;
    
    int current_layer = 0;
    for (int gpu = 0; gpu < num_gpus; ++gpu) {
        int start = current_layer;
        int count = layers_per_gpu + (gpu < remainder ? 1 : 0);
        int end = start + count - 1;
        
        Impl::LayerShard shard;
        shard.start_layer = start;
        shard.end_layer = end;
        shard.gpu_id = gpu;
        
        impl_->layer_shards_.push_back(shard);
        current_layer = end + 1;
    }
}

// ============================================================================
// Inference Execution
// ============================================================================

InferenceResult DualGPUInferenceContext::RunInference(const InferenceRequest& request) {
    InferenceResult result;
    result.success = false;
    
    if (!impl_->initialized_) {
        result.error_message = "Context not initialized";
        return result;
    }
    
    auto& orchestrator = GPU::DualGPUOrchestrator::Instance();
    
    if (impl_->gpu_contexts_.size() == 1) {
        // Single GPU or CPU mode
        result = RunSingleGPUInference(request, 0);
    } else {
        // Dual GPU mode
        result = RunDualGPUInference(request);
    }
    
    return result;
}

InferenceResult DualGPUInferenceContext::RunSingleGPUInference(
    const InferenceRequest& request, 
    int gpu_id
) {
    InferenceResult result;
    result.success = true;
    result.gpu_id = gpu_id;
    
    // Create work item
    GPU::GPUWorkItem work;
    work.type = GPU::GPUWorkType::INFERENCE;
    work.preferred_device = gpu_id;
    work.input_data = const_cast<void*>(request.input_tokens);
    work.data_size = request.num_tokens * sizeof(int32_t);
    
    // Submit and wait
    auto future = GPU::DualGPUOrchestrator::Instance().SubmitWorkAsync(work);
    auto gpu_result = future.get();
    
    if (!gpu_result.success) {
        result.success = false;
        result.error_message = gpu_result.error_message;
    }
    
    return result;
}

InferenceResult DualGPUInferenceContext::RunDualGPUInference(
    const InferenceRequest& request
) {
    InferenceResult result;
    result.success = true;
    result.gpu_id = -1; // Multi-GPU
    
    // Pipeline parallelism: alternate GPUs per layer
    for (const auto& shard : impl_->layer_shards_) {
        GPU::GPUWorkItem work;
        work.type = GPU::GPUWorkType::INFERENCE;
        work.preferred_device = shard.gpu_id;
        work.input_data = const_cast<void*>(request.input_tokens);
        work.data_size = request.num_tokens * sizeof(int32_t);
        
        auto future = GPU::DualGPUOrchestrator::Instance().SubmitWorkAsync(work);
        auto gpu_result = future.get();
        
        if (!gpu_result.success) {
            result.success = false;
            result.error_message = gpu_result.error_message;
            break;
        }
    }
    
    return result;
}

// ============================================================================
// KV Cache Management
// ============================================================================

bool DualGPUInferenceContext::AllocateKVCache(int gpu_id, size_t cache_size) {
    if (gpu_id < 0 || gpu_id >= static_cast<int>(impl_->gpu_contexts_.size())) {
        return false;
    }
    
    auto& ctx = impl_->gpu_contexts_[gpu_id];
    
    if (ctx.kv_cache) {
        GPU::DualGPUOrchestrator::Instance().FreeMemory(ctx.kv_cache);
    }
    
    ctx.kv_cache = GPU::DualGPUOrchestrator::Instance().AllocateMemory(cache_size, gpu_id);
    ctx.kv_cache_size = cache_size;
    
    return ctx.kv_cache != nullptr;
}

bool DualGPUInferenceContext::DistributeKVCache(size_t total_cache_size) {
    if (impl_->gpu_contexts_.size() <= 1) {
        // Single GPU gets all
        return AllocateKVCache(0, total_cache_size);
    }
    
    // Split evenly between GPUs
    size_t per_gpu = total_cache_size / impl_->gpu_contexts_.size();
    
    for (size_t i = 0; i < impl_->gpu_contexts_.size(); ++i) {
        if (!AllocateKVCache(static_cast<int>(i), per_gpu)) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Model Loading
// ============================================================================

bool DualGPUInferenceContext::LoadModelWeights(int gpu_id, const void* weights, size_t size) {
    if (gpu_id < 0 || gpu_id >= static_cast<int>(impl_->gpu_contexts_.size())) {
        return false;
    }
    
    auto& ctx = impl_->gpu_contexts_[gpu_id];
    
    // Allocate GPU memory
    ctx.model_weights = GPU::DualGPUOrchestrator::Instance().AllocateMemory(size, gpu_id);
    if (!ctx.model_weights) {
        return false;
    }
    
    // Copy weights to GPU
    GPU::GPUWorkItem work;
    work.type = GPU::GPUWorkType::MEMORY_COPY;
    work.preferred_device = gpu_id;
    work.input_data = const_cast<void*>(weights);
    work.output_data = ctx.model_weights;
    work.data_size = size;
    
    auto future = GPU::DualGPUOrchestrator::Instance().SubmitWorkAsync(work);
    auto result = future.get();
    
    if (!result.success) {
        GPU::DualGPUOrchestrator::Instance().FreeMemory(ctx.model_weights);
        ctx.model_weights = nullptr;
        return false;
    }
    
    ctx.model_weights_size = size;
    return true;
}

bool DualGPUInferenceContext::DistributeModelWeights(const void* weights, size_t total_size) {
    if (impl_->gpu_contexts_.size() <= 1) {
        // Single GPU gets all
        return LoadModelWeights(0, weights, total_size);
    }
    
    // Split by layer shards
    for (const auto& shard : impl_->layer_shards_) {
        // Calculate size for this shard
        size_t shard_size = total_size / impl_->layer_shards_.size();
        const uint8_t* shard_weights = static_cast<const uint8_t*>(weights) + 
                                       (shard.start_layer * shard_size);
        
        if (!LoadModelWeights(shard.gpu_id, shard_weights, shard_size)) {
            return false;
        }
    }
    
    return true;
}

// ============================================================================
// Performance Monitoring
// ============================================================================

std::vector<GPUInferenceMetrics> DualGPUInferenceContext::GetMetrics() const {
    std::vector<GPUInferenceMetrics> metrics;
    
    for (const auto& ctx : impl_->gpu_contexts_) {
        GPUInferenceMetrics m;
        m.gpu_id = ctx.device_id;
        m.tokens_processed = ctx.tokens_processed;
        m.kv_cache_size = ctx.kv_cache_size;
        m.model_weights_size = ctx.model_weights_size;
        m.is_active = ctx.is_active;
        
        // Get GPU metrics from orchestrator
        auto gpu_metrics = GPU::DualGPUOrchestrator::Instance().GetPerformanceMetrics(ctx.device_id);
        m.utilization_percent = gpu_metrics.utilization_percent;
        
        metrics.push_back(m);
    }
    
    return metrics;
}

void DualGPUInferenceContext::PrintMetrics() const {
    auto metrics = GetMetrics();
    
    std::cout << "=== Dual GPU Inference Metrics ===" << std::endl;
    for (const auto& m : metrics) {
        std::cout << "GPU " << m.gpu_id << ":" << std::endl;
        std::cout << "  Tokens: " << m.tokens_processed << std::endl;
        std::cout << "  KV Cache: " << (m.kv_cache_size / 1024 / 1024) << " MB" << std::endl;
        std::cout << "  Weights: " << (m.model_weights_size / 1024 / 1024) << " MB" << std::endl;
        std::cout << "  Utilization: " << m.utilization_percent << "%" << std::endl;
    }
}

} // namespace Inference
} // namespace RawrXD

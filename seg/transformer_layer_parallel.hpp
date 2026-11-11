// ============================================================================
// Multi-threaded Transformer Layer
// ============================================================================
// Parallelizes attention heads and FFN operations across CPU cores
// ============================================================================

#pragma once

#include "transformer_layer_inference.hpp"
#include "thread_pool.hpp"
#include <vector>
#include <future>

namespace RawrXD {
namespace Inference {

// Multi-threaded transformer layer
class ParallelTransformerLayer : public TransformerLayer {
public:
    ParallelTransformerLayer(const TransformerConfig& config);
    
    // Override forward pass with parallel execution
    bool ForwardParallel(const float* input, float* output,
                         KVCache& kv_cache, uint32_t position);
    
    // Set number of threads (0 = auto)
    void SetNumThreads(size_t num_threads);
    
    // Get number of threads
    size_t GetNumThreads() const { return num_threads_; }

private:
    // Parallel attention over heads
    void AttentionForwardParallel(const float* Q, const float* K, const float* V,
                                   float* output, KVCache& kv_cache, uint32_t position);
    
    // Parallel FFN computation
    void FFNForwardParallel(const float* input, float* output);
    
    // Parallel matrix multiplication - splits N dimension across threads
    void ParallelMatMul(const float* A, const float* B, float* C,
                        uint32_t M, uint32_t K, uint32_t N);
    
    // Thread pool for parallel execution
    ThreadPool thread_pool_;
    size_t num_threads_ = 0;
    
    // Per-thread buffers to avoid false sharing
    struct ThreadBuffers {
        std::vector<float> scores;
        std::vector<float> out_head;
    };
    std::vector<ThreadBuffers> thread_buffers_;
};

} // namespace Inference
} // namespace RawrXD

// ============================================================================
// Deep2Engine.h - Production Inference Engine
// Combines: ThreadPool + KVCache + Deep2 Kernels + Quantization
// ============================================================================

#ifndef DEEP2_ENGINE_H
#define DEEP2_ENGINE_H

#include "ThreadPool.h"
#include "KVCache.h"
#include <memory>
#include <string>

namespace Deep2 {

// ============================================================================
// Engine Configuration
// ============================================================================
struct EngineConfig {
    // Model architecture
    size_t hiddenDim = 4096;
    size_t numLayers = 32;
    size_t numHeads = 32;
    size_t vocabSize = 32000;
    
    // Inference settings
    size_t maxSeqLen = 2048;
    size_t numThreads = 0;  // 0 = auto
    
    // Quantization
    enum QuantType { Q4_0, Q4_K_M, Q8_0, FP16, FP32 };
    QuantType weightQuant = FP32;
    QuantType kvCacheQuant = FP32;
    
    // KV Cache
    bool useKVCache = true;
    
    // Performance
    bool useThreadPool = true;
    bool pinThreads = true;
};

// ============================================================================
// Inference Statistics
// ============================================================================
struct InferenceStats {
    double tokensPerSecond = 0.0;
    double latencyMs = 0.0;
    size_t tokensGenerated = 0;
    size_t cacheHits = 0;
    size_t cacheMisses = 0;
    double memoryBandwidthGBps = 0.0;
};

// ============================================================================
// Production Deep2 Engine
// ============================================================================
class Deep2Engine {
public:
    Deep2Engine();
    ~Deep2Engine();
    
    // Initialize with configuration
    bool initialize(const EngineConfig& config);
    
    // Load model weights (from GGUF or other format)
    bool loadWeights(const void* weightData, size_t weightSize);
    
    // Generate tokens
    // Returns number of tokens generated
    size_t generate(const int* promptTokens, size_t promptLen,
                   int* outputTokens, size_t maxOutputLen,
                   InferenceStats* stats = nullptr);
    
    // Reset state for new conversation
    void reset();
    
    // Get engine info
    bool isInitialized() const { return initialized; }
    const EngineConfig& getConfig() const { return config; }
    
    // Performance tuning
    void setNumThreads(size_t numThreads);
    void enableKVCache(bool enable);
    
private:
    EngineConfig config;
    std::unique_ptr<ThreadPool> threadPool;
    std::unique_ptr<KVCache> kvCache;
    
    // Weight tensors (simplified - real implementation uses GGUF)
    float* weights = nullptr;
    size_t weightSize = 0;
    
    // Buffers
    float* hiddenStates = nullptr;
    float* attentionOutput = nullptr;
    float* ffnOutput = nullptr;
    
    bool initialized = false;
    
    // Internal methods
    bool allocateBuffers();
    void deallocateBuffers();
    
    // Transformer layer forward pass
    void forwardLayer(size_t layer, const float* input, float* output, size_t seqLen);
    
    // Attention with optional KV cache
    void computeAttention(size_t layer, const float* input, float* output, size_t seqLen);
    
    // FFN (SwiGLU)
    void computeFFN(size_t layer, const float* input, float* output);
    
    // Sampling
    int sampleToken(const float* logits);
};

} // namespace Deep2

#endif // DEEP2_ENGINE_H

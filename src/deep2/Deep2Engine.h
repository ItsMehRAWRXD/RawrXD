// ============================================================================
// Deep2Engine.h - Production Inference Engine
// Combines: ThreadPool + KVCache + Deep2 Kernels + Quantization + Real Weights
// ============================================================================

#ifndef DEEP2_ENGINE_H
#define DEEP2_ENGINE_H

#include "ThreadPool.h"
#include "KVCache.h"
#include "GGUFLoader.hpp"
#include "Tokenizer.hpp"
#include "../sampling/advanced_sampler.hpp"#include "MoERouter.hpp"
#include "MoEWeightProxy.hpp"#include <memory>
#include <string>
#include <vector>

namespace Deep2 {

// ============================================================================
// Weight Tensor - Real quantized weight storage
// ============================================================================
struct WeightTensor {
    void*       data      = nullptr;  // Raw weight data (quantized or FP32)
    int         type      = 0;        // GGMLType enum value
    size_t      rows      = 0;        // Output dimension
    size_t      cols      = 0;        // Input dimension
    size_t      numBlocks = 0;        // For quantized types
    size_t      sizeBytes = 0;        // Total bytes
    std::string name;                 // Tensor name from GGUF
};

// ============================================================================
// Per-Layer Weights - Real transformer layer weight set
// ============================================================================
struct LayerWeights {
    // Attention
    WeightTensor wq;          // [hiddenDim, hiddenDim]
    WeightTensor wk;          // [kvDim, hiddenDim]
    WeightTensor wv;          // [kvDim, hiddenDim]
    WeightTensor wo;          // [hiddenDim, hiddenDim]
    WeightTensor attnNorm;    // [hiddenDim] RMSNorm weights

    // FFN
    WeightTensor wGate;       // [intermediateDim, hiddenDim]
    WeightTensor wUp;         // [intermediateDim, hiddenDim]
    WeightTensor wDown;       // [hiddenDim, intermediateDim]
    WeightTensor ffnNorm;     // [hiddenDim] RMSNorm weights

    // MoE (optional - if numExperts > 0)
    WeightTensor moeRouter;   // [numExperts, hiddenDim]
    std::vector<WeightTensor> moeGate;  // [numExperts][intermediateDim, hiddenDim]
    std::vector<WeightTensor> moeUp;    // [numExperts][intermediateDim, hiddenDim]
    std::vector<WeightTensor> moeDown;  // [numExperts][hiddenDim, intermediateDim]
    WeightTensor moeSharedGate;  // [sharedIntermediate, hiddenDim]
    WeightTensor moeSharedUp;    // [sharedIntermediate, hiddenDim]
    WeightTensor moeSharedDown;  // [hiddenDim, sharedIntermediate]
};

// ============================================================================
// Model Weights - Complete weight set for inference
// ============================================================================
struct ModelWeights {
    WeightTensor tokenEmbed;  // [vocabSize, hiddenDim]
    WeightTensor lmHead;      // [vocabSize, hiddenDim] (may share with embed)
    WeightTensor finalNorm;   // [hiddenDim] RMSNorm weights
    std::vector<LayerWeights> layers;

    // Architecture metadata
    size_t hiddenDim      = 0;
    size_t numLayers      = 0;
    size_t numHeads       = 0;
    size_t numKVHeads     = 0;
    size_t headDim        = 0;
    size_t vocabSize      = 0;
    size_t intermediateDim = 0;
    size_t moeIntermediateDim = 0;
    size_t numExperts     = 0;
    size_t numExpertsPerToken = 0;
    size_t numSharedExperts = 0;
    float  ropeTheta      = 10000.0f;
    float  ropeScaling    = 1.0f;
    float  normEps        = 1e-6f;
    bool   tieEmbeddings  = false;
    bool   isMoE          = false;
    bool   loaded         = false;
};

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

    // RoPE
    bool useRoPE = true;
    
    // Model path for GGUF loading
    std::string modelPath;
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
    
    // Load model from GGUF file
    bool loadModel(const std::string& ggufPath);
    
    // Load model weights (legacy API - from memory buffer)
    bool loadWeights(const void* weightData, size_t weightSize);
    
    // Tokenize text
    std::vector<int> tokenize(const std::string& text);
    
    // Detokenize tokens
    std::string detokenize(const std::vector<int>& tokens);
    
    // Generate tokens
    // Returns number of tokens generated
    size_t generate(const int* promptTokens, size_t promptLen,
                   int* outputTokens, size_t maxOutputLen,
                   InferenceStats* stats = nullptr);
    
    // Generate text (high-level API)
    std::string generateText(const std::string& prompt, size_t maxTokens = 256);
    
    // Reset state for new conversation
    void reset();
    
    // Get engine info
    bool isInitialized() const { return initialized; }
    bool isModelLoaded() const { return modelWeights.loaded; }
    const EngineConfig& getConfig() const { return config; }
    const ModelWeights& getModelWeights() const { return modelWeights; }
    
    // Performance tuning
    void setNumThreads(size_t numThreads);
    void enableKVCache(bool enable);
    
    // Linear layer with quantization support
    // Returns weight index for use in Linear()
    int registerWeightTensor(void* data, int type, size_t rows, size_t cols);
    
    // Matrix-vector multiplication: output = weights * input + bias
    void Linear(int weightIdx, const float* input, const float* bias, 
                float* output, size_t outDim);
    
    // Linear using WeightTensor directly
    void LinearW(const WeightTensor& wt, const float* input, const float* bias,
                 float* output, size_t outDim);
    
    // Parallel version using ThreadPool
    void LinearParallel(int weightIdx, const float* input, const float* bias,
                        float* output, size_t outDim);
    
    // RMSNorm with weights: output = weight * x / sqrt(mean(x^2) + eps)
    void RMSNormW(const WeightTensor& normWeight, const float* input,
                  float* output, size_t dim, float eps);
    
    // RoPE: apply rotary position embedding
    void applyRoPE(float* q, float* k, size_t headDim, size_t numHeads,
                   size_t numKVHeads, size_t pos, float theta, float scaling);
    
    // SwiGLU activation: output = silu(gate) * up
    void SwiGLU(const float* gate, const float* up, float* output, size_t dim);
    
    // Set sampler
    void setSampler(std::unique_ptr<ISampler> sampler);
    
private:
    EngineConfig config;
    std::unique_ptr<ThreadPool> threadPool;
    std::unique_ptr<KVCache> kvCache;
    std::unique_ptr<ISampler> sampler;
    std::unique_ptr<ITokenizer> tokenizer;
    
    // Real model weights
    ModelWeights modelWeights;
    
    // MoE infrastructure (real, not stubbed)
    std::unique_ptr<MoERouter> moeRouter_;
    std::unique_ptr<MoELayer> moeLayer_;
    std::unique_ptr<MoEWeightsLoader> moeWeightsLoader_;
    std::unique_ptr<MoEWeightProxy> moeWeightProxy_;
    MoEConfig moeConfig_;
    bool moeInitialized_ = false;
    
    // MoE per-layer expert weight cache (layer -> expert -> handle)
    // Pinned during inference to prevent eviction
    std::vector<std::vector<MoEWeightHandle>> moePinnedHandles_;
    
    // GGUF load result (kept for tensor lookup)
    GGUFLoadResult ggufResult;
    
    // Weight tensors (legacy registration system)
    float* weights = nullptr;
    size_t weightSize = 0;
    
    // Buffers
    float* hiddenStates = nullptr;
    float* attentionOutput = nullptr;
    float* ffnOutput = nullptr;
    float* logits = nullptr;
    float* qProj = nullptr;
    float* kProj = nullptr;
    float* vProj = nullptr;
    float* gateBuf = nullptr;
    float* upBuf = nullptr;
    
    bool initialized = false;
    
    // Internal methods
    bool allocateBuffers();
    void deallocateBuffers();
    
    // Transformer layer forward pass (real implementation)
    void forwardLayer(size_t layer, const float* input, float* output, size_t seqLen);
    
    // Attention with real weight projections
    void computeAttention(size_t layer, const float* input, float* output, size_t seqLen);
    
    // FFN (SwiGLU) with real weight projections
    void computeFFN(size_t layer, const float* input, float* output);
    
    // MoE FFN - real routed expert execution (no dense fallback)
    void computeMoEFFN(size_t layer, const float* input, float* output);
    
    // MoE expert FFN via streamed weights (gate/up/down projections)
    void computeExpertFFN(const MoEWeightHandle& handle,
                          const float* input, float* output,
                          size_t hiddenDim, size_t expertDim);
    
    // Shared expert FFN
    void computeSharedExpertFFN(size_t layer, const float* input, float* output);
    
    // Token embedding lookup
    void embedToken(int tokenId, float* output);
    
    // LM head projection: hiddenDim -> vocabSize
    void computeLogits(const float* hiddenState, float* logits);
    
    // Sampling
    int sampleToken(const float* logits);
    
    // Find tensor in GGUF by name pattern
    WeightTensor* findTensor(const std::string& namePattern);
    
    // Load a tensor from GGUF into WeightTensor
    bool loadTensorFromGGUF(WeightTensor& wt, const std::string& name);
};

} // namespace Deep2

#endif // DEEP2_ENGINE_H

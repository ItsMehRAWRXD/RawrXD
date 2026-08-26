// ============================================================================
// Deep2Engine.h - Production Inference Engine
// Combines: ThreadPool + KVCache + Deep2 Kernels + Quantization + Real Weights
// ============================================================================

#ifndef DEEP2_ENGINE_H
#define DEEP2_ENGINE_H

#include "ReverseIntegration.hpp"
#include "mars/MARSController.hpp"
#include "ThreadPool.h"
#include "KVCache.h"
#include "GGUFLoader.hpp"
#include "BP16Streamer.hpp"
#include "Tokenizer.hpp"
#include "../sampling/advanced_sampler.hpp"
#include "MoERouter.hpp"
#include "MoEWeightProxy.hpp"
#include "MedusaDecoder.hpp"
#include "NUFusedPacker.hpp"
#include "WarmupScheduler.hpp"
#include "CompressedKVCache.h"
#include "NVMeStream.h"
#include "SlidingWindowEngine.h"
#include "K2GlobalTensorIndex.hpp"
#include "TensorResidencyCache.hpp"
#include "ResidencyManager.hpp"
#include "ElasticResidencyManager.hpp"
#include "RouterPrefetchTelemetry.hpp"
#include "ProductionProfiler.hpp"
// Sovereign Engine components (Dragon Lore)
#include "Chamber.hpp"
#include "ToroidalKVCache.hpp"
#include "PlasmaGovernor.hpp"
#include "SovereignOutOfCoreRuntime.hpp"
// Vulkan GPU backend
#include "vulkan_compute.h"
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <unordered_map>

namespace Deep2 {

// Forward declarations
class ReverseIntegration;
class Deep2TelemetryController;

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

    // BP16 / external mapping support
    bool        mapped    = false;    // true if data is externally owned (do not free)
};

// ============================================================================
// Per-Layer Weights - Real transformer layer weight set
// ============================================================================
struct LayerWeights {
    // Standard Multi-Head Attention (MHA / GQA)
    WeightTensor wq;          // [hiddenDim, hiddenDim]
    WeightTensor wk;          // [kvDim, hiddenDim]
    WeightTensor wv;          // [kvDim, hiddenDim]
    WeightTensor wo;          // [hiddenDim, hiddenDim]
    WeightTensor wqkv;        // [hiddenDim + 2*kvDim, hiddenDim] fused QKV (Phi-3, etc.)
    WeightTensor attnNorm;    // [hiddenDim] RMSNorm weights

    // MLA (Multi-Latent Attention) — K2 factorized attention
    // Q-path: hidden → q_a (GEMV) → RMSNorm → q_b (GEMV)
    WeightTensor attnQ_a;        // [qLoraRank, hiddenDim]
    WeightTensor attnQ_a_norm;   // [qLoraRank] RMSNorm weights
    WeightTensor attnQ_b;        // [numHeads * headDim, qLoraRank]
    // KV-path: hidden → kv_a_mqa (GEMV) → split → [compressed_kv | k_pe]
    //          → RMSNorm → kv_b (GEMV) → k_b / v_b
    WeightTensor attnKV_a_mqa;   // [kvLoraRank + qkRopeHeadDim, hiddenDim]
    WeightTensor attnKV_a_norm;  // [kvLoraRank] RMSNorm weights
    WeightTensor attnK_b;        // [numHeads * qkNopeHeadDim, kvLoraRank]
    WeightTensor attnV_b;        // [numHeads * vHeadDim, kvLoraRank]
    WeightTensor attnO;          // [hiddenDim, numHeads * headDim]
    bool         useMLA = false; // true when MLA tensors are populated

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

    // MLA (K2) architecture fields
    size_t qLoraRank      = 0;
    size_t kvLoraRank     = 0;
    size_t qkNopeHeadDim  = 0;
    size_t qkRopeHeadDim  = 0;
    size_t vHeadDim       = 0;
    size_t keyLength      = 0;
    size_t valueLength    = 0;
    size_t keyLengthMla   = 0;
    size_t valueLengthMla = 0;
    size_t ropeDimensionCount = 0;
    bool   useMLA         = false;

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
    size_t numKVHeads = 32;
    size_t headDim = 128;
    size_t vocabSize = 32000;
    size_t intermediateDim = 11008;

    // MLA (K2) architecture fields
    size_t qLoraRank = 0;
    size_t kvLoraRank = 0;
    size_t qkNopeHeadDim = 0;
    size_t qkRopeHeadDim = 0;
    size_t vHeadDim = 0;
    bool   useMLA = false;
    
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
    float ropeTheta = 10000.0f;
    float ropeScaling = 1.0f;
    float normEps = 1e-6f;
    
    // Model path for GGUF loading (fixed size for C API compatibility)
    char modelPath[512] = {};
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
// Native Streaming Generation
// ============================================================================

struct GenerationOptions {
    uint32_t maxTokens = 2048;

    float temperature = 0.8f;
    float topP = 0.95f;

    uint32_t topK = 40;

    float repeatPenalty = 1.0f;

    uint64_t seed = 0;
};

struct GenerationResult {
    uint64_t promptTokens = 0;
    uint64_t generatedTokens = 0;

    double promptTimeMs = 0.0;
    double generationTimeMs = 0.0;

    bool cancelled = false;
    bool completed = false;
};

using TokenCallback =
    std::function<bool(int32_t tokenId, const std::string& token)>;

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

    // Load model from BP16 file (exact weight extraction, no dequantization)
    bool loadModelFromBP16(const std::string& bp16Path);

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
                    InferenceStats* stats = nullptr,
                    std::function<bool(int)> onToken = nullptr);
    // Generate text (high-level API)
    std::string generateText(const std::string& prompt, size_t maxTokens = 256);
    
    // Generate text with chat template formatting (for instruction-tuned models)
    std::string generateChat(const std::string& userMessage, 
                             const std::string& systemPrompt = "",
                             size_t maxTokens = 256);

    // Native streaming generation — token-by-token with cancellation
    GenerationResult generateStream(
        const std::string& prompt,
        const GenerationOptions& options,
        TokenCallback callback);

    // Dynamic model metadata from GGUF
    const ModelMetadata& getModelMetadata() const;

    // Public bridge for the extern "C" Deep2_Forward C-API to drive a single
    // transformer layer forward pass without exposing internal buffers.
    void forwardLayerPublic(size_t layer, const float* input, float* output, size_t seqLen) {
        forwardLayer(layer, input, output, seqLen);
    }
    // Reset state for new conversation
    void reset();
    
    // Unload model and free weight memory
    void unloadModel();
    
    // Get engine info
    bool isInitialized() const { return initialized; }
    bool isModelLoaded() const { return modelWeights.loaded; }
    const EngineConfig& getConfig() const { return config; }
    const ModelWeights& getModelWeights() const { return modelWeights; }
    
    // Backend identity for certification
    static constexpr const char* backendName() noexcept { return "Deep2Engine/Sovereign"; }
    static constexpr const char* backendId() noexcept { return "DEEP2_SOVEREIGN"; }
    
    // API Server helpers
    size_t getWeightSize() const { return weightSize; }
    std::string getModelPath() const { return config.modelPath; }
    
    // Performance tuning
    void setNumThreads(size_t numThreads);
    void enableKVCache(bool enable);

    // Batch 15: Elastic residency control
    void enableElasticResidency(bool enable);
    bool isElasticResidencyEnabled() const { return elasticResidencyEnabled_; }
    ElasticResidencyManager* getElasticResidencyManager() const { return elasticResidency_.get(); }

    // Router-driven prefetch telemetry
    void enableResidencyTelemetry(bool enable);
    bool isResidencyTelemetryEnabled() const { return telemetryEnabled_; }
    RouterPrefetchTelemetry* getResidencyTelemetry() const { return residencyTelemetry_.get(); }
    void printResidencyTelemetryReport() const;

    // Async Vulkan prefetch state management
    void setAsyncPrefetchEnabled(bool enable) { asyncPrefetchEnabled_ = enable; }
    bool isAsyncPrefetchEnabled() const { return asyncPrefetchEnabled_; }

    // Production profiler (Batch 1)
    void enableProfiling(bool enable);
    bool isProfilingEnabled() const { return profilingEnabled_; }
    const std::vector<TokenProfile>& getProfileHistory() const { return profileHistory_; }
    bool saveProfileJSON(const std::string& path) const;
    std::string getProfileJSONSummary() const;

    // Sovereign Engine: Chamber (SM0-DSP) integration
    void enableChamber(bool enable);
    bool isChamberEnabled() const { return chamberEnabled_; }
    rawrxd::ChamberResult evaluateChamber(const float* hidden_state, size_t dim);
    rawrxd::FormulaRoute routePrimitive(uint64_t context_hash);

    // Sovereign Engine: ToroidalKVCache (infinite context)
    void enableToroidalKV(bool enable, size_t maxTokens = 131072);
    bool isToroidalKVEnabled() const { return toroidalKVEnabled_; }

    // Sovereign Engine: PlasmaGovernor (thermal safety)
    void enablePlasmaGovernor(bool enable);
    bool isPlasmaGovernorEnabled() const { return plasmaGovernorEnabled_; }
    void updateThermalState(const rawrxd::ThermalState& state);
    float currentThrottle() const;

    // Sovereign Engine: OutOfCoreRuntime dual-backend orchestrator
    void enableSovereignRuntime(bool enable);
    bool isSovereignRuntimeEnabled() const { return sovereignRuntimeEnabled_; }
    rawrxd::SovereignOutOfCoreRuntime* getSovereignRuntime() const;

    // Vulkan GPU backend
    void enableVulkan(bool enable);
    bool isVulkanEnabled() const { return vulkanEnabled_; }
    bool isVulkanInitialized() const { return vulkanInitialized_; }
    CPUInference::VulkanCompute* getVulkanCompute() const { return vulkanCompute_.get(); }
    // GPU dispatch for GEMV: returns true if dispatched on GPU, false if CPU fallback needed
    bool tryVulkanGEMV(const WeightTensor& wt, const float* input, float* output, size_t outDim);

    // VAL-000 Phase 3: Advanced feature control
    void enableMedusa(bool enable);
    void enableNUPacking(bool enable);
    void enableWarmupScheduler(bool enable);
    void enableCompressedKV(bool enable, KVQuantType quantType = KVQuantType::KV_Q8_0);
    void enableNVMeStreaming(bool enable, const std::string& modelPath = "");
    void enableSlidingWindow(bool enable, size_t windowSize = 4096);
    
    // BigDaddyG Reverse Engine integration
    void enableReverseAnalysis(bool enable);
    void disableReverseAnalysis();
    ReverseIntegration* getReverseIntegration() const;
    
    // HotPatcher integration - The Bottle
    void printHotPatcherStatus();
    std::string registerKernelPatch(
        const std::string& kernelName,
        void* originalKernel,
        void* newKernel,
        float expectedSpeedup = 1.0f);
    bool rollbackKernelPatch(const std::string& patchId);
    void emergencyRollbackAllPatches();
    
    // Tool Call Limit Extension via Hotpatching
    // Dynamically extends the maximum tool iterations limit at runtime
    // Returns patch ID on success, empty string on failure
    std::string extendToolCallLimit(int newMaxIterations);
    
    // Get current tool call limit (returns -1 if not patched)
    int getExtendedToolCallLimit() const;
    
    // Get feature stats
    const MedusaStats& getMedusaStats() const;
    const WarmupStats& getWarmupStats() const;
    const NUFusedPacker::Stats& getNUPackerStats() const;
    
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
    void setSampler(std::unique_ptr<rawrxd::sampling::ISampler> sampler);

    // Token embedding lookup (public for tree speculative decoding)
    void embedToken(int tokenId, float* output);

    // LM head projection: hiddenDim -> vocabSize (public for tree speculative decoding)
    void computeLogits(const float* hiddenState, float* logits);

    // ------------------------------------------------------------------------
    // MARS: Dynamic Dual-GPU VRAM Hotpatch
    // ------------------------------------------------------------------------
    // Enable MARS with specified VRAM sizes (bytes)
    bool enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes);
    void disableMARS();
    bool isMARSEnabled() const { return marsEnabled_; }

    // Place a model tensor under MARS lease control
    MARS::VRAMLease* placeTensorMARS(
        uint64_t tensorId,
        const std::string& name,
        size_t bytes,
        float priority = 1.0f);

    // Hotpatch redirect a tensor to a different GPU
    MARS::HotpatchResult redirectTensor(uint64_t tensorId, int targetGPU);

    // Rebalance VRAM across GPUs
    void rebalanceMARS();

    // Get current dynamic parity state
    MARS::DynamicParity getDynamicParity() const;

    // Handle tensor fault (reverse recovery)
    bool handleTensorFault(uint64_t tensorId);

    // Handle GPU failure (migrate all tensors off)
    bool handleGPUFailure(int gpu);

private:
    EngineConfig config;
    std::unique_ptr<ThreadPool> threadPool;
    std::unique_ptr<KVCache> kvCache;
    std::unique_ptr<rawrxd::sampling::ISampler> sampler;
    
    // Real model weights
    ModelWeights modelWeights;
    
    // MoE infrastructure (real, not stubbed)
    std::vector<std::unique_ptr<MoERouter>> moeRouters_;  // per-layer router
    std::unique_ptr<MoELayer> moeLayer_;
    std::unique_ptr<MoEWeightsLoader> moeWeightsLoader_;
    std::unique_ptr<MoEWeightProxy> moeWeightProxy_;
    MoEConfig moeConfig_;
    bool moeInitialized_ = false;
    
    // MoE per-layer expert weight cache (layer -> expert -> handle)
    // Pinned during inference to prevent eviction
    std::vector<std::vector<MoEWeightHandle>> moePinnedHandles_;
    
    // VAL-000 Phase 3: Advanced execution components
    std::unique_ptr<MedusaDecoder> medusaDecoder_;       // Speculative decoding
    std::unique_ptr<NUFusedPacker> nuPacker_;           // Compression engine
    std::unique_ptr<WarmupScheduler> warmupScheduler_;  // Predictive prefetch
    std::unique_ptr<CompressedKVCache> compressedKV_;   // KV compression
    std::unique_ptr<NVMeStream> nvmeStream_;           // NVMe streaming
    std::unique_ptr<SlidingWindowEngine> slidingWindow_;// Sliding context
    std::unique_ptr<ReverseIntegration> reverseIntegration_; // BigDaddyG Reverse Engine
    
    // VAL-000 component configs
    MedusaConfig medusaConfig_;
    NUPackerConfig nuPackerConfig_;
    WarmupConfig warmupConfig_;
    CompressedKVConfig compressedKVConfig_;
    NVMeStreamConfig nvmeConfig_;
    SlidingWindowConfig slidingWindowConfig_;
    
    // Feature flags
    bool medusaEnabled_ = false;
    bool nuPackingEnabled_ = false;
    bool warmupEnabled_ = false;
    bool compressedKVEnabled_ = false;
    bool nvmeStreamingEnabled_ = false;
    bool slidingWindowEnabled_ = false;
    bool reverseAnalysisEnabled_ = false;
    
    // MARS: Dynamic dual-GPU VRAM orchestration
    std::unique_ptr<MARS::MARSController> marsController_;
    bool marsEnabled_ = false;
    std::unordered_map<size_t, MARS::VRAMLease*> marsLayerLeases_; // layer -> lease
    
    // GGUF load result (kept for tensor lookup)
    GGUFLoadResult ggufResult;
    
    // Multi-shard support (K2-002+)
    std::unique_ptr<GlobalTensorIndex> globalIndex_;
    std::unique_ptr<gguf_shard_cache::TensorResidencyCache> residencyCache_;
    std::filesystem::path modelDir_;
    bool isMultiShard_ = false;
    
    // VAL-051.7: Bounded-window tensor residency manager (legacy)
    std::unique_ptr<ResidencyManager> residencyManager_;
    bool residencyEnabled_ = false;

    // Batch 15: ElasticResidencyManager — representation-aware, async prefetch
    std::unique_ptr<ElasticResidencyManager> elasticResidency_;
    bool elasticResidencyEnabled_ = false;

    // Router-driven prefetch telemetry
    std::unique_ptr<RouterPrefetchTelemetry> residencyTelemetry_;
    bool telemetryEnabled_ = false;

    // Async Vulkan prefetch: pending jobs from previous layer's PrefetchAsync
    // Key: layerId, Value: vector of job handles returned by PrefetchAsync
    std::unordered_map<int, std::vector<uint64_t>> pendingPrefetches_;
    bool asyncPrefetchEnabled_ = false;

    // BP16 streaming support (zero-copy mapped weight access)
    std::unique_ptr<BP16Streamer> bp16Streamer_;
    bool bp16Enabled_ = false;

    // Tokenizer
    std::unique_ptr<ITokenizer> tokenizer;

    // Production profiler (Batch 1: 1-token decode instrumentation)
    std::unique_ptr<ProductionProfiler> profiler_;
    std::vector<TokenProfile> profileHistory_;
    bool profilingEnabled_ = false;

    // Deep2 Active Telemetry Controller (PCIe stall + bandwidth + residency)
    std::unique_ptr<Deep2TelemetryController> telemetryController_;
    bool telemetryControllerEnabled_ = false;

    // Sovereign Engine components (Dragon Lore)
    std::unique_ptr<rawrxd::Chamber> chamber_;              // SM0-DSP clash detector
    std::unique_ptr<rawrxd::ToroidalKVCache> toroidalKV_;    // Infinite-context ring buffer
    std::unique_ptr<rawrxd::PlasmaGovernor> plasmaGovernor_; // R9700 thermal safety
    std::unique_ptr<rawrxd::SovereignOutOfCoreRuntime> sovereignRuntime_; // Dual-backend orchestrator
    bool chamberEnabled_ = false;
    bool toroidalKVEnabled_ = false;
    bool plasmaGovernorEnabled_ = false;
    bool sovereignRuntimeEnabled_ = false;

    // Vulkan GPU backend
    std::unique_ptr<CPUInference::VulkanCompute> vulkanCompute_;
    bool vulkanEnabled_ = false;
    bool vulkanInitialized_ = false;
    
    // Ollama model loading temp file cleanup
    std::string tempOllamaGGUFPath_;

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
    float* layerTemp = nullptr;  // Dedicated temp buffer for forwardLayer()

    // MLA (K2) buffers
    float* mlaQ_a = nullptr;      // [qLoraRank]
    float* mlaKV_a = nullptr;     // [kvLoraRank + qkRopeHeadDim]
    float* mlaQ_b = nullptr;      // [numHeads * headDim]
    float* mlaK_b = nullptr;      // [numHeads * qkNopeHeadDim]
    float* mlaV_b = nullptr;      // [numHeads * vHeadDim]
    
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
    
    // Sampling
    int sampleToken(const float* logits);

    // Find tensor in GGUF by name pattern
    WeightTensor* findTensor(const std::string& namePattern);
    
    // Load a tensor from GGUF into WeightTensor
    bool loadTensorFromGGUF(WeightTensor& wt, const std::string& name);
    
    // VAL-000 Phase 3: Internal helpers
    bool initializeAdvancedFeatures();
    void recordExpertAccess(int layerId, int expertId, float weight);
    void prefetchNextExperts(int layerId);
    size_t generateWithMedusa(const int* promptTokens, size_t promptLen,
                               int* outputTokens, size_t maxOutputLen,
                               InferenceStats* stats);
    void applySlidingWindow(size_t& attentionStart, size_t& attentionEnd);
};

} // namespace Deep2

#endif // DEEP2_ENGINE_H

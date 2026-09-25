// ============================================================================
// Deep2Engine.h - Production Inference Engine
// Combines: ThreadPool + KVCache + Deep2 Kernels + Quantization + Real Weights
// ============================================================================

#ifndef DEEP2_ENGINE_H
#define DEEP2_ENGINE_H

#include "Beaconism.hpp"
#include "GpuScheduler.hpp"
#include "ReverseIntegration.hpp"
#include "mars/MARSController.hpp"
#include "ThreadPool.h"
#include "KVCache.h"
#include "GGUFLoader.hpp"
#include "lavapath/GgufDynamicGeometry.hpp"
#include "lavapath/LocalModelAuthority_Bundle.hpp"
#include "BP16Streamer.hpp"
#include "Tokenizer.hpp"
#include "../sampling/advanced_sampler.hpp"
#include "MoERouter.hpp"
#include "MoEWeightProxy.hpp"
#include "MedusaDecoder.hpp"
#include "KVSpecTransaction.hpp"
#include "Deep2Speculative.hpp"
#include "NUFusedPacker.hpp"
#include "WarmupScheduler.hpp"
#include "CompressedKVCache.h"
#include "NVMeStream.h"
#include "SlidingWindowEngine.h"
#include "K2GlobalTensorIndex.hpp"
#include "KimiK2Config.hpp"
#include "K2NativeStreamGate.hpp"
#include "TensorResidencyCache.hpp"
#include "ResidencyManager.hpp"
#include "VirtualTensorDesc.hpp"
#include <cstdio>
#include "ElasticResidencyManager.hpp"
#include "CycloneScheduler.hpp"
#include "Deep2LivePath.hpp"
#include "RouterPrefetchTelemetry.hpp"
#include "ProductionProfiler.hpp"
#include "VramStreamingController.hpp"
#include "StreamEngine.h"
#include "StreamRouter.h"
// Sovereign Engine components (Dragon Lore)
#include "Chamber.hpp"
#include "ToroidalKVCache.hpp"
#include "PlasmaGovernor.hpp"
#include "SovereignOutOfCoreRuntime.hpp"
// Vulkan GPU backend
#include "vulkan_compute.h"
#include "Deep2MultiGpuLayerPlan.hpp"
#include "Deep2GpuForward.hpp"
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <unordered_map>
#include <atomic>
#include <cstdint>

// RAWRXD_EXPERT_CACHE_004/005
#include "expert_cache/ExpertCache.h"
#include "expert_cache/VulkanExpertTransport.h"

namespace Deep2 {

struct PeerDeviceGroupProbe;

// Forward declarations
class ReverseIntegration;
class Deep2TelemetryController {};

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
    std::vector<int64_t> shape;       // Full shape (from GGUF loader)

    size_t numElements() const {
        if (shape.empty()) return rows * cols;
        size_t n = 1;
        for (auto d : shape) n *= static_cast<size_t>(d);
        return n;
    }

    // Physical backing (VWA/RMV) — absolute offset from GGUF; lost ⇒ mount FAIL
    uint32_t    shardId        = 0;
    uint64_t    fileOffset     = 0;
    bool        hasFileBacking = false;

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
    // Attention projection biases (Qwen2 family). F32 when present.
    WeightTensor bq;
    WeightTensor bk;
    WeightTensor bv;
    WeightTensor attnNorm;    // [hiddenDim] RMSNorm weights
    WeightTensor attnQNorm;   // [headDim] per-head Q RMSNorm (Qwen3.5)
    WeightTensor attnKNorm;   // [headDim] per-head K RMSNorm (Qwen3.5)

    // Gemma3 post-normalization (applied after attention / FFN and before residual)
    WeightTensor attnPostNorm;  // [hiddenDim] RMSNorm weights
    WeightTensor ffnPostNorm;   // [hiddenDim] RMSNorm weights

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

    // SSM / Mamba (State Space Model) — hybrid architecture support
    WeightTensor ssmA;          // [ssmStateDim] — SSM state transition parameters (F32)
    WeightTensor ssmAlpha;      // [ssmStateDim, hiddenDim] — input projection to state (Q4_K)
    WeightTensor ssmBeta;       // [ssmStateDim, hiddenDim] — input projection to state (Q4_K)
    WeightTensor ssmIn;         // Nemotron-H: blk.N.ssm_in.weight
    WeightTensor ssmD;          // Nemotron-H: blk.N.ssm_d skip scale
    WeightTensor ssmConv1d;     // [convKernelSize, channels] — causal conv1d weights
    WeightTensor ssmConv1dBias; // Nemotron-H: blk.N.ssm_conv1d.bias
    WeightTensor ssmDtBias;     // [ssmStateDim] — delta_t bias (F32)
    WeightTensor ssmNorm;       // SSM path RMSNorm
    WeightTensor ssmOut;        // SSM output projection
    bool         hasSSM = false; // true when SSM tensors are populated
    bool         hasAttn = true; // true when attention tensors are present
    bool         hasFFN  = true; // true when FFN tensors are present
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

    float  ropeTheta       = 0.0f;   // unset until GGUF dynamic geometry
    float  ropeThetaLocal  = 0.0f;   // Gemma3 local (sliding-window) base
    float  ropeScaling     = 0.0f;   // 0 + !present => no scale (not a guessed 1.0)
    float  normEps         = 0.0f;   // unset until GGUF dynamic geometry
    size_t slidingWindowSize   = 0;   // e.g. 512
    size_t slidingWindowPattern = 0;  // e.g. 6 (every Nth layer is local)
    bool   ropeNeoxStyle  = false;  // true: NeoX rotated-half (llama/qwen); false: GPT-J adjacent
    bool   tieEmbeddings  = false;
    bool   isMoE          = false;
    bool   loaded         = false;
};

// ============================================================================
// Engine Configuration
// ============================================================================
struct EngineConfig {
    // Model architecture — zeros until GgufResolveDynamicGeometry (no static geometry)
    size_t hiddenDim = 0;
    size_t numLayers = 0;
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    size_t headDim = 0;
    size_t vocabSize = 0;
    size_t intermediateDim = 0;

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
    float ropeTheta = 0.0f;  // unset until dynamic geometry
    float ropeScaling = 1.0f;
    float normEps = 1e-6f;
    
    // Model path for GGUF loading (fixed size for C API compatibility)
    char modelPath[512] = {};
};

// ============================================================================
// Inference Statistics
// ============================================================================
struct InferenceStats {
    double tokensPerSecond = 0.0;       // E2E: generated / total_wall
    double latencyMs = 0.0;             // E2E: total_wall / generated
    size_t tokensGenerated = 0;
    size_t promptTokens = 0;
    double prefillMs = 0.0;             // wall ms for prompt prefill only
    double decodeMs = 0.0;              // wall ms for decode loop only
    double prefillTokensPerSecond = 0.0; // promptTokens / prefill_s
    double decodeTokensPerSecond = 0.0;  // generated / decode_s
    double totalWallMs = 0.0;
    size_t cacheHits = 0;
    size_t cacheMisses = 0;
    double memoryBandwidthGBps = 0.0;

    // VRAM streaming telemetry (populated when VramStreamingController is active)
    double vramStreamingTokensPerSecond = 0.0; // measured TPS with streaming overhead
    double avgVramBytesPerToken = 0.0;         // average bytes moved per token
    uint64_t vramTokensMeasured = 0;           // number of tokens measured
    uint64_t vramCeilingBytes = 0;             // active ceiling at end of generation
    uint64_t vramPeakUsedBytes = 0;            // peak VRAM used during generation
    uint64_t hostSpillBytes = 0;               // total bytes spilled to host
};

// ============================================================================
// Native Streaming Generation
// ============================================================================

struct GenerationOptions {
    uint32_t maxTokens = 0; // 0 = unlimited (EOS/cancel); stub-generator style

    float temperature = 0.8f;
    float topP = 0.95f;

    uint32_t topK = 40;

    float repeatPenalty = 1.0f;
    float minP = 0.0f;

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

enum class ModelState : uint8_t {
    Closed = 0,
    Indexed = 1,
    Choreographable = 2,
    Generating = 3
};

// ============================================================================
// Model-load stage diagnostics (RAWRXD_MODEL_ADMISSION_DIAG_001)
// ============================================================================
struct ModelLoadDiag {
    int stageCode = 0;            // Unique per-stage identifier
    std::string stageName;        // Human-readable stage tag
    std::string message;          // Detailed failure reason
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
    
    // Load model from GGUF file (optional out-param for granular diagnostics)
    bool loadModel(const std::string& ggufPath, ModelLoadDiag* diag = nullptr);

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
    struct ModelMetadata { std::string name; uint32_t version = 0; };
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

    // Switch to another GGUF (unload → load → re-init from metadata)
    bool switchModel(const std::string& ggufPath);

    // Grow KV / hidden buffers to a larger max sequence length (reuse existing prefix)
    bool growContext(size_t newMaxSeqLen);

    // Cooperative cancel for generate / generateStream (checked each decode step)
    void requestCancel() { cancelRequested_.store(true, std::memory_order_release); }
    void clearCancel() { cancelRequested_.store(false, std::memory_order_release); }
    bool isCancelRequested() const { return cancelRequested_.load(std::memory_order_acquire); }

    // K2 Gate 11: index-only shard open + certified partial-forward (no full load)
    bool openK2ShardDirectory(const std::string& shardDirPath);
    bool isK2ShardIndexOpen() const { return k2ShardIndexOpen_; }
    const GlobalTensorIndex* k2TensorIndex() const { return globalIndex_.get(); }
    const Deep2::KimiK2Config& k2ShardConfig() const { return k2ShardConfig_; }
    Deep2::K2NativeStreamGate::Result runK2NativeStreamPartial(const Deep2::K2NativeStreamGate::Config& cfg);
    
    // Model architecture from GGUF metadata (populated after loadModel succeeds)
    const std::string& modelArchitecture() const noexcept { return modelArchitecture_; }

    // Get engine info
    bool isInitialized() const { return initialized; }
    bool isModelLoaded() const { return modelWeights.loaded; }
    ModelState modelState() const { return modelState_; }
    bool hostQ8GemvSafe() const { return hostQ8GemvSafe_; }
    void emitHostQ8GemvReceipts(FILE* f) const {
        if (!f) return;
        std::fprintf(f,
            "HOST_Q8_GEMV_FFN=%d\nHOST_Q8_GEMV_ATTN=%d\nHOST_Q8_GEMV_SSM_IN=%d\n"
            "HOST_Q8_GEMV_NUMERIC_FINITE=%d\nHOST_Q8_GEMV_BOUNDS_SAFE=%d\n"
            "HOST_Q8_GEMV_REFERENCE_PARITY=%d\nHOST_Q8_GEMV_SAFE=%d\n",
            hostQ8Ffn_, hostQ8Attn_, hostQ8SsmIn_, hostQ8Finite_,
            hostQ8Bounds_, hostQ8Parity_, hostQ8GemvSafe_ ? 1 : 0);
        std::fflush(f);
    }
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
    void refreshElasticDynamicBudget();
    bool isElasticResidencyEnabled() const { return elasticResidencyEnabled_; }
    ElasticResidencyManager* getElasticResidencyManager() const { return elasticResidency_.get(); }
    NVMeStream* HostNvme() const noexcept { return nvmeStream_.get(); }
    int GgufMmapBound() const noexcept { return ggufResult.mmapBound; }

    // 24 GiB hard-residency / measured streaming controller
    void enableVramStreaming(bool enable);
    bool isVramStreamingEnabled() const { return vramStreamingEnabled_; }
    VramStreamingController* getVramStreamingController() const { return vramStreamingController_.get(); }
    StreamEngine* getStreamEngine() const { return streamEngine_.get(); }
    StreamRouter* getStreamRouter() const { return streamRouter_.get(); }

    // Lock / unlock / set ceiling (GiB)
    void lockVramResidency();
    void unlockVramResidency();
    void setVramCeilingGiB(uint32_t gib);
    uint64_t vramCeilingBytes() const;

    // Per-token measurement helpers
    void beginTokenStreamingMeasurement(uint64_t tokenIndex);
    bool endTokenStreamingMeasurement(uint64_t& outBytesMoved);
    VramStreamingStats getVramStreamingStats() const;

    // Cyclone temporal scheduler (live generate ownership)
    void enableCyclone(bool enable);
    bool isCycloneEnabled() const { return cycloneEnabled_; }
    CycloneScheduler* getCycloneScheduler() const { return cyclone_.get(); }

    // Router-driven prefetch telemetry
    void enableResidencyTelemetry(bool enable);
    bool isResidencyTelemetryEnabled() const { return telemetryEnabled_; }
    RouterPrefetchTelemetry* getResidencyTelemetry() const { return residencyTelemetry_.get(); }
    void printResidencyTelemetryReport() const;

    // Async Vulkan prefetch state management
    void setAsyncPrefetchEnabled(bool enable) { asyncPrefetchEnabled_ = enable; }
    bool isAsyncPrefetchEnabled() const { return asyncPrefetchEnabled_; }

    // Async stream prefetch state management (measured streaming controller)
    void setStreamPrefetchEnabled(bool enable) { streamPrefetchEnabled_ = enable; }
    bool isStreamPrefetchEnabled() const { return streamPrefetchEnabled_; }

    // Production profiler (Batch 1)
    void enableProfiling(bool enable);
    bool isProfilingEnabled() const { return profilingEnabled_; }
    const std::vector<TokenProfile>& getProfileHistory() const { return profileHistory_; }
    bool saveProfileJSON(const std::string& path) const;
    std::string getProfileJSONSummary() const;

    // Sovereign Engine: Chamber (SM0-DSP) integration
    void enableChamber(bool enable);
    bool isChamberEnabled() const { return chamberEnabled_; }
    Deep2::ChamberResult evaluateChamber(const float* hidden_state, size_t dim);
    Deep2::FormulaRoute routePrimitive(uint64_t context_hash);

    // Sovereign Engine: ToroidalKVCache (infinite context)
    void enableToroidalKV(bool enable, size_t maxTokens = 131072);
    bool isToroidalKVEnabled() const { return toroidalKVEnabled_; }

    // Sovereign Engine: PlasmaGovernor (thermal safety)
    void enablePlasmaGovernor(bool enable);
    bool isPlasmaGovernorEnabled() const { return plasmaGovernorEnabled_; }
    void updateThermalState(const Deep2::ThermalState& state);
    float currentThrottle() const;

    // Sovereign Engine: OutOfCoreRuntime dual-backend orchestrator
    void enableSovereignRuntime(bool enable);
    bool isSovereignRuntimeEnabled() const { return sovereignRuntimeEnabled_; }
    Deep2::SovereignOutOfCoreRuntime* getSovereignRuntime() const;

    // Vulkan GPU backend (SOLO or MULTI contiguous-layer)
    void enableVulkan(bool enable);
    void setVulkanStrictNoCpuFallback(bool strict) { vulkanStrictNoCpuFallback_ = strict; }
    bool isVulkanStrictNoCpuFallback() const { return vulkanStrictNoCpuFallback_; }
    bool isVulkanEnabled() const { return vulkanEnabled_; }
    bool isVulkanInitialized() const { return vulkanInitialized_; }
    Deep2::VulkanCompute* getVulkanCompute() const { return getVulkanComputeSlot(0); }
    Deep2::VulkanCompute* getVulkanComputeSlot(unsigned slot) const;
    unsigned vulkanDeviceCount() const { return (unsigned)vulkanDevices_.size(); }
    using MultiGpuLayerPlan = Deep2MultiGpuLayerPlan;
    const MultiGpuLayerPlan& multiGpuLayerPlan() const { return multiGpuLayerPlan_; }
    uint64_t vulkanGemvSuccessCount() const { return vulkanGemvOk_; }
    uint64_t vulkanGemvFallbackCount() const { return vulkanGemvFail_; }
    uint64_t vulkanUnplannedFallbacks() const { return vulkanUnplannedFallbacks_; }
    uint64_t plannedCpuGemvOps() const { return plannedCpuGemvOps_; }
    uint64_t plannedGpuGemvOps() const { return plannedGpuGemvOps_; }
    const GpuForwardCounters& gpuForwardCounters() const;
    void resetGpuForwardCounters();
    bool isRealGpuForward() const;
    bool ensureGpuForwardArena(unsigned slot);
    bool forwardLayerGpuResident(uint32_t layer, unsigned slot,
                                 bool uploadEntry, bool downloadExit);
    bool forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                   const float* hostIn, float* hostOut);
    bool forwardGpuMultiMap(const float* hostIn, float* hostOut);
    bool tryGpuTokenForward(float* hidden);
    // Execution route tracking for strict no-fallback authority
    enum class ExecutionRoute : uint8_t {
        Unset,
        Cpu,
        VulkanResident,
        VulkanMoeHybrid,
        VulkanDualRow,
        HostFallback
    };
    struct ForwardResult {
        bool ok = false;
        ExecutionRoute actualRoute = ExecutionRoute::Unset;
        bool gpuCommitted = false;
        const char* failureStage = nullptr;
    };

    ForwardResult forwardTokenAllLayers(float* hidden, size_t seqLen);
    bool forwardSpeculativeBlock(const int32_t* tokenIds,size_t count,
                                 size_t basePos,float* finalHiddenBatch);
    bool verifySpeculativeGreedyWindow(
        float* currentHidden,
        const std::vector<int32_t>& proposals,
        size_t maxEmit,
        std::vector<int32_t>& verified);
    bool proposeSelfSpeculativeGreedy(
        const float* currentHidden,size_t maxDraft,
        std::vector<int32_t>& proposals,
        uint32_t draftLayersOverride=0);

    // Gemma3-style per-layer RoPE theta (global vs local)
    float ropeThetaForLayer(size_t layer) const noexcept;
    bool buildAdaptiveSpeculativeProposals(
        const float* currentHidden,size_t remaining,
        std::vector<int32_t>& proposals);

    bool gpuResidentDecodeEnabled() const;
    void emitHotpathWitnesses();
    void emitLiveDecodeWitnesses(FILE* f = nullptr);
    uint64_t vulkanGpuWeightBytes() const { return vulkanGpuWeightBytes_; }
    uint64_t vulkanGpuTensorBytes() const { return vulkanGpuTensorBytes_; }
    uint64_t vulkanRealWeightLayers() const { return vulkanRealWeightLayers_; }
    bool vulkanStrictViolation() const { return vulkanStrictViolation_; }
    uint64_t vulkanSlotGemvSuccess(unsigned slot) const;
    uint64_t vulkanSlotWeightUploads(unsigned slot) const;
    uint64_t vulkanSlotWeightHits(unsigned slot) const;
    uint64_t vulkanSlotQueueSubmits(unsigned slot) const;
    uint64_t vulkanSlotPinnedWeightBytes(unsigned slot) const;
    uint64_t vulkanSlotPinnedWeightEntries(unsigned slot) const;
    uint64_t vulkanSlotResidentBatchInputUploads(unsigned slot) const;
    uint64_t vulkanSlotDirectSpecKvAppends(unsigned slot) const;
    uint64_t vulkanSlotResidentGroupOutputReallocs(unsigned slot) const;
    uint64_t vulkanSlotSecondaryImportBytes(unsigned slot) const;
    uint64_t vulkanSlotFullOutputBoundaryBytes(unsigned slot) const;
    uint64_t vulkanSlotResidentFullOutputCopies(unsigned slot) const;
    uint64_t vulkanSlotSpecLayerGraphSubmits(unsigned slot) const;
    uint64_t vulkanSlotQ4KBatchWeightBytes(unsigned slot) const;
    uint64_t vulkanSlotQ4KBatchGpuNs(unsigned slot) const;
    // DEEP2_DENSE_ROW_GPU_TIMING_AUTHORITY_001
    uint64_t vulkanSlotDenseRowGpuNs(unsigned slot) const;
    uint64_t vulkanSlotDenseRowTimedOps(unsigned slot) const;
    uint64_t vulkanSlotDenseRowSingleGpuNs(unsigned slot) const;
    uint64_t vulkanSlotDenseRowGroupGpuNs(unsigned slot) const;
    // DEEP2_RESIDENT_Q4K_KERNEL_PARITY_001 (lane: 1=dual-row, 2=resident)
    uint64_t vulkanSlotQ4kParityDispatchCount(unsigned slot, uint32_t lane) const;
    uint64_t vulkanSlotQ4kParityRows(unsigned slot, uint32_t lane) const;
    uint64_t vulkanSlotQ4kParitySampledNs(unsigned slot, uint32_t lane) const;
    uint64_t vulkanSlotQ4kParitySampledCount(unsigned slot, uint32_t lane) const;
    uint64_t vulkanSlotQ4kParitySampledRows(unsigned slot, uint32_t lane) const;
    uintptr_t vulkanSlotQ4kParityPipeline(unsigned slot, uint32_t lane) const;
    // DEEP2_RESIDENT_OPS_BREAKDOWN_001 (lane: 1=dual-row, 2=resident;
    // opKind: 0=probe,1=gemv_f32,2=rmsnorm,3=residual,4=swiglu,5=rope,
    // 6=attn,7=mla_attn)
    uint64_t vulkanSlotOpsSampledNs(unsigned slot, uint32_t lane, uint32_t opKind) const;
    uint64_t vulkanSlotOpsSampledCount(unsigned slot, uint32_t lane, uint32_t opKind) const;
    uint64_t vulkanSlotOpsSampledUnits(unsigned slot, uint32_t lane, uint32_t opKind) const;
    // DEEP2_RESIDENT_RANGE_GAP_AUTHORITY_001: per-transition sampled
    // kernel ns, dispatch count, and barrier ns.
    uint64_t vulkanSlotTransitionKernelNs(unsigned slot, uint32_t lane, uint32_t transition) const;
    uint64_t vulkanSlotTransitionKernelCount(unsigned slot, uint32_t lane, uint32_t transition) const;
    uint64_t vulkanSlotTransitionBarrierNs(unsigned slot, uint32_t lane, uint32_t transition) const;
    // Reset the sampled parity/ops statistics on every slot (call between
    // warmup and measurement so admission-phase contention cannot
    // contaminate the receipt).
    void vulkanResetQ4kParityStats();
    uint64_t vulkanSlotQ4KBatch4RowOps(unsigned slot) const;
    uint64_t vulkanSlotSpecArenaFlips(unsigned slot) const;
    uint64_t vulkanSlotQ4KBatch8RowOps(unsigned slot) const;
    uint64_t vulkanSlotQ4KAutotuneRuns(unsigned slot) const;
    uint64_t vulkanSlotRecordedQ4KSubmits(unsigned slot) const;
    uint64_t vulkanSlotRecordedQ4KBuilds(unsigned slot) const;
    uint64_t vulkanSlotQ4KAsyncSubmits(unsigned slot) const;
    uint64_t vulkanSlotQ4KAsyncWaitNs(unsigned slot) const;
    uint64_t vulkanSlotDownloadRingSubmits(unsigned slot) const;
    uint64_t vulkanSlotDownloadRingWaitNs(unsigned slot) const;
    bool vulkanSlotHasDedicatedTransferQueue(unsigned slot) const;
    uint32_t vulkanSlotComputeQueueFamily(unsigned slot) const;
    uint32_t vulkanSlotTransferQueueFamily(unsigned slot) const;
    uint64_t vulkanSlotTransferQueueSubmits(unsigned slot) const;

    // GpuScheduler: dual-GPU policy scheduler integration
    void setGpuPolicy(GpuPolicy policy);
    GpuPolicy currentGpuPolicy() const;
    GpuScheduler* getGpuScheduler() const;
    void initializeGpuScheduler();
    std::string scheduleGpuWork(const GpuWorkItem& work);

    // Per-token GPU telemetry counters (for Beaconism / profiler)
    struct TokenGpuCounters {
        uint64_t tokenWallNs = 0;
        uint64_t gpu0ExecNs = 0;
        uint64_t gpu1ExecNs = 0;
        uint64_t gpu0WaitNs = 0;
        uint64_t gpu1WaitNs = 0;
        uint64_t hostMergeNs = 0;
        uint64_t hostOrchestrationNs = 0;
        uint64_t cpuSsmNs = 0;
        uint64_t transferNs = 0;
        uint64_t vkSubmits = 0;
        uint64_t fenceWaits = 0;
        size_t gpu0Rows = 0;
        size_t gpu1Rows = 0;
        size_t h2dBytes = 0;
        size_t d2hBytes = 0;
        size_t stagingBytes = 0;
    };
    const TokenGpuCounters& lastTokenCounters() const { return lastTokenCounters_; }
    void resetTokenCounters() { lastTokenCounters_ = {}; }
    uint64_t vulkanSlotTransferRingOverlapNs(unsigned slot) const;
    bool vulkanSlotTimelineSemaphoreEnabled(unsigned slot) const;
    uint64_t vulkanSlotTimelineSignals(unsigned slot) const;
    uint64_t vulkanSlotTimelineWaits(unsigned slot) const;
    uint64_t vulkanSlotTimelineComputeTransferChains(unsigned slot) const;
    uint64_t vulkanSlotAsyncCmdRingReuses(unsigned slot) const;
    uint64_t vulkanSlotRecordedGroupBuilds(unsigned slot) const;
    uint64_t vulkanSlotRecordedGroupSubmits(unsigned slot) const;
    uint64_t vulkanSlotSpecAcceptGpuOps(unsigned slot) const;
    uint64_t vulkanSlotVerifiedHiddenHandoffs(unsigned slot) const;
    uint64_t vulkanSlotLayerTimelineChains(unsigned slot) const;
    uint64_t vulkanSlotRecordedGroupAsyncSubmits(unsigned slot) const;
    uint64_t vulkanSlotRecordedGroupSyncWaits(unsigned slot) const;
    uint64_t vulkanSlotSpecAcceptResidentOps(unsigned slot) const;
    uint64_t vulkanSlotSpecAcceptInputUploadBytes(unsigned slot) const;
    uint64_t vulkanSlotHiddenTimelineSubmits(unsigned slot) const;
    // GPU dispatch for GEMV: returns true if dispatched on GPU, false if CPU fallback needed

    bool tryVulkanGEMV(const WeightTensor& wt, const float* input, float* output, size_t outDim);

    // Batch10: host-bound heavy GPU path. These methods are physically GPU-backed
    // but deliberately do not claim fully resident no-host authority.
    bool tryVulkanHostGEMV(const WeightTensor& wt, const float* input,
                           float* output, size_t outDim);
    bool tryVulkanHostGEMVBatch4(const WeightTensor& wt,
                                 const float* inputBatch, size_t count,
                                 float* outputBatch, size_t outDim);

    bool tryVulkanHostGEMVGroup(
        const WeightTensor* const* weights,
        float* const* outputs,
        size_t count,
        const float* input,
        size_t inputCount);
    bool computeMoEFFNGpu(size_t layer, const float* input, float* output);

    bool computeMLAAttentionGpu(size_t layer, const float* input,
                                float* output, size_t seqLen);
    bool forwardTokenGpuHybrid(float* hidden, size_t seqLen);
    PeerDeviceGroupProbe probeVulkanPeerGroup() const;

    // VAL-000 Phase 3: Advanced feature control
    void enableMedusa(bool enable);
    void enableVerifiedSpeculation(bool enable,uint32_t window=4);
    const SpeculativeCounters& speculativeCounters() const;
    void enableNUPacking(bool enable);
    void enableWarmupScheduler(bool enable);
    void enableCompressedKV(bool enable, KVQuantType quantType = KVQuantType::KV_Q8_0);
    bool isCompressedKVEnabled() const { return compressedKVEnabled_; }
    void enableNVMeStreaming(bool enable, const std::string& modelPath = "");
    void enableSlidingWindow(bool enable, size_t windowSize = 4096);
    // Turn on the full VAL-000 + Sovereign + GPU stack (fail-soft per feature).
    void enableAllEnhancements();
    
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
    
    // Advanced System Hotpatching
    std::string disableTelemetryServices();
    std::string disableDamSysDriver();
    std::string disableIFEORedirects();
    std::string bypassHereticSafety();
    std::string reprogramPCIeBARs();
    
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
    void LinearWBatch4(const WeightTensor& wt,
                       const float* inputBatch, size_t count,
                       const float* bias, float* outputBatch,
                       size_t outDim);
    
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

    // Apply GenerationOptions to the authoritative sampler used by generate().
    // temperature <= 0 or topK <= 1 enables deterministic greedy (hard argmax).
    void configureGeneration(const GenerationOptions& options);
    bool isDeterministicGreedy() const;

    // Thin setters used by HexMag RepeatSession sampling adapters.
    void setTemperature(float temperature);
    void setTopP(float topP);
    void setSampling(float temperature, float topP);

    // Token embedding lookup (public for tree speculative decoding)
    // Returns false on FATAL_EMBED (zero/nonfinite row). Callers must abort inference.
    bool embedToken(int tokenId, float* output);
    bool embedTokensBatch(const int32_t* tokenIds, size_t count, float* outputBatch);

    // LM head projection: hiddenDim -> vocabSize (public for tree speculative decoding)
    void computeLogits(const float* hiddenState, float* logits);
    void computeLogitsBatch(const float* hiddenBatch, size_t count,
                            float* logitsBatch);
    bool computeGreedyTop1Batch(const float* hiddenBatch,size_t count,
                                int32_t* outTokens);
    bool trySpecRmsNormBatch(const WeightTensor& w,const float* in,
                             float* out,size_t width,size_t count);
    bool trySpecSwiGLUBatch(const float* gate,const float* up,float* out,
                            size_t width,size_t count);
    bool trySpecAttentionBatch(size_t layer,const float* q,
                               const float* k,const float* v,float* out,
                               size_t basePos,size_t count);
    bool trySpecColumnSplitBatch(const WeightTensor& wt,const float* in,
                                 float* out,size_t count);
    bool trySpecQ4KGroup(
        const WeightTensor* const* w,float* const* out,size_t weightCount,
        const float* input,size_t count);

    // DEEP2_ENGINE_SSVK_DECODE_BIND_001 — product decode transaction surface
    int sampleCommittedToken(const float* logits);
    bool advancePersistentKv();
    size_t persistentKvLength() const;
    const char* modelPathCStr() const { return config.modelPath; }
    float modelNormEps() const { return modelWeights.normEps; }

    // ------------------------------------------------------------------------
    // MARS: Dynamic Dual-GPU VRAM Hotpatch
    // ------------------------------------------------------------------------
    // Enable MARS with specified VRAM sizes (bytes)
    bool enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes);
    void disableMARS();
    bool isMARSEnabled() const { return marsEnabled_; }
    bool isMARSStandby() const { return marsStandby_; }
    /* HOST_RESIDENT_DENSE only; K2_STREAM_AUTHORITY → STANDBY by law. */
    bool marsHostResidentAuthorityOk() const;
    void standdownMARSEmptyPlacement(const char* reason);
    Deep2::MARSController* getMARSController() { return marsController_.get(); }

    // Place a model tensor under MARS lease control
    Deep2::VRAMLease* placeTensorMARS(
        uint64_t tensorId,
        const std::string& name,
        size_t bytes,
        float priority = 1.0f);

    // Inventory all loaded WeightTensors into MARS leases (dual-GPU split).
    struct MARSPlacementReport {
        size_t placed = 0;
        size_t skipped = 0;
        size_t oom = 0;
        size_t bytesTotal = 0;
        size_t bytesGpu0 = 0;
        size_t bytesGpu1 = 0;
        size_t leaseCount = 0;
    };
    MARSPlacementReport placeAllModelTensorsMARS();

    // Hotpatch redirect a tensor to a different GPU
    Deep2::HotpatchResult redirectTensor(uint64_t tensorId, int targetGPU);

    // Rebalance VRAM across GPUs
    void rebalanceMARS();

    // Get current dynamic parity state
    Deep2::DynamicParity getDynamicParity() const;

    // Handle tensor fault (reverse recovery)
    bool handleTensorFault(uint64_t tensorId);

    // Handle GPU failure (migrate all tensors off)
    bool handleGPUFailure(int gpu);

    // ONE_LOCAL_MODEL_AUTHORITY — sealed on loadModel (SSOT for ProductRuntime).
    const rawr::olma::AuthorityBundle& sessionAuthority() const { return sessionAuth_; }
    bool sessionAuthorityPass() const { return sessionAuth_.PASS != 0; }

    // ------------------------------------------------------------------------
    // Layer-0 parity probe (DEEP2_QWEN25_LAYER0_LOGIT_PARITY_001)
    // Emits compact per-checkpoint fingerprints (STEP/COUNT/FINITE/MIN/MAX/
    // MEAN/L2/FIRST8/HASH) to a file so an external oracle can compare against
    // a reference implementation. Disabled unless enabledParityProbe() is
    // called; zero overhead otherwise.
    // ------------------------------------------------------------------------
    enum class ParityCheckpoint : int {
        Embed = 0, AttnNorm = 1, Q = 2, K = 3, V = 4,
        Q_Rope = 5, K_Rope = 6, AttnScores = 7, AttnProbs = 8,
        AttnValue = 9, OProj = 10, AttnResidual = 11, FfnNorm = 12,
        FfnGate = 13, FfnUp = 14, Swiglu = 15, FfnDown = 16,
        LayerResidual = 17, FinalNorm = 18, Logits = 19
    };
    void enableParityProbe(const char* filePath, int maxSteps);

    // Multi-position mode: starts a new generation step. All checkpoint
    // emissions are re-armed and tagged with the current step; the trace then
    // contains one full checkpoint set per position (steps 0..N-1).
    void parityBeginStep(int step);

    // Layer-scoped KV-cache write fingerprints for the CURRENT step.
    // Emits K_CACHE_WRITE / V_CACHE_WRITE records (per-call: one layer).
    void parityEmitKvWrite(int layer, const float* k, const float* v,
                           size_t n);

    // Layer-scoped LOGITS_TOP10 record for the CURRENT step: deterministic
    // top-10 (tokenId,logit) pairs with greedy tie-break (first max wins).
    void parityEmitLogitsTop10(const float* logits, size_t n);

    void disableParityProbe();

private:
    PreparedSpecWindow preparedSpec_[2]{};
    uint64_t specGeneration_=0;
    bool prepareSpecWindow(
        const float* currentHidden,size_t remaining,
        PreparedSpecWindow& out);

    struct ParityProbe;
    ParityProbe* parityProbe_ = nullptr;  // owned; only when enabled

    // Internal probe emission (called by forward paths).
    void parityEmit(ParityCheckpoint cp, const float* v, size_t n);
    void parityEmitCount(ParityCheckpoint cp, size_t n, double minv,
                         double maxv, double mean, double l2,
                         const float* first8, uint64_t hash);
    // Layer-scoped emission (bypasses once-per-step guard).
    void parityEmitLayer(int layer, const char* cpName,
                         const float* v, size_t n);

private:
    // ------------------------------------------------------------------------
    // End parity probe
    // ------------------------------------------------------------------------
    EngineConfig config;
    std::unique_ptr<ThreadPool> threadPool;
    std::unique_ptr<KVCache> kvCache;
    std::unique_ptr<rawrxd::sampling::ISampler> sampler;
    bool deterministicGreedy_ = false;
    std::vector<float> speculativeHiddenScratch_;
    struct SpecWorkspace {
        std::vector<float> hidden,norm,q,k,v,attn,proj,gate,up,down;
        std::vector<float> logits,scores;
        std::vector<float> logitsBatch;
        std::vector<float> kPacked,vPacked;
        void clear() {
            hidden.clear();norm.clear();q.clear();k.clear();v.clear();
            attn.clear();proj.clear();gate.clear();up.clear();down.clear();
            logits.clear();scores.clear();logitsBatch.clear();
            kPacked.clear();vPacked.clear();
        }
    };

    SpecWorkspace specWs_{};
    std::vector<size_t> specKvMirrorCommittedLen_;
    void specKvMirrorCommit(size_t newLen);
    void specKvMirrorReset();

    std::atomic<bool> cancelRequested_{false};
    
    // Real model weights
    ModelWeights modelWeights;

    // Immutable session geometry from GGUF metadata (ONE_LOCAL_MODEL_AUTHORITY)
    GgufDynamicGeometry sessionGeometry_{};
    rawr::olma::AuthorityBundle sessionAuth_{};
    
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
    std::unique_ptr<Deep2::NUFusedPacker> nuPacker_;           // Compression engine
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
    SpeculativeCounters speculativeEmpty_{};

    bool nuPackingEnabled_ = false;
    bool warmupEnabled_ = false;
    bool compressedKVEnabled_ = false;
    bool nvmeStreamingEnabled_ = false;
    bool slidingWindowEnabled_ = false;
    bool reverseAnalysisEnabled_ = false;
    bool vramStreamingEnabled_ = false;
    bool streamPrefetchEnabled_ = false;
    
    // MARS: Dynamic dual-GPU VRAM orchestration
    std::unique_ptr<Deep2::MARSController> marsController_;
    bool marsEnabled_ = false;
    bool marsWeightsPlaced_ = false;
    bool marsStandby_ = false; /* CONTROLLER_ON_PLACED_0 or K2_STREAM_AUTHORITY */
    std::unordered_map<size_t, Deep2::VRAMLease*> marsLayerLeases_; // layer -> lease
    uint64_t marsNextTensorId_ = 1;
    
    // GGUF load result (kept for tensor lookup)
    GGUFLoadResult ggufResult;
    
    // Multi-shard support (K2-002+)
    std::unique_ptr<Deep2::GlobalTensorIndex> globalIndex_;
    std::unique_ptr<Deep2::TensorResidencyCache> residencyCache_;
    std::filesystem::path modelDir_;
    bool isMultiShard_ = false;
    bool k2ShardIndexOpen_ = false;
    Deep2::KimiK2Config k2ShardConfig_{};
    
    // VAL-051.7: Bounded-window tensor residency manager (legacy)
    std::unique_ptr<ResidencyManager> residencyManager_;
    bool residencyEnabled_ = false;

    // Batch 15: ElasticResidencyManager — representation-aware, async prefetch
    std::unique_ptr<ElasticResidencyManager> elasticResidency_;
    bool elasticResidencyEnabled_ = false;

    // RAWRXD_EXPERT_CACHE_004/005: per-device expert cache
    std::vector<std::unique_ptr<rawrxd::deep2::ExpertCache>> expertCaches_;
    std::vector<std::unique_ptr<rawrxd::deep2::VulkanExpertTransport>> expertTransports_;
    std::vector<std::vector<char>> expertStagingBuffers_;

    // Cyclone: temporal prediction over Elastic (live generate)
    std::unique_ptr<CycloneScheduler> cyclone_;
    bool cycloneEnabled_ = false;

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

    // 24 GiB hard-residency / measured streaming controller
    std::unique_ptr<VramStreamingController> vramStreamingController_;
    std::unique_ptr<StreamEngine> streamEngine_;
    std::unique_ptr<StreamRouter> streamRouter_;

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
    std::unique_ptr<Deep2::Chamber> chamber_;              // SM0-DSP clash detector
    std::unique_ptr<Deep2::ToroidalKVCache> toroidalKV_;    // Infinite-context ring buffer
    std::unique_ptr<Deep2::PlasmaGovernor> plasmaGovernor_; // R9700 thermal safety
    std::unique_ptr<Deep2::SovereignOutOfCoreRuntime> sovereignRuntime_; // Dual-backend orchestrator
    bool chamberEnabled_ = false;
    bool toroidalKVEnabled_ = false;
    bool plasmaGovernorEnabled_ = false;
    bool sovereignRuntimeEnabled_ = false;

    // Vulkan GPU backend (slot 0 = primary; extras for MULTI contiguous plan)
    std::unique_ptr<CPUInference::VulkanCompute> vulkanCompute_;
    std::vector<std::unique_ptr<CPUInference::VulkanCompute>> vulkanDevices_;
    MultiGpuLayerPlan multiGpuLayerPlan_{};
    bool vulkanEnabled_ = false;
    bool vulkanInitialized_ = false;
    bool vulkanStrictNoCpuFallback_ = true;  // GPU required; CPU only if HOST_DECODE
    bool vulkanStrictViolation_ = false;
    uint64_t vulkanGemvOk_ = 0;
    uint64_t vulkanGemvFail_ = 0;
    uint64_t vulkanGpuWeightBytes_ = 0;
    uint64_t vulkanGpuTensorBytes_ = 0;
    uint64_t vulkanRealWeightLayers_ = 0;
    uint64_t vulkanUnplannedFallbacks_ = 0;
    uint64_t plannedCpuGemvOps_ = 0;
    uint64_t plannedGpuGemvOps_ = 0;
    GpuForwardCounters gpuFwd_{};
    bool gpuFwdCommitted_ = false;

    // B5_SLOT1_RANGE_RESIDENCY_001: per-slot layer-range pin state.
    bool layerRangePinned_[2] = {false, false};

    // B4_LMHEAD_PERMANENT_RESIDENCY_001: lmHead slices pinned on both
    // devices at the frozen dual-row split geometry. Pinning happens once
    // at first logits GEMV; a split-geometry change re-pins (counted).
    bool lmHeadPinned_[2] = {false, false};
    uint32_t lmHeadPinRow0Count_ = 0;
    uint32_t lmHeadPinRePins_ = 0;
    uint64_t lmHeadPinUploadDeltas_[2] = {0, 0};
    std::unordered_map<std::string, std::vector<float>> vulkanWeightF32_;
    std::unordered_map<std::string, uint8_t> vulkanWeightSeen_;
    int parseWeightLayerIndex(const std::string& name) const;
    
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
    float* layerOut = nullptr;   // Layer output buffer (must NOT alias layerTemp)
    float* attnHeadScratch_ = nullptr; // [numHeads*headDim] pre-O concat

    // MLA (K2) buffers
    float* mlaQ_a = nullptr;      // [qLoraRank]
    float* mlaKV_a = nullptr;     // [kvLoraRank + qkRopeHeadDim]
    float* mlaQ_b = nullptr;      // [numHeads * headDim]
    float* mlaK_b = nullptr;      // [numHeads * qkNopeHeadDim]
    float* mlaV_b = nullptr;      // [numHeads * vHeadDim]

    // SSM / Mamba buffers (Nemotron-H: state=[L,H,D,N]=inner*state_size)
    float* ssmState = nullptr;
    float* ssmConvState = nullptr;
    float* ssmX = nullptr;     /* yInner scratch [ssmInner_] */
    float* ssmY = nullptr;
    float* ssmTemp = nullptr;  /* proj scratch [ssmInRows_] */

    // Per-layer SSM dequant caches — replaces process-static globals in computeSSM()
    struct SSMLayerRuntimeCache {
        std::vector<float> convK;
        std::vector<float> convB;
        std::vector<float> dtBias;
        std::vector<float> A;
        std::vector<float> D;
        std::vector<float> normW;
        bool initialized = false;
    };
    std::vector<SSMLayerRuntimeCache> ssmLayerCaches_;

    size_t ssmStateDim = 32;   /* legacy; Nemotron uses ssmStateSize_=128 */
    size_t ssmConvKernel = 4;
    size_t ssmInner_ = 0;
    size_t ssmStateSize_ = 0;  /* 128 — not heads(96) */
    size_t ssmConvDim_ = 0;
    size_t ssmInRows_ = 0;
    size_t ssmHeads_ = 0;
    size_t ssmHeadDimM_ = 0;
    size_t ssmGroups_ = 0;
    int nemotronGeoOk_ = 0;
    size_t ssmRealCalls_ = 0;
    size_t ssmIdentityCalls_ = 0;
    size_t ssmHybridLayers_ = 0;
    /* Nemotron-H Mamba2 experimental scratch (≠ CERT). */
    float* ssmMambaProj_ = nullptr;
    float* ssmMambaY_ = nullptr;
    float* ssmMambaState_ = nullptr;
    float* ssmMambaConv_ = nullptr;
    int ssmMambaArmed_ = 0;
    size_t ssmMambaInRows_ = 0;
    size_t ssmMambaInner_ = 0;
    size_t ssmMambaStateN_ = 0;
    size_t ssmMambaHeads_ = 0;
    size_t ssmMambaHeadDim_ = 0;
    size_t ssmMambaGroups_ = 0;
    size_t ssmMambaConvDim_ = 0;
    size_t ssmMambaConvK_ = 0;
    size_t ssmMambaGroupState_ = 0;
    size_t ssmMambaDtRank_ = 0;

    bool initialized = false;
    ModelState modelState_ = ModelState::Closed;
    std::string modelArchitecture_;               // <<< set from GGUF metadata after loadModel()
    bool hostQ8GemvSafe_ = true;

    // GpuScheduler instance
    std::unique_ptr<GpuScheduler> gpuScheduler_;

    // Per-token GPU telemetry (last completed token)
    mutable TokenGpuCounters lastTokenCounters_;

    bool hostDecodeSanitize_ = false;
    int hostQ8Ffn_ = 1;
    int hostQ8Attn_ = 1;
    int hostQ8SsmIn_ = 1;
    int hostQ8Finite_ = 1;
    int hostQ8Bounds_ = 1;
    int hostQ8Parity_ = 1;
    
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

    // SSM / Mamba forward pass (selective scan + causal conv1d)
    void computeSSM(size_t layer, const float* input, float* output);

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

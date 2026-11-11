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
#include "KimiK2Config.hpp"
#include "K2NativeStreamGate.hpp"
#include "TensorResidencyCache.hpp"
#include "ResidencyManager.hpp"
#include "ElasticResidencyManager.hpp"
#include "CycloneScheduler.hpp"
#include "Deep2LivePath.hpp"
#include "RouterPrefetchTelemetry.hpp"
#include "ProductionProfiler.hpp"
#include "deep2_flight_recorder.hpp"
// Sovereign Engine components (Dragon Lore)
#include "Chamber.hpp"
#include "ToroidalKVCache.hpp"
#include "PlasmaGovernor.hpp"
#include "SovereignOutOfCoreRuntime.hpp"
#include "lavapath/LocalModelAuthority_Bundle.hpp"
#include "deep2_flight_recorder.hpp"
// Model-fit authority + execution authority (DEEP2_MODEL_FIT_AUTHORITY_001)
#include "HostHardwareProbe.hpp"
#include "ModelFit.hpp"
#include "ExecutionAuthority.hpp"
#include "ExecutionTraceEmit.hpp"
#include "BatchedPrefill.hpp"
// Vulkan GPU backend
#include "vulkan_compute.h"
// The engine-facing backend contract. Deep2::VulkanCompute (src/deep2/
// vulkan_compute.h) is the deep device/kernel/shader implementation, but the
// engine types its slots as CPUInference::VulkanCompute. That class is
// forward-declared in many headers and was never completed, so any
// translation unit that used vulkanCompute_ or vulkanDevices_ saw an
// "undefined type" (C2027) and every member access failed.
//
// include/vulkan_compute_cpu_ns.hpp is the authoritative declaration of that
// class - it declares exactly the surface the engine calls (InitializeSolo,
// DispatchGEMV, DispatchGEMVQuant, GemvSuccess, GemvWeight{Hits,Uploads},
// SetPinResidentBudget, GetDeviceInfo, ...). It is included after
// vulkan_compute.h because it needs the Vk* types from it.
#include "vulkan_compute_cpu_ns.hpp"
#include "Deep2MultiGpuLayerPlan.hpp"
#include "Deep2GpuForward.hpp"
#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <filesystem>
#include <unordered_map>
#include <atomic>

namespace Deep2
{

    // Forward declarations
    class ReverseIntegration;
    class Deep2TelemetryController;

    // ============================================================================
    // Weight Tensor - Real quantized weight storage
    // ============================================================================
    struct WeightTensor
    {
        void *data = nullptr; // Raw weight data (quantized or FP32)
        int type = 0;         // GGMLType enum value
        size_t rows = 0;      // Output dimension
        size_t cols = 0;      // Input dimension
        size_t numBlocks = 0; // For quantized types
        size_t sizeBytes = 0; // Total bytes
        std::string name;     // Tensor name from GGUF

        // Multi-shard / sharding support
        size_t shardId = 0;   // Shard index for multi-shard models (0 = single shard)

        // BP16 / external mapping support
        bool mapped = false; // true if data is externally owned (do not free)
        bool hasFileBacking = false; // true if weight data is file-backed (mmap/mmap_range)
        uint64_t fileOffset = 0;    // byte offset in the backing GGUF file
    };

    // ============================================================================
    // Per-Layer Weights - Real transformer layer weight set
    // ============================================================================
    struct LayerWeights
    {
        // Standard Multi-Head Attention (MHA / GQA)
        WeightTensor wq;        // [hiddenDim, hiddenDim]
        WeightTensor wk;        // [kvDim, hiddenDim]
        WeightTensor wv;        // [kvDim, hiddenDim]
        WeightTensor wo;        // [hiddenDim, hiddenDim]
        WeightTensor wqkv;      // [hiddenDim + 2*kvDim, hiddenDim] fused QKV (Phi-3, etc.)
        WeightTensor attnNorm;  // [hiddenDim] RMSNorm weights
        WeightTensor attnQNorm; // [headDim] per-head Q RMSNorm (Qwen3.5)
        WeightTensor attnKNorm; // [headDim] per-head K RMSNorm (Qwen3.5)

        // Attention bias projections (Q/K/V/O)
        WeightTensor bq;  // Query bias
        WeightTensor bk;  // Key bias
        WeightTensor bv;  // Value bias
        WeightTensor bo;  // Output bias

        // MLA (Multi-Latent Attention) — K2 factorized attention
        // Q-path: hidden → q_a (GEMV) → RMSNorm → q_b (GEMV)
        WeightTensor attnQ_a;      // [qLoraRank, hiddenDim]
        WeightTensor attnQ_a_norm; // [qLoraRank] RMSNorm weights
        WeightTensor attnQ_b;      // [numHeads * headDim, qLoraRank]
        // KV-path: hidden → kv_a_mqa (GEMV) → split → [compressed_kv | k_pe]
        //          → RMSNorm → kv_b (GEMV) → k_b / v_b
        WeightTensor attnKV_a_mqa;  // [kvLoraRank + qkRopeHeadDim, hiddenDim]
        WeightTensor attnKV_a_norm; // [kvLoraRank] RMSNorm weights
        WeightTensor attnK_b;       // [numHeads * qkNopeHeadDim, kvLoraRank]
        WeightTensor attnV_b;       // [numHeads * vHeadDim, kvLoraRank]
        WeightTensor attnO;         // [hiddenDim, numHeads * headDim]
        bool useMLA = false;        // true when MLA tensors are populated

        // FFN
        WeightTensor wGate;   // [intermediateDim, hiddenDim]
        WeightTensor wUp;     // [intermediateDim, hiddenDim]
        WeightTensor wDown;   // [hiddenDim, intermediateDim]
        WeightTensor ffnNorm; // [hiddenDim] RMSNorm weights

        // MoE (optional - if numExperts > 0)
        WeightTensor moeRouter;            // [numExperts, hiddenDim]
        std::vector<WeightTensor> moeGate; // [numExperts][intermediateDim, hiddenDim]
        std::vector<WeightTensor> moeUp;   // [numExperts][intermediateDim, hiddenDim]
        std::vector<WeightTensor> moeDown; // [numExperts][hiddenDim, intermediateDim]
        WeightTensor moeSharedGate;        // [sharedIntermediate, hiddenDim]
        WeightTensor moeSharedUp;          // [sharedIntermediate, hiddenDim]
        WeightTensor moeSharedDown;        // [hiddenDim, sharedIntermediate]

        // SSM / Mamba (State Space Model) — hybrid architecture support
        // Nemotron-H Mamba-2 tensor layout:
        //   ssm_in:  [d_inner + d_conv + d_dt, hiddenDim] — fused input projection
        //   ssm_out: [hiddenDim, d_inner] — output projection
        //   ssm_a:   [d_state] — diagonal state matrix (F32)
        //   ssm_d:   [d_inner] — skip connection scale (F32)
        //   ssm_conv1d: [d_conv, d_inner] — causal conv1d weights (F32)
        //   ssm_conv1d_bias: [d_inner] — conv1d bias (F32)
        //   ssm_dt_bias: [d_inner] — delta bias (F32)
        //   ssm_norm: [d_inner] — RMSNorm weights (F32)
        WeightTensor ssmIn;              // [d_inner + d_conv + d_dt, hiddenDim] — fused input projection
        WeightTensor ssmInScale;         // [1] — per-tensor scale for ssm_in (F32)
        WeightTensor ssmOut;             // [hiddenDim, d_inner] — SSM output projection
        WeightTensor ssmOutScale;        // [1] — per-tensor scale for ssm_out (F32)
        WeightTensor ssmA;               // [d_state] — diagonal state matrix (F32)
        WeightTensor ssmD;               // [d_inner] — skip connection scale (F32)
        WeightTensor ssmConv1d;          // [d_conv, d_inner] — causal conv1d weights (F32)
        WeightTensor ssmConv1dBias;      // [d_inner] — conv1d bias (F32)
        WeightTensor ssmDtBias;          // [d_inner] — delta bias (F32)
        WeightTensor ssmNorm;            // [d_inner] — RMSNorm weights for SSM path (F32)
        WeightTensor ssmAlpha;           // [ssmStateDim, hiddenDim] — legacy alpha projection
        WeightTensor ssmBeta;            // [ssmStateDim, hiddenDim] — legacy beta projection
        bool hasSSM = false;             // true when SSM tensors are populated
    };

    // ============================================================================
    // Model Weights - Complete weight set for inference
    // ============================================================================
    struct ModelWeights
    {
        WeightTensor tokenEmbed; // [vocabSize, hiddenDim]
        WeightTensor lmHead;     // [vocabSize, hiddenDim] (may share with embed)
        WeightTensor finalNorm;  // [hiddenDim] RMSNorm weights
        std::vector<LayerWeights> layers;

        // Architecture metadata
        size_t hiddenDim = 0;
        size_t numLayers = 0;
        size_t numHeads = 0;
        size_t numKVHeads = 0;
        size_t headDim = 0;
        size_t vocabSize = 0;
        size_t intermediateDim = 0;
        size_t moeIntermediateDim = 0;
        size_t numExperts = 0;
        size_t numExpertsPerToken = 0;
        size_t numSharedExperts = 0;

        // MLA (K2) architecture fields
        size_t qLoraRank = 0;
        size_t kvLoraRank = 0;
        size_t qkNopeHeadDim = 0;
        size_t qkRopeHeadDim = 0;
        size_t vHeadDim = 0;
        size_t keyLength = 0;
        size_t valueLength = 0;
        size_t keyLengthMla = 0;
        size_t valueLengthMla = 0;
        size_t ropeDimensionCount = 0;
        bool useMLA = false;

        float ropeTheta = 10000.0f;
        float ropeScaling = 1.0f;
        float normEps = 1e-6f;
        bool tieEmbeddings = false;
        bool isMoE = false;
        bool loaded = false;
    };

    // ============================================================================
    // Engine Configuration
    // ============================================================================
    struct EngineConfig
    {
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
        bool useMLA = false;

        // Inference settings
        size_t maxSeqLen = 0;  // resolved from model metadata (maxPositionEmbeddings)
        size_t numThreads = 0; // 0 = auto

        // Quantization
        enum QuantType
        {
            Q4_0,
            Q4_K_M,
            Q8_0,
            FP16,
            FP32
        };
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
    struct InferenceStats
    {
        double tokensPerSecond = 0.0; // E2E: generated / total_wall
        double latencyMs = 0.0;       // E2E: total_wall / generated
        size_t tokensGenerated = 0;
        size_t promptTokens = 0;
        double prefillMs = 0.0;              // wall ms for prompt prefill only
        double decodeMs = 0.0;               // wall ms for decode loop only
        double prefillTokensPerSecond = 0.0; // promptTokens / prefill_s
        double decodeTokensPerSecond = 0.0;  // generated / decode_s
        double totalWallMs = 0.0;
        size_t cacheHits = 0;
        size_t cacheMisses = 0;
        double memoryBandwidthGBps = 0.0;
    };

    // ============================================================================
    // Native Streaming Generation
    // ============================================================================

    struct GenerationOptions
    {
        uint32_t maxTokens = 2048;

        float temperature = 0.8f;
        float topP = 0.95f;

        uint32_t topK = 40;

        float repeatPenalty = 1.0f;
        float minP = 0.0f;

        uint64_t seed = 0;
    };

    struct GenerationResult
    {
        uint64_t promptTokens = 0;
        uint64_t generatedTokens = 0;

        double promptTimeMs = 0.0;
        double generationTimeMs = 0.0;

        bool cancelled = false;
        bool completed = false;
    };

    using TokenCallback =
        std::function<bool(int32_t tokenId, const std::string &token)>;

    // ============================================================================
    // Per-layer topology descriptor — classifies each layer by its actual
    // mixer (SSM vs attention) and FFN configuration (dense vs MoE).
    // ============================================================================
    enum class LayerMixer { Attention, SSM, MoE, DenseFFN, Unknown };

    struct LayerTopology {
        LayerMixer mixer = LayerMixer::Unknown;
        bool hasMoE = false;
        bool hasSSM = false;
        size_t ssmInnerSize = 0;
        size_t ssmStateSize = 0;
        size_t ssmConvDim = 0;
        size_t moeNumExperts = 0;
        size_t moeExpertsPerToken = 0;
        size_t moeIntermediateDim = 0;
    };

    // ============================================================================
    // Production Deep2 Engine
    // ============================================================================
    class Deep2Engine
    {
    public:
        // Stable, machine-readable terminal reason for the most recent generation.
        enum class GenerationStopReason {
            NONE,
            NOT_INITIALIZED,
            NO_MODEL,
            BAD_ARGUMENTS,
            EMPTY_PROMPT,
            NO_CONTEXT_LEFT,
            INVALID_CONFIG,
            CONFIG_MISMATCH,
            KV_INIT_FAILED,
            COMPLETION_PLAN_BLOCKED,
            EMBED_FAILED,
            FORWARD_FAULT,
            EXCEPTION,
            CANCELLED,
            EOS,
            BUDGET_EXHAUSTED,
            COMPLETED,
        };
        static const char* GenerationStopReasonName(GenerationStopReason reason);
        GenerationStopReason generationStopReason() const { return m_generationStop; }

        Deep2Engine();
        ~Deep2Engine();

        // Initialize with configuration
        bool initialize(const EngineConfig &config);

        // Load model from GGUF file
        bool loadModel(const std::string &ggufPath);

        // Load model from BP16 file (exact weight extraction, no dequantization)
        bool loadModelFromBP16(const std::string &bp16Path);

        // Load model weights (legacy API - from memory buffer)
        bool loadWeights(const void *weightData, size_t weightSize);

        // Tokenize text
        std::vector<int> tokenize(const std::string &text);

        // Detokenize tokens
        std::string detokenize(const std::vector<int> &tokens);

        // Generate tokens
        // Returns number of tokens generated
        size_t generate(const int *promptTokens, size_t promptLen,
                        int *outputTokens, size_t maxOutputLen,
                        InferenceStats *stats = nullptr,
                        std::function<bool(int)> onToken = nullptr);
        // Generate text (high-level API)
        std::string generateText(const std::string &prompt, size_t maxTokens = 256);

        // Generate text with chat template formatting (for instruction-tuned models)
        std::string generateChat(const std::string &userMessage,
                                 const std::string &systemPrompt = "",
                                 size_t maxTokens = 256);

        // Native streaming generation — token-by-token with cancellation
        GenerationResult generateStream(
            const std::string &prompt,
            const GenerationOptions &options,
            TokenCallback callback);

        // Dynamic model metadata from GGUF
        const ModelMetadata &getModelMetadata() const;

        // Public bridge for the extern "C" Deep2_Forward C-API to drive a single
        // transformer layer forward pass without exposing internal buffers.
        void forwardLayerPublic(size_t layer, const float *input, float *output, size_t seqLen)
        {
            forwardLayer(layer, input, output, seqLen);
        }
        // Reset state for new conversation
        void reset();

        // Unload model and free weight memory
        void unloadModel();

        // Switch to another GGUF (unload → load → re-init from metadata)
        bool switchModel(const std::string &ggufPath);

        // Grow KV / hidden buffers to a larger max sequence length (reuse existing prefix)
        bool growContext(size_t newMaxSeqLen);

        // Cooperative cancel for generate / generateStream (checked each decode step)
        void requestCancel() { cancelRequested_.store(true, std::memory_order_release); }
        void clearCancel() { cancelRequested_.store(false, std::memory_order_release); }
        bool isCancelRequested() const { return cancelRequested_.load(std::memory_order_acquire); }

        // K2 Gate 11: index-only shard open + certified partial-forward (no full load)
        bool openK2ShardDirectory(const std::string &shardDirPath);
        bool isK2ShardIndexOpen() const { return k2ShardIndexOpen_; }
        const GlobalTensorIndex *k2TensorIndex() const { return globalIndex_.get(); }
        const Deep2::KimiK2Config &k2ShardConfig() const { return k2ShardConfig_; }
        K2NativeStreamGate::Result runK2NativeStreamPartial(const K2NativeStreamGate::Config &cfg);

        // Get engine info
        bool isInitialized() const { return initialized; }
        bool isModelLoaded() const { return modelWeights.loaded; }
        const EngineConfig &getConfig() const { return config; }
        const ModelWeights &getModelWeights() const { return modelWeights; }

        // Public buffer accessors for BoltExecutor bridge
        float *getLayerTemp() { return layerTemp; }
        float *getFfnOutput() { return ffnOutput; }

        // Backend identity for certification
        static constexpr const char *backendName() noexcept { return "Deep2Engine/Sovereign"; }
        static constexpr const char *backendId() noexcept { return "DEEP2_SOVEREIGN"; }

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
        ElasticResidencyManager *getElasticResidencyManager() const { return elasticResidency_.get(); }

        // Cyclone temporal scheduler (live generate ownership)
        void enableCyclone(bool enable);
        bool isCycloneEnabled() const { return cycloneEnabled_; }
        CycloneScheduler *getCycloneScheduler() const { return cyclone_.get(); }

        // Router-driven prefetch telemetry
        void enableResidencyTelemetry(bool enable);
        bool isResidencyTelemetryEnabled() const { return telemetryEnabled_; }
        RouterPrefetchTelemetry *getResidencyTelemetry() const { return residencyTelemetry_.get(); }
        void printResidencyTelemetryReport() const;

        // Async Vulkan prefetch state management
        void setAsyncPrefetchEnabled(bool enable) { asyncPrefetchEnabled_ = enable; }
        bool isAsyncPrefetchEnabled() const { return asyncPrefetchEnabled_; }

        // Production profiler (Batch 1)
        void enableProfiling(bool enable);
        bool isProfilingEnabled() const { return profilingEnabled_; }
        const std::vector<TokenProfile> &getProfileHistory() const { return profileHistory_; }
        bool saveProfileJSON(const std::string &path) const;
        std::string getProfileJSONSummary() const;

        // Sovereign Engine: Chamber (SM0-DSP) integration
        void enableChamber(bool enable);
        bool isChamberEnabled() const { return chamberEnabled_; }
        rawrxd::ChamberResult evaluateChamber(const float *hidden_state, size_t dim);
        rawrxd::FormulaRoute routePrimitive(uint64_t context_hash);

        // Sovereign Engine: ToroidalKVCache (infinite context)
        void enableToroidalKV(bool enable, size_t maxTokens = 131072);
        bool isToroidalKVEnabled() const { return toroidalKVEnabled_; }

        // Sovereign Engine: PlasmaGovernor (thermal safety)
        void enablePlasmaGovernor(bool enable);
        bool isPlasmaGovernorEnabled() const { return plasmaGovernorEnabled_; }
        void updateThermalState(const rawrxd::ThermalState &state);
        float currentThrottle() const;

        // Sovereign Engine: OutOfCoreRuntime dual-backend orchestrator
        void enableSovereignRuntime(bool enable);
        bool isSovereignRuntimeEnabled() const { return sovereignRuntimeEnabled_; }
        rawrxd::SovereignOutOfCoreRuntime *getSovereignRuntime() const;

        // Vulkan GPU backend (SOLO or MULTI contiguous-layer)
        void enableVulkan(bool enable);
        void setVulkanStrictNoCpuFallback(bool strict) { vulkanStrictNoCpuFallback_ = strict; }
        bool isVulkanStrictNoCpuFallback() const { return vulkanStrictNoCpuFallback_; }
        bool isVulkanEnabled() const { return vulkanEnabled_; }
        bool isVulkanInitialized() const { return vulkanInitialized_; }
        CPUInference::VulkanCompute *getVulkanCompute() const { return getVulkanComputeSlot(0); }
        CPUInference::VulkanCompute *getVulkanComputeSlot(unsigned slot) const;
        unsigned vulkanDeviceCount() const { return (unsigned)vulkanDevices_.size(); }
        const MultiGpuLayerPlan &multiGpuLayerPlan() const { return multiGpuLayerPlan_; }
        uint64_t vulkanGemvSuccessCount() const { return vulkanGemvOk_; }
        uint64_t vulkanGemvFallbackCount() const { return vulkanGemvFail_; }
        uint64_t vulkanUnplannedFallbacks() const { return vulkanUnplannedFallbacks_; }
        uint64_t plannedCpuGemvOps() const { return plannedCpuGemvOps_; }
        uint64_t plannedGpuGemvOps() const { return plannedGpuGemvOps_; }
        const GpuForwardCounters &gpuForwardCounters() const;
        void resetGpuForwardCounters();
        bool isRealGpuForward() const;
        bool ensureGpuForwardArena(unsigned slot);
        bool forwardLayerGpuResident(uint32_t layer, unsigned slot,
                                     bool uploadEntry, bool downloadExit);
        bool forwardGpuContiguousRange(unsigned slot, uint32_t lo, uint32_t hi,
                                       const float *hostIn, float *hostOut);
        bool forwardGpuMultiMap(const float *hostIn, float *hostOut);
        bool tryGpuTokenForward(float *hidden);
        bool forwardTokenAllLayers(float *hidden, size_t seqLen);
        bool gpuResidentDecodeEnabled() const;
        void emitHotpathWitnesses();
        void emitLiveDecodeWitnesses(FILE *f = nullptr);
        uint64_t vulkanGpuWeightBytes() const { return vulkanGpuWeightBytes_; }
        uint64_t vulkanGpuTensorBytes() const { return vulkanGpuTensorBytes_; }
        uint64_t vulkanRealWeightLayers() const { return vulkanRealWeightLayers_; }
        bool vulkanStrictViolation() const { return vulkanStrictViolation_; }
        uint64_t vulkanSlotGemvSuccess(unsigned slot) const;
        uint64_t vulkanSlotWeightUploads(unsigned slot) const;
        uint64_t vulkanSlotWeightHits(unsigned slot) const;
        // GPU dispatch for GEMV: returns true if dispatched on GPU, false if CPU fallback needed
        bool tryVulkanGEMV(const WeightTensor &wt, const float *input, float *output, size_t outDim);

        // VAL-000 Phase 3: Advanced feature control
        void enableMedusa(bool enable);
        void enableNUPacking(bool enable);
        void enableWarmupScheduler(bool enable);
        void enableCompressedKV(bool enable, KVQuantType quantType = KVQuantType::KV_Q8_0);
        void enableNVMeStreaming(bool enable, const std::string &modelPath = "");
        // VAL-000 Component: Memory Engine → NVMe Streaming (HostNvme accessor)
        NVMeStream* HostNvme() const { return nvmeStream_.get(); }

        // Sovereign Runtime: session authority accessors
        bool sessionAuthorityPass() const { return sessionAuthority_.PASS != 0; }
        const rawr::olma::AuthorityBundle& sessionAuthority() const { return sessionAuthority_; }
        void setSessionAuthority(const rawr::olma::AuthorityBundle& a) { sessionAuthority_ = a; }

        // Product Open: GGUF mmap boundary query
        int GgufMmapBound() const {
            return (modelWeights.loaded && (nvmeStream_ || bp16Enabled_)) ? 1 : 0;
        }
        void enableSlidingWindow(bool enable, size_t windowSize = 4096);
        // Turn on the full VAL-000 + Sovereign + GPU stack (fail-soft per feature).
        void enableAllEnhancements();

        // ====================================================================
        // DEEP2_MODEL_FIT_AUTHORITY_001 — admission-to-execution contract.
        // ====================================================================

        /// Produce the MODEL_FIT verdict for a GGUF without loading it.
        /// `requestedContext` 0 = "as large as fits".
        /// Pure: same inputs always produce the same plan.
        rawrxd::ModelFitPlan estimateModelFit(const std::string &ggufPath,
                                             size_t requestedContext = 0) const;

        /// The plan the last loadModel() admitted.  Only meaningful when
        /// modelFitAccepted() is true.
        const rawrxd::ModelFitPlan &modelFitPlan() const { return fitPlan_; }
        bool modelFitAccepted() const { return fitPlanValid_ && fitPlan_.accepted; }
        const std::string &modelFitRejectReason() const { return fitRejectReason_; }
        const rawrxd::HostHardwareSnapshot &hardwareSnapshot() const {
            return hardwareSnapshot_;
        }

        /// Emit the authoritative MODEL_FIT + execution trace block.
        void emitModelFitReport(FILE *f = stdout) const;
        void emitExecutionTrace(FILE *f = stdout);

        /// Measured telemetry accessor (swarm / telemetry consumers read this
        /// rather than re-deriving numbers).
        const rawrxd::ExecutionTelemetry &executionTelemetry() const {
            return execTelemetry_;
        }

        /// KV-cache provenance gate: reuse the cached prefix ONLY when it
        /// belongs to this exact model instance and token prefix.
        bool kvPrefixReusable(const std::vector<int> &promptTokens,
                              std::string *reason = nullptr) const;

        /// Enable/disable chunked prefill (default on; chunk tunable).
        void enableBatchedPrefill(bool enable, size_t chunkTokens = 0);
        bool isBatchedPrefillEnabled() const { return batchedPrefillEnabled_; }
        size_t prefillChunkSize() const { return prefillChunkSize_; }

        // --------------------------------------------------------------------
        // H11 parity surface.  Both paths are public so a parity harness can
        // run them on the SAME loaded model and compare KV + logits.  Neither
        // touches sampler state, so they are safe to call back-to-back after
        // reset().
        // --------------------------------------------------------------------

        /// Faithful one-token-at-a-time reference. Always available.
        size_t prefillSerial(const int *promptTokens, size_t promptLen,
                             float *hiddenOut);

        /// Chunked-causal prefill. `chunkTokens` 0 = auto.
        /// Numerically identical to prefillSerial() for the same input; the
        /// parity gates (H11-P1..P4) assert that rather than assuming it.
        size_t prefillBatched(const int *promptTokens, size_t promptLen,
                              float *hiddenOut, size_t chunkTokens = 0);

        /// Run both paths and return the max relative KV/logits divergence.
        /// Emits the H11 receipt block. 0 = identical within tolerance.
        double prefillParityReport(const int *promptTokens, size_t promptLen,
                                   size_t chunkTokens, FILE *f = stdout);

        /// Direct KV access for parity capture (per-layer K/V snapshots).
        Deep2::KVCache *getKVCache() const { return kvCache.get(); }

        /// Reset KV + hidden state without unloading weights (parity runs need
        /// this between the serial and batched legs).
        void resetInferenceState();

        /// H11 dispatch-accounting: the four independent counters that separate
        /// "2,619 compute commands" from "2,619 queue submissions".
        struct DispatchAccount {
            uint64_t cmdDispatchCount = 0;   // vkCmdDispatch calls recorded
            uint64_t queueSubmitCount = 0;   // vkQueueSubmit calls
            uint64_t fenceWaitCount = 0;     // host synchronisation points
            uint64_t gpuExecutionNs = 0;     // calibrated GPU timestamp span
            uint64_t gpuSyncNs = 0;          // host wait for GPU completion
            uint64_t matrixRowsDelta = 0;    // rows actually streamed to GEMV
        };
        DispatchAccount dispatchAccount() const { return dispatchAccount_; }
        void resetDispatchAccount() { dispatchAccount_ = DispatchAccount{}; }

        // Read-only accessors for the execution-ledger consumers.
        uint64_t executionRunId() const { return executionRunId_; }
        uint64_t executorInstanceId() const { return executorInstanceId_; }

        // BigDaddyG Reverse Engine integration
        void enableReverseAnalysis(bool enable);
        void disableReverseAnalysis();
        ReverseIntegration *getReverseIntegration() const;

        // HotPatcher integration - The Bottle
        void printHotPatcherStatus();
        std::string registerKernelPatch(
            const std::string &kernelName,
            void *originalKernel,
            void *newKernel,
            float expectedSpeedup = 1.0f);
        bool rollbackKernelPatch(const std::string &patchId);
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
        const MedusaStats &getMedusaStats() const;
        const WarmupStats &getWarmupStats() const;
        const NUFusedPacker::Stats &getNUPackerStats() const;

        // Linear layer with quantization support
        // Returns weight index for use in Linear()
        int registerWeightTensor(void *data, int type, size_t rows, size_t cols);

        // Matrix-vector multiplication: output = weights * input + bias
        void Linear(int weightIdx, const float *input, const float *bias,
                    float *output, size_t outDim);

        // Linear using WeightTensor directly
        void LinearW(const WeightTensor &wt, const float *input, const float *bias,
                     float *output, size_t outDim);

        // Parallel version using ThreadPool
        void LinearParallel(int weightIdx, const float *input, const float *bias,
                            float *output, size_t outDim);

        // RMSNorm with weights: output = weight * x / sqrt(mean(x^2) + eps)
        void RMSNormW(const WeightTensor &normWeight, const float *input,
                      float *output, size_t dim, float eps);

        // RoPE: apply rotary position embedding
        void applyRoPE(float *q, float *k, size_t headDim, size_t numHeads,
                       size_t numKVHeads, size_t pos, float theta, float scaling);

        // SwiGLU activation: output = silu(gate) * up
        void SwiGLU(const float *gate, const float *up, float *output, size_t dim);

        // Set sampler
        void setSampler(std::unique_ptr<rawrxd::sampling::ISampler> sampler);

        // Apply GenerationOptions to the authoritative sampler used by generate().
        // temperature <= 0 or topK <= 1 enables deterministic greedy (hard argmax).
        void configureGeneration(const GenerationOptions &options);
        bool isDeterministicGreedy() const { return deterministicGreedy_; }

        // Thin setters used by HexMag RepeatSession sampling adapters.
        void setTemperature(float temperature);
        void setTopP(float topP);
        void setSampling(float temperature, float topP);

        // Token embedding lookup (public for tree speculative decoding)
        // Returns false on FATAL_EMBED (zero/nonfinite row). Callers must abort inference.
        bool embedToken(int tokenId, float *output);

        // LM head projection: hiddenDim -> vocabSize (public for tree speculative decoding)
        void computeLogits(const float *hiddenState, float *logits);

        // ------------------------------------------------------------------------
        // MARS: Dynamic Dual-GPU VRAM Hotpatch
        // ------------------------------------------------------------------------
        // Enable MARS with specified VRAM sizes (bytes)
        bool enableMARS(size_t gpu0VRAMBytes, size_t gpu1VRAMBytes);
        void disableMARS();
        bool isMARSEnabled() const { return marsEnabled_; }
        MARS::MARSController *getMARSController() { return marsController_.get(); }

        // Place a model tensor under MARS lease control
        MARS::VRAMLease *placeTensorMARS(
            uint64_t tensorId,
            const std::string &name,
            size_t bytes,
            float priority = 1.0f);

        // Inventory all loaded WeightTensors into MARS leases (dual-GPU split).
        struct MARSPlacementReport
        {
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
        GenerationStopReason m_generationStop = GenerationStopReason::NONE;
        EngineConfig config;
        std::unique_ptr<ThreadPool> threadPool;
        std::unique_ptr<KVCache> kvCache;
        // Maps model layer index -> KV cache layer index.  SIZE_MAX for
        // SSM-only layers that do not use the KV cache.  Allows sizing the
        // KV cache for attention layers only while preserving per-layer
        // addressing in the forward pass.
        std::vector<size_t> kvLayerMap_;

        // Translate a model layer index to a KV cache layer index.
        // Returns SIZE_MAX when the layer does not use the KV cache.
        size_t kvLayerIdx(size_t modelLayer) const {
            if (kvLayerMap_.empty() || modelLayer >= kvLayerMap_.size())
                return modelLayer;
            return kvLayerMap_[modelLayer];
        }
        std::unique_ptr<rawrxd::sampling::ISampler> sampler;
        bool deterministicGreedy_ = false;
        std::atomic<bool> cancelRequested_{false};

        // Real model weights
        ModelWeights modelWeights;

        // Per-layer topology descriptors — classifies each layer's mixer and FFN config
        std::vector<LayerTopology> layerTopology_;

        // MoE infrastructure (real, not stubbed)
        std::vector<std::unique_ptr<MoERouter>> moeRouters_; // per-layer router
        std::unique_ptr<MoELayer> moeLayer_;
        std::unique_ptr<MoEWeightsLoader> moeWeightsLoader_;
        std::unique_ptr<MoEWeightProxy> moeWeightProxy_;
        MoEConfig moeConfig_;
        bool moeInitialized_ = false;

        // MoE per-layer expert weight cache (layer -> expert -> handle)
        // Pinned during inference to prevent eviction
        std::vector<std::vector<MoEWeightHandle>> moePinnedHandles_;

        // VAL-000 Phase 3: Advanced execution components
        std::unique_ptr<MedusaDecoder> medusaDecoder_;           // Speculative decoding
        std::unique_ptr<NUFusedPacker> nuPacker_;                // Compression engine
        std::unique_ptr<WarmupScheduler> warmupScheduler_;       // Predictive prefetch
        std::unique_ptr<CompressedKVCache> compressedKV_;        // KV compression
        std::unique_ptr<NVMeStream> nvmeStream_;                 // NVMe streaming
        std::unique_ptr<SlidingWindowEngine> slidingWindow_;     // Sliding context
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

        // Sovereign Runtime: session authority bundle (sealed at model open)
        rawr::olma::AuthorityBundle sessionAuthority_{};

        // MARS: Dynamic dual-GPU VRAM orchestration
        std::unique_ptr<MARS::MARSController> marsController_;
        bool marsEnabled_ = false;
        bool marsWeightsPlaced_ = false;
        std::unordered_map<size_t, MARS::VRAMLease *> marsLayerLeases_; // layer -> lease
        uint64_t marsNextTensorId_ = 1;

        // GGUF load result (kept for tensor lookup)
        GGUFLoadResult ggufResult;

        // Multi-shard support (K2-002+)
        std::unique_ptr<GlobalTensorIndex> globalIndex_;
        std::unique_ptr<gguf_shard_cache::TensorResidencyCache> residencyCache_;
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

        // Tokenizer
        std::unique_ptr<ITokenizer> tokenizer;

        // Production profiler (Batch 1: 1-token decode instrumentation)
        std::unique_ptr<ProductionProfiler> profiler_;
        std::vector<TokenProfile> profileHistory_;
        bool profilingEnabled_ = false;

        // Deep2 Flight Recorder: self-logging inference debugger
        std::unique_ptr<rawrxd::debug::Recorder> flight_recorder_;
        std::wstring flight_log_path_;

        // Deep2 Active Telemetry Controller (PCIe stall + bandwidth + residency)
        std::unique_ptr<Deep2TelemetryController> telemetryController_;
        bool telemetryControllerEnabled_ = false;

        // ====================================================================
        // DEEP2_MODEL_FIT_AUTHORITY_001 / DEEP2_EXECUTION_AUTHORITY_001
        // The one plan that admission produces and the executor must honor,
        // plus the measured execution telemetry the trace reports.
        // ====================================================================
        rawrxd::ModelFitPlan fitPlan_;
        bool fitPlanValid_ = false;
        rawrxd::ExecutionTelemetry execTelemetry_;
        rawrxd::ModelInstanceId sessionModelId_;
        std::string fitRejectReason_;

        // Measured hardware snapshot (RAM/storage/GPUs).  Refreshed at
        // loadModel() so a temporarily-removed GPU is discovered rather than
        // still required.
        rawrxd::HostHardwareSnapshot hardwareSnapshot_;

        // Execution identity for the current generate() run.
        uint64_t executionRunId_ = 0;
        uint64_t executionRequestId_ = 0;
        uint64_t executorInstanceId_ = 0;
        uint64_t prefillChunkSize_ = 0;
        bool batchedPrefillEnabled_ = false;

        // KV provenance for cross-request reuse (gate 3: context truth).
        rawrxd::ModelInstanceId kvProvenanceModel_;
        std::vector<int> kvProvenanceTokens_;
        bool kvProvenanceValid_ = false;

        // Measured phase/counter values the execution trace reports.  These are
        // the ONLY numbers the trace is allowed to show; anything not captured
        // here is emitted as "unmeasured" rather than a fabricated zero.
        uint64_t planPrefillTokens_ = 0;
        uint64_t planLayerExecutions_ = 0;
        uint64_t measuredPrefillNs_ = 0;
        uint64_t measuredDecodeNs_ = 0;
        uint64_t measuredGeneratedTokens_ = 0;
        uint64_t kvReusedPrefixTokens_ = 0;
        uint64_t kvAppendedTokens_ = 0;
        const char *measuredTimingAuthority_ = "unmeasured";

        // Placeholder-avoidance flag: once real phase timings are captured the
        // trace stops labelling itself unmeasured.
        bool executionTraceArmed_ = false;

        // Sovereign Engine components (Dragon Lore)
        std::unique_ptr<rawrxd::Chamber> chamber_;                            // SM0-DSP clash detector
        std::unique_ptr<rawrxd::ToroidalKVCache> toroidalKV_;                 // Infinite-context ring buffer
        std::unique_ptr<rawrxd::PlasmaGovernor> plasmaGovernor_;              // R9700 thermal safety
        std::unique_ptr<rawrxd::SovereignOutOfCoreRuntime> sovereignRuntime_; // Dual-backend orchestrator
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
        bool vulkanStrictNoCpuFallback_ = false;
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
        std::unordered_map<std::string, std::vector<float>> vulkanWeightF32_;
        std::unordered_map<std::string, uint8_t> vulkanWeightSeen_;
        int parseWeightLayerIndex(const std::string &name) const;

        // Ollama model loading temp file cleanup
        std::string tempOllamaGGUFPath_;

        // Weight tensors (legacy registration system)
        float *weights = nullptr;
        size_t weightSize = 0;

        // Buffers
        float *hiddenStates = nullptr;
        float *attentionOutput = nullptr;
        float *ffnOutput = nullptr;
        float *logits = nullptr;
        float *qProj = nullptr;
        float *kProj = nullptr;
        float *vProj = nullptr;
        float *gateBuf = nullptr;
        float *upBuf = nullptr;
        float *layerTemp = nullptr; // Dedicated temp buffer for forwardLayer()

        // MLA (K2) buffers
        float *mlaQ_a = nullptr;  // [qLoraRank]
        float *mlaKV_a = nullptr; // [kvLoraRank + qkRopeHeadDim]
        float *mlaQ_b = nullptr;  // [numHeads * headDim]
        float *mlaK_b = nullptr;   // [numHeads * (qkNopeHeadDim + qkRopeHeadDim)] — K_nope + K_pe per head
        float *mlaV_b = nullptr;   // [numHeads * vHeadDim]
        float *mlaK_pe = nullptr;  // [numHeads * qkRopeHeadDim] — RoPE'd key part per head

        // SSM / Mamba buffers
        float *ssmState = nullptr;     // [numLayers * ssmStateDim] — per-layer SSM hidden state (legacy)
        float *ssmConvState = nullptr; // [numLayers * ssmConvSize * hiddenDim] — causal conv1d state (legacy)
        float *ssmX = nullptr;         // [hiddenDim] — SSM input buffer
        float *ssmY = nullptr;         // [hiddenDim] — SSM output buffer
        float *ssmTemp = nullptr;      // [hiddenDim] — SSM temp buffer
        size_t ssmStateDim = 32;       // SSM state dimension (from tensor dims)
        size_t ssmConvKernel = 4;      // Conv1d kernel size (from tensor dims)

        // Mamba-2 dynamic state buffers (sized from actual tensor geometry at load time)
        float *ssmMambaState = nullptr;   // [numLayers * dInner * dState] — per-layer recurrent state
        float *ssmMambaConvState = nullptr; // [numLayers * dConv * dConvDim] — per-layer conv state
        float *ssmMambaProj = nullptr;    // [max(ssmInRows)] — input projection output
        size_t ssmMambaDInner = 0;   // d_inner from bound tensors
        size_t ssmMambaDState = 0;   // d_state from bound tensors
        size_t ssmMambaDConvKernel = 0;   // d_conv kernel size
        size_t ssmMambaDConvDim = 0;      // d_conv_dim channel count

        // ── SSM / Mamba member set ──────────────────────────────────────────
        // SSM/Mamba geometry (loaded from GGUF tensors)
        float *ssmMambaD = nullptr;        // [d_state] — diagonal D parameter
        float *ssmMambaA = nullptr;        // [d_state] — diagonal A parameter (log scale)
        float *ssmMambaB = nullptr;        // [d_inner, d_state] — B projection
        float *ssmMambaC = nullptr;        // [d_state, d_inner] — C projection
        float *ssmMambaDt = nullptr;       // [d_inner] — delta parameter
        float *ssmMambaDConv = nullptr;    // [d_conv, 1, d_inner] — conv1d weight
        float *ssmMambaBias = nullptr;     // [d_inner] — bias
        float *ssmInner = nullptr;         // [d_inner] — inner projection output
        float *ssmInnerGate = nullptr;     // [d_inner] — gate for gating
        float *ssmInnerOut = nullptr;      // [d_inner] — output projection
        float *ssmSSMState = nullptr;      // [d_state] — SSM recurrent state
        float *ssmMambaA_log = nullptr;    // [d_state] — log(A) for stable exp
        float *ssmMambaDtBias = nullptr;   // [d_inner] — delta bias
        float *ssmMambaDtScale = nullptr;  // [d_inner] — delta scale
        float *ssmMambaDtSoftplus = nullptr; // [d_inner] — softplus(delta)
        size_t ssmHeads = 0;               // Number of SSM heads (if multi-head)
        size_t ssmDimInner = 0;            // d_inner dimension
        size_t ssmDimState = 0;            // d_state dimension
        size_t ssmConvSize = 0;            // conv1d kernel size
        bool ssmMambaInitialized = false;  // SSM buffers initialized
        bool ssmUseMamba2 = false;         // Use Mamba-2 grouped SSM

        // Geometry / head layout (loaded from GGUF)
        size_t hiddenDim = 0;
        size_t numHeads = 0;
        size_t numKVHeads = 0;
        size_t headDim = 0;
        size_t headDimQ = 0;
        size_t headDimK = 0;
        size_t headDimV = 0;
        size_t headDimGQA = 0;
        size_t ffnDim = 0;
        size_t vocabSize = 0;
        size_t numLayers = 0;
        float ropeTheta = 10000.0f;
        float ropeScaling = 1.0f;
        bool useRoPE = true;
        bool useGQA = false;
        bool useMQA = false;
        bool useMLA = false;

        bool initialized = false;

        // Internal methods
        bool allocateBuffers();
        void deallocateBuffers();

        // Multi-shard embedding lookup: reads a single token_embd row from
        // the appropriate GGUF shard via GlobalTensorIndex + TensorResidencyCache.
        // Used when modelWeights.tokenEmbed.data is null (multi-shard models
        // do not eagerly load tensor data). Returns false on any failure.
        bool embedTokenFromShard(int tokenId, float *output);

        // Transformer layer forward pass (real implementation)
        void forwardLayer(size_t layer, const float *input, float *output, size_t seqLen);
        // SEH-safe wrapper around forwardLayer: catches access violations from
        // buffer overflows during inference so the engine can shut down cleanly
        // instead of corrupting the heap and crashing during teardown.
        bool safeForwardLayer(size_t layer, float *input, float *output, size_t seqLen);

        // Attention with real weight projections
        void computeAttention(size_t layer, const float *input, float *output, size_t seqLen);

        // FFN (SwiGLU) with real weight projections
        void computeFFN(size_t layer, const float *input, float *output);

        // MoE FFN - real routed expert execution (no dense fallback)
        void computeMoEFFN(size_t layer, const float *input, float *output);

        // MoE expert FFN via streamed weights (gate/up/down projections)
        void computeExpertFFN(const MoEWeightHandle &handle,
                              const float *input, float *output,
                              size_t hiddenDim, size_t expertDim);

        // Shared expert FFN
        void computeSharedExpertFFN(size_t layer, const float *input, float *output);

        // SSM / Mamba forward pass (selective scan + causal conv1d)
        void computeSSM(size_t layer, const float *input, float *output);

        // Sampling
        int sampleToken(const float *logits);

        // Find tensor in GGUF by name pattern
        WeightTensor *findTensor(const std::string &namePattern);

        // Load a tensor from GGUF into WeightTensor
        bool loadTensorFromGGUF(WeightTensor &wt, const std::string &name);

        // VAL-000 Phase 3: Internal helpers
        bool initializeAdvancedFeatures();
        void recordExpertAccess(int layerId, int expertId, float weight);
        void prefetchNextExperts(int layerId);
        size_t generateWithMedusa(const int *promptTokens, size_t promptLen,
                                  int *outputTokens, size_t maxOutputLen,
                                  InferenceStats *stats);
        void applySlidingWindow(size_t &attentionStart, size_t &attentionEnd);

        // ====================================================================
        // DEEP2_MODEL_FIT_AUTHORITY_001 internal helpers
        // ====================================================================

        // Build the FitModelGeometry from a GGUFLoader without binding weights.
        bool buildFitGeometry(const std::string &ggufPath,
                              const GGUFLoader &loader,
                              rawrxd::FitModelGeometry &geo,
                              uint64_t &contentHash,
                              uint64_t &tokenizerHash) const;

        // Refresh the measured hardware snapshot (RAM/storage/GPUs).
        void probeHostHardware(const std::string &storagePathHint);

        // Bind the admitted plan into the executor (device slots + lane).
        // Returns false when the hardware cannot honor the plan.
        bool commitFitPlan(const rawrxd::ModelFitPlan &plan);

        // Establish the execution-ledger identity for a generate() run.
        void beginExecutionRun();
        void endExecutionRun();

        // ====================================================================
        // DEEP2_BATCHED_PREFILL_001 — chunked-causal prefill.
        // Runs the whole prompt (or one chunk of it) layer-major.
        // ====================================================================

        // One layer over a contiguous chunk of tokens.  KV is appended per
        // row in causal order; returns false on a real per-layer failure.
        bool forwardLayerBatched(size_t layer, ActivationBatch &batch,
                                 size_t chunkBase, size_t seqLen);

        // H11 dispatch accounting (the four independent counters).
        DispatchAccount dispatchAccount_;
        void noteCmdDispatch(uint64_t n = 1) { dispatchAccount_.cmdDispatchCount += n; }
        void noteQueueSubmit(uint64_t n = 1) { dispatchAccount_.queueSubmitCount += n; }
        void noteFenceWait(uint64_t n = 1) { dispatchAccount_.fenceWaitCount += n; }
        void noteGpuExecutionNs(uint64_t ns) { dispatchAccount_.gpuExecutionNs += ns; }
        void noteGpuSyncNs(uint64_t ns) { dispatchAccount_.gpuSyncNs += ns; }
        void noteMatrixRows(uint64_t rows) { dispatchAccount_.matrixRowsDelta += rows; }
    };

} // namespace Deep2

#endif // DEEP2_ENGINE_H

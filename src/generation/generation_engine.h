// ============================================================================
// generation_engine.h — Full Generation Logic for CLI and GUI IDE
// ============================================================================
// This header provides the complete generation pipeline integrating:
// - Vulkan/ROCm GPU backends
// - Speculative execution
// - KV cache management
// - Token sampling strategies
// - Streaming generation
//
// Supports both CLI (batch) and GUI IDE (interactive) modes.
//
// ============================================================================

#pragma once

#include "../backend/vulkan_rocm_backend.h"
#include "../speculative/speculative_execution_engine.h"
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <queue>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <future>
#include <cstdint>

namespace RawrXD {
namespace Generation {

// ============================================================================
// Forward Declarations
// ============================================================================
class Tokenizer;
class ModelWeights;
class Sampler;
class StreamingBuffer;

// ============================================================================
// Generation Mode
// ============================================================================
enum class GenerationMode {
    Batch = 0,      // CLI mode - generate all at once
    Streaming = 1,  // GUI mode - stream tokens as ready
    Interactive = 2 // Real-time chat mode
};

// ============================================================================
// Sampling Strategy
// ============================================================================
enum class SamplingStrategy {
    Greedy = 0,
    Temperature = 1,
    TopK = 2,
    TopP = 3,
    TopKTopP = 4,
    BeamSearch = 5
};

// ============================================================================
// Generation Configuration
// ============================================================================
struct GenerationConfig {
    // Model settings
    std::string modelPath;
    uint32_t numLayers = 32;
    uint32_t hiddenSize = 4096;
    uint32_t numHeads = 32;
    uint32_t numKeyValueHeads = 32;
    uint32_t vocabSize = 32000;
    uint32_t intermediateSize = 14336;
    float rmsNormEps = 1e-5f;
    float ropeTheta = 10000.0f;
    uint32_t maxPositionEmbeddings = 131072;

    // Generation settings
    uint32_t maxNewTokens = 512;
    uint32_t maxContextLength = 4096;
    SamplingStrategy samplingStrategy = SamplingStrategy::TopKTopP;
    float temperature = 0.7f;
    uint32_t topK = 40;
    float topP = 0.9f;
    float repetitionPenalty = 1.0f;
    uint32_t numBeams = 1;

    // Performance settings
    bool useGPU = true;
    GPU::GPUBackendType gpuBackend = GPU::GPUBackendType::Auto;
    uint32_t gpuLayers = 999; // Offload all layers to GPU
    bool useFlashAttention = true;
    bool useSpeculative = true;
    std::string draftModelPath;
    uint32_t speculativeTokens = 5;

    // Streaming settings
    GenerationMode mode = GenerationMode::Batch;
    uint32_t streamingIntervalMs = 50;
    bool echo = false; // Include prompt in output

    // Special tokens
    TokenId bosToken = 1;
    TokenId eosToken = 2;
    TokenId padToken = 0;
    std::vector<TokenId> stopTokens;

    // Callbacks (for streaming mode)
    std::function<void(const std::string&)> onToken;
    std::function<void(const std::string&)> onSentence;
    std::function<void()> onComplete;
    std::function<void(const std::string&)> onError;
};

// ============================================================================
// Generation Result
// ============================================================================
struct GenerationResult {
    std::string text;
    std::vector<TokenId> tokens;
    uint32_t numTokensGenerated;
    uint32_t numPromptTokens;
    double generationTimeMs;
    double tokensPerSecond;
    bool finished;
    std::string finishReason; // "length", "eos", "stop"
};

// ============================================================================
// Token Info (for streaming)
// ============================================================================
struct TokenInfo {
    TokenId id;
    std::string text;
    float logprob;
    bool isSpecial;
    uint32_t position;
};

// ============================================================================
// Streaming Callback Interface
// ============================================================================
class IStreamingCallback {
public:
    virtual ~IStreamingCallback() = default;
    virtual void OnToken(const TokenInfo& token) = 0;
    virtual void OnSentence(const std::string& sentence) = 0;
    virtual void OnComplete(const GenerationResult& result) = 0;
    virtual void OnError(const std::string& error) = 0;
};

// ============================================================================
// Tokenizer Interface
// ============================================================================
class ITokenizer {
public:
    virtual ~ITokenizer() = default;

    // Encode text to tokens
    virtual std::vector<TokenId> Encode(const std::string& text) = 0;

    // Decode tokens to text
    virtual std::string Decode(const std::vector<TokenId>& tokens) = 0;

    // Decode single token
    virtual std::string DecodeToken(TokenId token) = 0;

    // Get vocab size
    virtual uint32_t GetVocabSize() const = 0;

    // Special tokens
    virtual TokenId GetBosToken() const = 0;
    virtual TokenId GetEosToken() const = 0;
    virtual TokenId GetPadToken() const = 0;
    virtual bool IsSpecialToken(TokenId token) const = 0;
};

// ============================================================================
// BPE Tokenizer Implementation
// ============================================================================
class BPETokenizer : public ITokenizer {
public:
    BPETokenizer();
    ~BPETokenizer() override;

    bool Load(const std::string& vocabPath);

    std::vector<TokenId> Encode(const std::string& text) override;
    std::string Decode(const std::vector<TokenId>& tokens) override;
    std::string DecodeToken(TokenId token) override;
    uint32_t GetVocabSize() const override { return vocabSize_; }

    TokenId GetBosToken() const override { return bosToken_; }
    TokenId GetEosToken() const override { return eosToken_; }
    TokenId GetPadToken() const override { return padToken_; }
    bool IsSpecialToken(TokenId token) const override;

private:
    std::unordered_map<std::string, TokenId> vocab_;
    std::unordered_map<TokenId, std::string> idToToken_;
    uint32_t vocabSize_ = 0;
    TokenId bosToken_ = 1;
    TokenId eosToken_ = 2;
    TokenId padToken_ = 0;

    std::vector<std::string> ByteEncode(const std::string& text);
    std::string ByteDecode(const std::string& token);
};

// ============================================================================
// Model Weights Manager
// ============================================================================
class ModelWeights {
public:
    ModelWeights(GPU::IGPUBackend* backend);
    ~ModelWeights();

    // Load weights from GGUF file
    bool LoadFromGGUF(const std::string& path, const GenerationConfig& config);

    // Get layer weights
    GPU::GPUBuffer* GetEmbeddingWeight() { return embeddingWeight_; }
    GPU::GPUBuffer* GetOutputWeight() { return outputWeight_; }
    GPU::GPUBuffer* GetLayerNormWeight(uint32_t layer) { return layerNormWeights_[layer]; }
    GPU::GPUBuffer* GetQKVWeight(uint32_t layer) { return qkvWeights_[layer]; }
    GPU::GPUBuffer* GetOWeight(uint32_t layer) { return oWeights_[layer]; }
    GPU::GPUBuffer* GetGateUpWeight(uint32_t layer) { return gateUpWeights_[layer]; }
    GPU::GPUBuffer* GetDownWeight(uint32_t layer) { return downWeights_[layer]; }

    // Check if loaded
    bool IsLoaded() const { return loaded_; }

    // Get memory usage
    uint64_t GetTotalWeightBytes() const { return totalWeightBytes_; }

private:
    GPU::IGPUBackend* backend_;

    // Embedding and output
    GPU::GPUBuffer* embeddingWeight_ = nullptr;
    GPU::GPUBuffer* outputWeight_ = nullptr;

    // Per-layer weights
    std::vector<GPU::GPUBuffer*> layerNormWeights_;
    std::vector<GPU::GPUBuffer*> qkvWeights_;
    std::vector<GPU::GPUBuffer*> oWeights_;
    std::vector<GPU::GPUBuffer*> gateUpWeights_;
    std::vector<GPU::GPUBuffer*> downWeights_;

    uint64_t totalWeightBytes_ = 0;
    bool loaded_ = false;
};

// ============================================================================
// Sampler
// ============================================================================
class Sampler {
public:
    Sampler(const GenerationConfig& config);
    ~Sampler();

    // Sample from logits
    TokenId Sample(const std::vector<float>& logits, const std::vector<TokenId>& context);

    // Sample with repetition penalty
    TokenId SampleWithPenalty(const std::vector<float>& logits,
                               const std::vector<TokenId>& context,
                               float penalty);

    // Reset state
    void Reset();

private:
    GenerationConfig config_;
    std::mt19937 rng_;

    TokenId GreedySample(const std::vector<float>& logits);
    TokenId TemperatureSample(const std::vector<float>& logits, float temperature);
    TokenId TopKSample(const std::vector<float>& logits, uint32_t k);
    TokenId TopPSample(const std::vector<float>& logits, float p);
    TokenId TopKTopPSample(const std::vector<float>& logits, uint32_t k, float p);

    void ApplyRepetitionPenalty(std::vector<float>& logits,
                                 const std::vector<TokenId>& context,
                                 float penalty);
    void Softmax(std::vector<float>& logits);
};

// ============================================================================
// Transformer Layer
// ============================================================================
class TransformerLayer {
public:
    TransformerLayer(uint32_t layerId, GPU::IGPUBackend* backend);
    ~TransformerLayer();

    // Initialize with weights
    bool Initialize(ModelWeights* weights, const GenerationConfig& config);

    // Forward pass
    bool Forward(GPU::GPUBuffer* input, GPU::GPUBuffer* output,
                  GPU::KVCacheEntry* kvCache, uint32_t seqLen,
                  uint32_t startPos, bool useCache);

private:
    uint32_t layerId_;
    GPU::IGPUBackend* backend_;

    // Intermediate buffers
    GPU::GPUBuffer* attnOutput_ = nullptr;
    GPU::GPUBuffer* ffnOutput_ = nullptr;

    bool initialized_ = false;
};

// ============================================================================
// Main Generation Engine
// ============================================================================
class GenerationEngine {
public:
    GenerationEngine();
    ~GenerationEngine();

    // Initialize the engine
    bool Initialize(const GenerationConfig& config);

    // Shutdown
    void Shutdown();

    // Load model
    bool LoadModel(const std::string& modelPath);

    // Check if model is loaded
    bool IsModelLoaded() const { return modelLoaded_; }

    // Generate text (batch mode)
    GenerationResult Generate(const std::string& prompt);
    GenerationResult Generate(const std::vector<TokenId>& promptTokens);

    // Generate with streaming (GUI/IDE mode)
    void GenerateStreaming(const std::string& prompt, IStreamingCallback* callback);
    void GenerateStreaming(const std::vector<TokenId>& promptTokens, IStreamingCallback* callback);

    // Async generation
    std::future<GenerationResult> GenerateAsync(const std::string& prompt);

    // Cancel ongoing generation
    void CancelGeneration();

    // Check if generating
    bool IsGenerating() const { return isGenerating_.load(); }

    // Get performance stats
    struct PerformanceStats {
        double avgTokensPerSecond;
        double avgLatencyMs;
        uint64_t totalTokensGenerated;
        uint64_t totalPromptsProcessed;
        double gpuUtilization;
        uint64_t vramUsed;
        uint64_t vramTotal;
    };
    PerformanceStats GetPerformanceStats() const;

    // Reset performance stats
    void ResetStats();

    // Update configuration
    void UpdateConfig(const GenerationConfig& config);
    const GenerationConfig& GetConfig() const { return config_; }

    // Tokenizer access
    ITokenizer* GetTokenizer() { return tokenizer_.get(); }

    // GPU backend access
    GPU::IGPUBackend* GetGPUBackend() { return gpuBackend_; }

private:
    // Internal generation
    GenerationResult GenerateInternal(const std::vector<TokenId>& promptTokens);
    void GenerateStreamingInternal(const std::vector<TokenId>& promptTokens,
                                    IStreamingCallback* callback);

    // Forward pass through model
    std::vector<float> Forward(const std::vector<TokenId>& tokens, bool useCache);

    // Single token forward (for generation)
    std::vector<float> ForwardSingle(TokenId token, uint32_t position);

    // Initialize GPU resources
    bool InitializeGPU();

    // Initialize speculative execution
    bool InitializeSpeculative();

    // Tokenizer
    std::unique_ptr<ITokenizer> tokenizer_;

    // Model weights
    std::unique_ptr<ModelWeights> weights_;

    // GPU backend
    GPU::IGPUBackend* gpuBackend_ = nullptr;
    bool ownsGPUBackend_ = false;

    // Transformer layers
    std::vector<std::unique_ptr<TransformerLayer>> layers_;

    // KV cache
    std::vector<GPU::KVCacheEntry*> kvCaches_;

    // Sampler
    std::unique_ptr<Sampler> sampler_;

    // Speculative execution
    std::unique_ptr<Speculative::SpeculativeExecutionEngine> speculativeEngine_;

    // Configuration
    GenerationConfig config_;

    // State
    std::atomic<bool> isGenerating_{false};
    std::atomic<bool> cancelGeneration_{false};
    bool modelLoaded_ = false;
    bool initialized_ = false;

    // Performance tracking
    std::atomic<uint64_t> totalTokensGenerated_{0};
    std::atomic<uint64_t> totalPromptsProcessed_{0};
    std::atomic<uint64_t> totalGenerationTimeNs_{0};

    std::mutex generationMutex_;
};

// ============================================================================
// CLI Generation Interface
// ============================================================================
class CLIGenerator {
public:
    CLIGenerator();
    ~CLIGenerator();

    // Initialize with model
    bool Initialize(const std::string& modelPath, const GenerationConfig& config = {});

    // Generate completion
    std::string Generate(const std::string& prompt, uint32_t maxTokens = 512);

    // Interactive mode
    void RunInteractive();

    // Batch process file
    void ProcessFile(const std::string& inputPath, const std::string& outputPath);

private:
    std::unique_ptr<GenerationEngine> engine_;
};

// ============================================================================
// GUI/IDE Generation Interface
// ============================================================================
class GUIIDEGenerator : public IStreamingCallback {
public:
    GUIIDEGenerator();
    ~GUIIDEGenerator();

    // Initialize with model
    bool Initialize(const std::string& modelPath, const GenerationConfig& config = {});

    // Start generation
    void StartGeneration(const std::string& prompt);

    // Stop generation
    void StopGeneration();

    // Check if generating
    bool IsGenerating() const;

    // Get generated text so far
    std::string GetGeneratedText() const;

    // Clear generated text
    void Clear();

    // Set callbacks
    void SetOnToken(std::function<void(const std::string&)> callback) { onToken_ = callback; }
    void SetOnComplete(std::function<void()> callback) { onComplete_ = callback; }

    // IStreamingCallback implementation
    void OnToken(const TokenInfo& token) override;
    void OnSentence(const std::string& sentence) override;
    void OnComplete(const GenerationResult& result) override;
    void OnError(const std::string& error) override;

private:
    std::unique_ptr<GenerationEngine> engine_;
    std::string generatedText_;
    mutable std::mutex textMutex_;

    std::function<void(const std::string&)> onToken_;
    std::function<void()> onComplete_;
};

// ============================================================================
// Generation Engine Factory
// ============================================================================
class GenerationEngineFactory {
public:
    // Create engine with auto-configuration
    static std::unique_ptr<GenerationEngine> CreateEngine(
        const std::string& modelPath,
        GenerationMode mode = GenerationMode::Batch);

    // Create with explicit configuration
    static std::unique_ptr<GenerationEngine> CreateEngine(
        const GenerationConfig& config);

    // Create CLI generator
    static std::unique_ptr<CLIGenerator> CreateCLI(const std::string& modelPath);

    // Create GUI/IDE generator
    static std::unique_ptr<GUIIDEGenerator> CreateGUI(const std::string& modelPath);
};

} // namespace Generation
} // namespace RawrXD

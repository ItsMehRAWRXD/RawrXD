/**
 * @file InferenceEngine.h
 * @brief Unified Inference Engine API - Layer 2
 * 
 * Consolidates all CPUInferenceEngine implementations into a single interface.
 * Replaces:
 *   - cpu_inference_engine.h/cpp
 *   - cpu_inference_engine_Clean.h/cpp
 *   - cpu_inference_engine_fixed.cpp
 *   - cpu_inference_engine_init_fix.cpp
 *   - cpu_inference_engine_production.cpp
 *   - cpu_inference_engine_real.cpp
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

// Forward declarations for GGML (Layer 1)
struct ggml_context;
struct ggml_tensor;
struct ggml_model;

namespace RawrXD {
namespace Inference {

// ============================================================================
// Configuration Structures
// ============================================================================

/**
 * @brief Engine configuration parameters
 */
struct EngineConfig {
    // Model settings
    std::string modelPath;           ///< Path to GGUF model file
    size_t maxContextLength = 4096;  ///< Maximum context tokens
    size_t batchSize = 1;            ///< Inference batch size
    
    // Threading
    int numThreads = 0;              ///< 0 = auto-detect
    
    // Hardware
    bool useGPU = true;              ///< Enable GPU acceleration
    int gpuLayerCount = -1;          ///< -1 = all layers
    
    // Memory
    size_t memoryPoolSize = 0;       ///< 0 = auto (MB)
    bool useMemoryMapping = true;    ///< Use mmap for model loading
    
    // Validation
    bool validateTensors = true;     ///< Validate tensor integrity on load
    bool computeChecksums = false;   ///< Compute SHA256 of weights
    
    // GGML backend
    size_t tensorBufferSize = 1024 * 1024 * 1024;  ///< 1GB default tensor buffer
};

/**
 * @brief Generation/sampling parameters
 */
struct GenerationParams {
    // Sampling
    float temperature = 0.7f;        ///< Softmax temperature
    int topK = 40;                   ///< Top-k sampling (0 = disabled)
    float topP = 0.9f;               ///< Nucleus sampling (1.0 = disabled)
    float repeatPenalty = 1.1f;      ///< Repetition penalty
    int repeatLastN = 64;            ///< Tokens to check for repetition
    
    // Limits
    int maxTokens = 256;             ///< Maximum tokens to generate
    int minTokens = 1;               ///< Minimum tokens to generate
    
    // Stopping
    std::vector<std::string> stopSequences;  ///< Stop generation on these
    std::string stopEOS;             ///< EOS token string
    
    // Streaming
    bool streamOutput = false;         ///< Enable token streaming
    size_t streamInterval = 1;       ///< Tokens between stream callbacks
};

// ============================================================================
// Result Structures
// ============================================================================

/**
 * @brief Token information
 */
struct TokenInfo {
    int id;                          ///< Token ID
    std::string text;                ///< Token text
    float logprob;                   ///< Log probability
    bool isSpecial;                  ///< Special token (EOS, BOS, etc.)
};

/**
 * @brief Generation result
 */
struct GenerationResult {
    bool success = false;            ///< Generation succeeded
    std::string text;                ///< Generated text
    std::vector<TokenInfo> tokens;   ///< Token details
    
    // Metrics
    int tokensGenerated = 0;       ///< Number of tokens generated
    int promptTokens = 0;          ///< Number of prompt tokens
    float tokensPerSecond = 0.0f;  ///< Generation speed
    int64_t durationMs = 0;        ///< Total time in milliseconds
    
    // Status
    bool stoppedEOS = false;       ///< Stopped due to EOS
    bool stoppedLimit = false;     ///< Stopped due to token limit
    bool stoppedSequence = false;  ///< Stopped due to stop sequence
    bool isComplete = false;       ///< Generation is complete
    std::string stopReason;          ///< Human-readable stop reason
    std::string errorMessage;        ///< Error if success=false
};

/**
 * @brief Model information
 */
struct ModelInfo {
    std::string path;                ///< Model file path
    std::string architecture;        ///< Model architecture (llama, etc.)
    std::string quantization;        ///< Quantization type (Q4_K_M, etc.)
    
    // Dimensions
    int vocabSize;                   ///< Vocabulary size
    int numLayers;                   ///< Number of layers
    int embeddingDim;                ///< Embedding dimension
    int numHeads;                    ///< Number of attention heads
    int contextLength;               ///< Maximum context length
    
    // Memory
    size_t modelSize;                ///< Model size in bytes
    size_t weightsSize;              ///< Weights size in bytes
    size_t vocabSizeBytes;           ///< Vocabulary size in bytes
    
    // Features
    bool hasTokenizer;               ///< Has embedded tokenizer
    bool hasGGMLFormat;              ///< Valid GGML/GGUF format
};

/**
 * @brief Performance metrics from generation
 */
struct PerformanceMetrics {
    float tokensPerSecond = 0.0f;
    float promptTokensPerSecond = 0.0f;
    int64_t timeToFirstTokenMs = 0;
    int64_t totalTimeMs = 0;
    size_t memoryUsed = 0;
    float cpuUtilization = 0.0f;
    int tokensGenerated = 0;
    int promptTokens = 0;
};

// ============================================================================
// Main Interface
// ============================================================================

/**
 * @brief Unified inference engine interface
 * 
 * This is the single, consolidated inference engine that replaces all
 * previous CPUInferenceEngine implementations.
 * 
 * Thread Safety:
 * - LoadModel/UnloadModel: Not thread-safe (call from single thread)
 * - Generate/GenerateStreaming: Thread-safe for concurrent generation
 * - Tokenize/Detokenize: Thread-safe
 * - Getters (IsLoaded, GetInfo, etc.): Thread-safe
 */
class InferenceEngine {
public:
    virtual ~InferenceEngine() = default;

    // ------------------------------------------------------------------------
    // Factory
    // ------------------------------------------------------------------------
    
    /**
     * @brief Create a new inference engine instance
     * @param config Engine configuration
     * @return Unique pointer to engine instance
     */
    static std::unique_ptr<InferenceEngine> Create(const EngineConfig& config);
    
    /**
     * @brief Create with default configuration
     * @return Unique pointer to engine instance
     */
    static std::unique_ptr<InferenceEngine> Create();

    // ------------------------------------------------------------------------
    // Factory - Legacy Adapter
    // ------------------------------------------------------------------------
    
    /**
     * @brief Create adapter wrapping existing legacy inference engine
     * @param legacyEngine Existing inference engine instance (LegacyInferenceEngine*)
     * @param config Engine configuration
     * @return Adapter instance implementing InferenceEngine interface
     * 
     * This factory method allows gradual migration from legacy code.
     * The adapter wraps the existing engine behind the new unified API.
     */
    static std::unique_ptr<InferenceEngine> CreateLegacyAdapter(
        void* legacyEngine,
        const EngineConfig& config = EngineConfig{});

    // ------------------------------------------------------------------------
    // Model Lifecycle
    // ------------------------------------------------------------------------
    
    /**
     * @brief Load a model from file
     * @param path Path to GGUF model file
     * @return true if successful
     */
    virtual bool LoadModel(const std::string& path) = 0;
    
    /**
     * @brief Unload the current model
     */
    virtual void UnloadModel() = 0;
    
    /**
     * @brief Check if a model is loaded
     * @return true if model is loaded and ready
     */
    virtual bool IsModelLoaded() const = 0;
    
    /**
     * @brief Get information about the loaded model
     * @return Model info (empty if no model loaded)
     */
    virtual ModelInfo GetModelInfo() const = 0;

    // ------------------------------------------------------------------------
    // Generation
    // ------------------------------------------------------------------------
    
    /**
     * @brief Generate text from a prompt (synchronous)
     * @param prompt Input prompt text
     * @param params Generation parameters
     * @return Generation result
     */
    virtual GenerationResult Generate(
        const std::string& prompt,
        const GenerationParams& params
    ) = 0;
    
    /**
     * @brief Generate text with streaming callback
     * @param prompt Input prompt text
     * @param params Generation parameters
     * @param callback Called for each token (return false to stop)
     * @return Generation result
     */
    virtual GenerationResult GenerateStreaming(
        const std::string& prompt,
        const GenerationParams& params,
        std::function<bool(const TokenInfo&)> callback
    ) = 0;
    
    /**
     * @brief Generate with simple string callback
     * @param prompt Input prompt text
     * @param params Generation parameters
     * @param callback Called with token text
     * @return Generation result
     */
    virtual GenerationResult GenerateStreaming(
        const std::string& prompt,
        const GenerationParams& params,
        std::function<void(const std::string&)> callback
    ) = 0;

    // ------------------------------------------------------------------------
    // Token Operations
    // ------------------------------------------------------------------------
    
    /**
     * @brief Tokenize text into token IDs
     * @param text Input text
     * @return Vector of token IDs
     */
    virtual std::vector<int> Tokenize(const std::string& text) = 0;
    
    /**
     * @brief Tokenize with special tokens (BOS/EOS)
     * @param text Input text
     * @param addBOS Add beginning-of-sequence token
     * @param addEOS Add end-of-sequence token
     * @return Vector of token IDs
     */
    virtual std::vector<int> Tokenize(
        const std::string& text,
        bool addBOS,
        bool addEOS
    ) = 0;
    
    /**
     * @brief Convert token IDs to text
     * @param tokens Vector of token IDs
     * @return Detokenized text
     */
    virtual std::string Detokenize(const std::vector<int>& tokens) = 0;
    
    /**
     * @brief Convert single token ID to text
     * @param token Token ID
     * @return Token text
     */
    virtual std::string Detokenize(int token) = 0;
    
    /**
     * @brief Get token info by ID
     * @param tokenId Token ID
     * @return Token information
     */
    virtual TokenInfo GetTokenInfo(int tokenId) = 0;

    // ------------------------------------------------------------------------
    // Context Management
    // ------------------------------------------------------------------------
    
    /**
     * @brief Clear the conversation context
     */
    virtual void ClearContext() = 0;
    
    /**
     * @brief Get current context length in tokens
     * @return Number of tokens in context
     */
    virtual size_t GetContextLength() const = 0;
    
    /**
     * @brief Get remaining context capacity
     * @return Tokens remaining before context limit
     */
    virtual size_t GetContextRemaining() const = 0;
    
    /**
     * @brief Check if context is full
     * @return true if context is at capacity
     */
    virtual bool IsContextFull() const = 0;
    
    /**
     * @brief Set system prompt/prefix
     * @param systemPrompt System prompt text
     */
    virtual void SetSystemPrompt(const std::string& systemPrompt) = 0;

    // ------------------------------------------------------------------------
    // Metrics & Diagnostics
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get last generation metrics
     * @return Performance metrics from last generation
     */
    virtual PerformanceMetrics GetLastMetrics() const = 0;
    
    /**
     * @brief Reset performance metrics
     */
    virtual void ResetMetrics() = 0;
    
    /**
     * @brief Validate model integrity
     * @return true if model passes validation
     */
    virtual bool ValidateModel() = 0;
    
    /**
     * @brief Get detailed error information
     * @return Last error message
     */
    virtual std::string GetLastError() const = 0;

    // ------------------------------------------------------------------------
    // Advanced Features
    // ------------------------------------------------------------------------
    
    /**
     * @brief Set a callback for progress updates
     * @param callback Progress callback (0.0 to 1.0)
     */
    virtual void SetProgressCallback(
        std::function<void(float)> callback
    ) = 0;
    
    /**
     * @brief Cancel current generation
     */
    virtual void CancelGeneration() = 0;
    
    /**
     * @brief Check if generation is in progress
     * @return true if generating
     */
    virtual bool IsGenerating() const = 0;
    
    /**
     * @brief Warm up the model (pre-allocate buffers)
     * @return true if successful
     */
    virtual bool Warmup() = 0;
    
    /**
     * @brief Get internal GGML context (for advanced use)
     * @return GGML context pointer (may be null)
     */
    virtual ggml_context* GetGGMLContext() = 0;
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get library version
 * @return Version string
 */
const char* GetInferenceVersion();

/**
 * @brief Get available hardware info
 * @return Hardware capabilities
 */
struct HardwareInfo {
    int numPhysicalCores;
    int numLogicalCores;
    bool hasAVX;
    bool hasAVX2;
    bool hasAVX512;
    bool hasGPU;
    size_t systemMemory;
    size_t gpuMemory;
};
HardwareInfo GetHardwareInfo();

/**
 * @brief Check if file is a valid GGUF model
 * @param path File path
 * @return true if valid GGUF
 */
bool IsValidGGUF(const std::string& path);

/**
 * @brief Get model info without loading
 * @param path Model file path
 * @return Model info (empty if invalid)
 */
ModelInfo PeekModelInfo(const std::string& path);

} // namespace Inference
} // namespace RawrXD

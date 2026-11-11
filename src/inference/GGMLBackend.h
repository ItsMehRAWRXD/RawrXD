/**
 * @file GGMLBackend.h
 * @brief Clean C++ wrapper around GGML for model loading and inference
 * 
 * Part of Phase 3: Real GGML Integration
 * Provides a modern C++ interface to GGML functionality.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Forward declarations for GGML C types (opaque pointers)
// These are defined in the global namespace in GGML headers
struct ggml_rxd_context;
struct ggml_rxd_tensor;
struct ggml_rxd_backend;
struct gguf_context;

namespace RawrXD {
namespace Inference {

// Model architecture definition
struct ModelArchitecture {
    std::string name;                ///< Model architecture name (llama, qwen, etc.)
    int vocabSize = 0;               ///< Vocabulary size
    int numLayers = 0;               ///< Number of transformer layers
    int numHeads = 0;                ///< Number of attention heads
    int numKVHeads = 0;              ///< Number of key/value heads (GQA)
    int embeddingDim = 0;            ///< Embedding dimension
    int hiddenDim = 0;               ///< Feed-forward hidden dimension
    int contextLength = 0;           ///< Maximum context length
    float ropeFreqBase = 10000.0f;   ///< RoPE frequency base
    float ropeFreqScale = 1.0f;      ///< RoPE frequency scale
};

/**
 * @brief GGML backend configuration
 */
struct GGMLBackendConfig {
    enum class BackendType {
        CPU,        ///< CPU backend
        CUDA,       ///< NVIDIA CUDA backend
        Vulkan,     ///< Vulkan GPU backend
        Metal,      ///< Apple Metal backend
        Auto        ///< Automatically select best backend
    };
    
    BackendType backendType = BackendType::Auto;
    size_t maxContextSize = 4096;      ///< Maximum context size in tokens
    size_t maxBatchSize = 512;         ///< Maximum batch size
    size_t tensorBufferSize = 1024 * 1024 * 1024;  ///< 1GB default tensor buffer
    int numThreads = 0;                ///< 0 = auto-detect
    bool useGPU = true;                ///< Try to use GPU if available
    int gpuLayerCount = 99;            ///< Number of layers to offload to GPU
};

/**
 * @brief GGML Backend wrapper
 * 
 * Provides a clean C++ interface to GGML functionality including:
 * - Backend initialization
 * - Model loading from GGUF
 * - Context management
 * - Inference execution
 * - Tokenization
 */
class GGMLBackend {
public:
    /**
     * @brief Create a new GGML backend instance
     * @param config Backend configuration
     * @return Unique pointer to backend instance
     */
    static std::unique_ptr<GGMLBackend> Create(const GGMLBackendConfig& config = GGMLBackendConfig{});
    
    /**
     * @brief Destructor
     */
    ~GGMLBackend();

    // ------------------------------------------------------------------------
    // Backend Lifecycle
    // ------------------------------------------------------------------------
    
    /**
     * @brief Initialize the backend
     * @return true if successful
     */
    bool Initialize();
    
    /**
     * @brief Shutdown the backend and free resources
     */
    void Shutdown();
    
    /**
     * @brief Check if backend is initialized
     * @return true if ready
     */
    bool IsInitialized() const;
    
    /**
     * @brief Get the backend type in use
     * @return Backend type string
     */
    std::string GetBackendType() const;

    // ------------------------------------------------------------------------
    // Model Loading
    // ------------------------------------------------------------------------
    
    /**
     * @brief Load a model from GGUF file
     * @param path Path to GGUF file
     * @return true if successful
     */
    bool LoadModel(const std::string& path);
    
    /**
     * @brief Unload the current model
     */
    void UnloadModel();
    
    /**
     * @brief Check if a model is loaded
     * @return true if model is loaded
     */
    bool IsModelLoaded() const;
    
    /**
     * @brief Get model architecture info
     * @return Model architecture
     */
    ModelArchitecture GetModelArchitecture() const;
    
    /**
     * @brief Get model size in bytes
     * @return Model size
     */
    size_t GetModelSize() const;

    // ------------------------------------------------------------------------
    // Tokenization
    // ------------------------------------------------------------------------
    
    /**
     * @brief Tokenize text
     * @param text Input text
     * @param addBOS Add beginning-of-sequence token
     * @param addEOS Add end-of-sequence token
     * @return Vector of token IDs
     */
    std::vector<int> Tokenize(const std::string& text, bool addBOS = false, bool addEOS = false);
    
    /**
     * @brief Convert token IDs to text
     * @param tokens Vector of token IDs
     * @return Detokenized text
     */
    std::string Detokenize(const std::vector<int>& tokens);
    
    /**
     * @brief Convert single token to text
     * @param token Token ID
     * @return Token text
     */
    std::string GetTokenText(int token) const;
    
    /**
     * @brief Get vocabulary size
     * @return Number of tokens in vocabulary
     */
    int GetVocabSize() const;
    
    /**
     * @brief Get special token IDs
     */
    int GetBOSToken() const;
    int GetEOSToken() const;
    int GetPadToken() const;
    int GetNLToken() const;

    // ------------------------------------------------------------------------
    // Inference
    // ------------------------------------------------------------------------
    
    /**
     * @brief Run forward pass to get logits
     * @param tokens Input tokens
     * @return Logits for next token prediction
     */
    std::vector<float> Forward(const std::vector<int>& tokens);
    
    /**
     * @brief Run forward pass with batch
     * @param batchTokens Batch of token sequences
     * @return Logits for each sequence
     */
    std::vector<std::vector<float>> ForwardBatch(const std::vector<std::vector<int>>& batchTokens);
    
    /**
     * @brief Sample next token from logits
     * @param logits Logits from forward pass
     * @param temperature Sampling temperature
     * @param topK Top-K sampling (0 = disabled)
     * @param topP Top-P sampling (1.0 = disabled)
     * @param repeatPenalty Repeat penalty (1.0 = disabled)
     * @return Sampled token ID
     */
    int SampleToken(const std::vector<float>& logits,
                    float temperature = 1.0f,
                    int topK = 40,
                    float topP = 0.95f,
                    float repeatPenalty = 1.0f);
    
    /**
     * @brief Generate text from prompt
     * @param prompt Input prompt
     * @param maxTokens Maximum tokens to generate
     * @param temperature Sampling temperature
     * @param callback Optional callback for each generated token
     * @return Generated text
     */
    std::string Generate(const std::string& prompt,
                         int maxTokens = 256,
                         float temperature = 0.7f,
                         std::function<bool(const std::string&)> callback = nullptr);

    // ------------------------------------------------------------------------
    // Context Management
    // ------------------------------------------------------------------------
    
    /**
     * @brief Clear the KV cache
     */
    void ClearKVCache();
    
    /**
     * @brief Get current context length
     * @return Number of tokens in current context
     */
    size_t GetContextLength() const;
    
    /**
     * @brief Get maximum context length
     * @return Maximum supported context length
     */
    size_t GetMaxContextLength() const;

    // ------------------------------------------------------------------------
    // Memory Management
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get memory usage
     * @return Memory used in bytes
     */
    size_t GetMemoryUsage() const;
    
    /**
     * @brief Get total memory allocated
     * @return Total allocated in bytes
     */
    size_t GetTotalAllocated() const;

    // ------------------------------------------------------------------------
    // Error Handling
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get last error message
     * @return Error description
     */
    std::string GetLastError() const;
    
    /**
     * @brief Clear error state
     */
    void ClearError();

private:
    // Private implementation (PIMPL pattern)
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Private constructor - use Create() factory
    GGMLBackend(const GGMLBackendConfig& config);
};

} // namespace Inference
} // namespace RawrXD

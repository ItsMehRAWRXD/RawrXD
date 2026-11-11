#pragma once

#include <cstdint>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd {

/**
 * @brief Configuration for the code embedding model
 */
struct EmbedderConfig {
    std::string model_path;              // Path to ONNX model file
    std::string tokenizer_vocab_path;    // Path to tokenizer vocabulary
    int max_sequence_length = 512;       // Max tokens per input
    int embedding_dimension = 384;       // Output vector dimension
    bool use_gpu = false;                // Use GPU for inference (if available)
    int intra_op_threads = 4;              // ONNX intra-op parallelism
    int inter_op_threads = 1;            // ONNX inter-op parallelism
};

/**
 * @brief CodeEmbedder - ONNX Runtime-based code embedding engine
 * 
 * Phase 17C.3: Embedding Pipeline
 * Transforms code snippets into semantic vectors using CodeBERT/MiniLM
 * 
 * Architecture:
 * - Tokenization: Character -> Token ID mapping
 * - Tensor Mapping: Token IDs -> ONNX input tensors
 * - Inference: ONNX Session::Run for hidden state extraction
 * - Pooling: Mean pooling -> 384-d semantic vector
 */
class CodeEmbedder {
public:
    /**
     * @brief Construct embedder with configuration
     * @param config Embedder configuration (model path, threads, etc.)
     * 
     * Note: Model loading is lazy - happens on first Embed() call
     * to avoid blocking IDE startup
     */
    explicit CodeEmbedder(const EmbedderConfig& config = {});
    
    /**
     * @brief Destructor - ensures proper ONNX session cleanup
     */
    ~CodeEmbedder();
    
    // Disable copy, enable move
    CodeEmbedder(const CodeEmbedder&) = delete;
    CodeEmbedder& operator=(const CodeEmbedder&) = delete;
    CodeEmbedder(CodeEmbedder&&) noexcept;
    CodeEmbedder& operator=(CodeEmbedder&&) noexcept;

    /**
     * @brief Transform code into semantic vector
     * @param code Source code snippet to embed
     * @return 384-dimensional normalized embedding vector
     * 
     * Pipeline:
     * 1. Tokenize code using WordPiece/BPE tokenizer
     * 2. Create ONNX input tensors (input_ids, attention_mask)
     * 3. Run ONNX inference to get hidden states
     * 4. Mean pool hidden states -> 384-d vector
     * 5. L2 normalize output
     */
    std::vector<float> Embed(std::string_view code);
    
    /**
     * @brief Check if model is loaded and ready
     */
    bool IsLoaded() const;
    
    /**
     * @brief Get last inference latency (ms)
     */
    float GetLastLatencyMs() const;
    
    /**
     * @brief Get embedding dimension
     */
    int GetDimension() const { return m_config.embedding_dimension; }
    
    /**
     * @brief Preload model into memory (optional optimization)
     * @return true if model loaded successfully
     * 
     * Call during IDE background initialization to avoid
     * cold-start latency on first autocomplete
     */
    bool PreloadModel();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    EmbedderConfig m_config;
    float m_last_latency_ms = 0.0f;
    bool m_model_loaded = false;
};

/**
 * @brief Stub embedder for when ONNX Runtime is unavailable
 * 
 * Generates deterministic pseudo-embeddings based on text hash.
 * Used as fallback when CodeBERT model is not available.
 */
class StubCodeEmbedder {
public:
    explicit StubCodeEmbedder(int dim = 384) : dimension(dim), rng(42) {}
    
    std::vector<float> Embed(std::string_view code);
    int GetDimension() const { return dimension; }

private:
    int dimension;
    std::mt19937 rng;
};

} // namespace rawrxd

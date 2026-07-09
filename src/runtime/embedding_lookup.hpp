/**
 * @file embedding_lookup.hpp
 * @brief RawrXD Embedding Lookup - Step C3
 *
 * Converts token IDs to embedding vectors via token_embd.weight lookup.
 * Zero external dependencies. Pure C++17.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <memory>

// Forward declaration
namespace rawrxd {
namespace model {
    class ModelContext;
}
}

namespace rawrxd {
namespace runtime {

// ============================================================================
// Embedding Lookup Telemetry
// ============================================================================

struct EmbeddingTelemetry {
    uint32_t token_count = 0;           // Number of tokens processed
    uint32_t embedding_dim = 0;         // Dimension of embeddings
    double lookup_ms = 0.0;               // Time for lookup operation
    uint64_t bytes_read = 0;              // Bytes read from weight tensor
    bool used_quantized = false;          // Whether quantized weights were used
    
    std::string ToJson() const;
};

// ============================================================================
// Embedding Matrix
// ============================================================================

struct EmbeddingMatrix {
    uint32_t num_tokens = 0;              // Number of tokens (rows)
    uint32_t embedding_dim = 0;           // Embedding dimension (cols)
    std::vector<float> data;              // Flat storage: [token0_dim0, token0_dim1, ...]
    
    // Access embedding for token i
    const float* GetEmbedding(uint32_t token_id) const {
        if (token_id >= num_tokens) return nullptr;
        return &data[token_id * embedding_dim];
    }
    
    float* GetEmbedding(uint32_t token_id) {
        if (token_id >= num_tokens) return nullptr;
        return &data[token_id * embedding_dim];
    }
    
    // Get total size in bytes
    size_t GetSizeBytes() const {
        return data.size() * sizeof(float);
    }
    
    // Check if valid
    bool IsValid() const {
        return num_tokens > 0 && embedding_dim > 0 && 
               data.size() == static_cast<size_t>(num_tokens) * embedding_dim;
    }
};

// ============================================================================
// Embedding Lookup
// ============================================================================

class EmbeddingLookup {
public:
    EmbeddingLookup();
    ~EmbeddingLookup();
    
    // Initialize with model context
    bool Initialize(const model::ModelContext& model);
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get embedding for single token
    std::vector<float> GetEmbedding(uint32_t token_id) const;
    
    // Get embeddings for multiple tokens (batch lookup)
    EmbeddingMatrix GetEmbeddings(const std::vector<uint32_t>& token_ids) const;
    
    // Get embeddings with telemetry
    EmbeddingMatrix GetEmbeddingsWithTelemetry(
        const std::vector<uint32_t>& token_ids,
        EmbeddingTelemetry* telemetry) const;
    
    // Get embedding dimension
    uint32_t GetEmbeddingDim() const { return embedding_dim_; }
    
    // Get vocabulary size
    uint32_t GetVocabSize() const { return vocab_size_; }
    
    // Get last error
    const std::string& GetLastError() const { return last_error_; }
    
    // Get telemetry from last operation
    const EmbeddingTelemetry& GetLastTelemetry() const { return last_telemetry_; }
    
private:
    bool initialized_ = false;
    uint32_t vocab_size_ = 0;
    uint32_t embedding_dim_ = 0;
    std::string last_error_;
    EmbeddingTelemetry last_telemetry_;
    
    // Weight tensor data (owned by this class)
    std::vector<float> weight_data_;
    
    // Quantized weights (if applicable)
    std::vector<uint8_t> quantized_data_;
    uint32_t block_size_ = 0;
    std::vector<float> quantization_scales_;
    
    // Internal helpers
    bool LoadWeightsFromModel(const model::ModelContext& model);
    bool LoadF32Weights(const void* data, size_t size);
    bool LoadF16Weights(const void* data, size_t size);
    bool LoadQ4_0Weights(const void* data, size_t size);
    bool LoadQ8_0Weights(const void* data, size_t size);
    
    float DequantizeValue(size_t index) const;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick lookup without class instantiation
EmbeddingMatrix LookupEmbeddings(
    const model::ModelContext& model,
    const std::vector<uint32_t>& token_ids,
    std::string* error = nullptr
);

// Validate token IDs against vocab size
bool ValidateTokenIds(
    const std::vector<uint32_t>& token_ids,
    uint32_t vocab_size,
    std::vector<uint32_t>* invalid_ids = nullptr
);

} // namespace runtime
} // namespace rawrxd

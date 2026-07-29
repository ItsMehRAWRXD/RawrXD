// ============================================================================
// EmbeddingServer.hpp - Embedding Extraction & Serving
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct EmbeddingConfig {
    uint64_t dim = 4096;
    std::string modelPath;
    bool normalize = true;
    bool usePooling = true; // mean pooling for sequence
    uint32_t maxBatchSize = 32;
    uint32_t maxSeqLen = 512;
};

struct EmbeddingResult {
    std::vector<float> embedding;
    uint64_t dim;
    uint64_t tokenCount;
    bool normalized;
};

class EmbeddingServer {
public:
    EmbeddingServer();
    ~EmbeddingServer();

    bool Initialize(const EmbeddingConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    EmbeddingResult EmbedText(const std::string& text);
    std::vector<EmbeddingResult> EmbedTexts(const std::vector<std::string>& texts);
    EmbeddingResult EmbedTokens(const std::vector<int>& tokens);

    float CosineSimilarity(const EmbeddingResult& a, const EmbeddingResult& b);
    float DotProduct(const EmbeddingResult& a, const EmbeddingResult& b);
    std::vector<float> Average(const std::vector<EmbeddingResult>& embeddings);

    void Normalize(std::vector<float>& vec);
    uint64_t GetDim() const { return config_.dim; }

    struct EmbeddingStats {
        uint64_t totalEmbeddings;
        uint64_t totalTokens;
        double avgTimeMs;
    };
    EmbeddingStats GetStats() const { return stats_; }

private:
    EmbeddingConfig config_;
    EmbeddingStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
    
    std::vector<float> ExtractEmbedding(const std::vector<float>& hiddenStates, uint64_t seqLen);
};

} // namespace Sovereign

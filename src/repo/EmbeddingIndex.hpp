// ============================================================================
// EmbeddingIndex.hpp - Semantic Embedding Search
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>

namespace RawrXD {
namespace IDE {

struct EmbeddingResult {
    std::string filePath;
    size_t chunkIndex;
    std::string content;
    float similarity;
};

class EmbeddingIndex {
public:
    EmbeddingIndex();
    ~EmbeddingIndex();

    void SetEmbeddingDimension(size_t dim);
    void IndexChunk(const std::string& filePath, size_t chunkIndex, 
                    const std::string& content, const std::vector<float>& embedding);
    void RemoveFile(const std::string& filePath);
    
    std::vector<EmbeddingResult> Search(const std::vector<float>& queryEmbedding, 
                                         size_t topK = 10);
    std::vector<EmbeddingResult> SearchByText(const std::string& text, size_t topK = 10);
    
    void Clear();
    size_t GetChunkCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD

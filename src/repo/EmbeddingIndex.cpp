// ============================================================================
// EmbeddingIndex.cpp - Semantic Embedding Search
// WORKING IMPLEMENTATION
// ============================================================================

#include "EmbeddingIndex.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

namespace RawrXD {
namespace IDE {

struct EmbeddingIndex::Impl {
    size_t dimension_ = 768; // Default embedding dimension
    size_t nextChunkId_ = 0;
    
    struct Chunk {
        std::string filePath;
        size_t chunkIndex;
        std::string content;
        std::vector<float> embedding;
    };
    
    std::vector<Chunk> chunks_;
    std::unordered_map<std::string, std::vector<size_t>> fileChunks_; // filePath -> chunk indices
    
    mutable std::shared_mutex mutex_;
    
    // Cosine similarity
    float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b) {
        float dot = 0.0f, normA = 0.0f, normB = 0.0f;
        size_t n = std::min(a.size(), b.size());
        for (size_t i = 0; i < n; i++) {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }
        float denom = sqrtf(normA) * sqrtf(normB);
        return (denom > 1e-10f) ? dot / denom : 0.0f;
    }
    
    // Simple bag-of-words embedding for text (fallback when no model available)
    std::vector<float> TextToEmbedding(const std::string& text) {
        std::vector<float> embedding(dimension_, 0.0f);
        
        // Use hash-based feature extraction
        std::hash<std::string> hasher;
        size_t pos = 0;
        
        // Tokenize and hash into embedding space
        std::string current;
        for (char c : text) {
            if (isalnum(c) || c == '_') {
                current += tolower(c);
            } else {
                if (current.length() >= 2) {
                    size_t h = hasher(current);
                    size_t idx = h % dimension_;
                    embedding[idx] += 1.0f;
                    current.clear();
                }
                current.clear();
            }
        }
        if (current.length() >= 2) {
            size_t h = hasher(current);
            size_t idx = h % dimension_;
            embedding[idx] += 1.0f;
        }
        
        // Normalize
        float norm = 0.0f;
        for (float v : embedding) norm += v * v;
        norm = sqrtf(norm);
        if (norm > 1e-10f) {
            for (float& v : embedding) v /= norm;
        }
        
        return embedding;
    }
};

EmbeddingIndex::EmbeddingIndex() : impl_(std::make_unique<Impl>()) {}
EmbeddingIndex::~EmbeddingIndex() = default;

void EmbeddingIndex::SetEmbeddingDimension(size_t dim) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->dimension_ = dim;
}

void EmbeddingIndex::IndexChunk(const std::string& filePath, size_t chunkIndex,
                                 const std::string& content, const std::vector<float>& embedding) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    Impl::Chunk chunk;
    chunk.filePath = filePath;
    chunk.chunkIndex = chunkIndex;
    chunk.content = content;
    chunk.embedding = embedding;
    
    size_t idx = impl_->chunks_.size();
    impl_->chunks_.push_back(chunk);
    impl_->fileChunks_[filePath].push_back(idx);
}

void EmbeddingIndex::RemoveFile(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->fileChunks_.find(filePath);
    if (it != impl_->fileChunks_.end()) {
        // Mark chunks for removal (set filePath to empty)
        for (size_t idx : it->second) {
            impl_->chunks_[idx].filePath.clear();
        }
        impl_->fileChunks_.erase(it);
    }
}

std::vector<EmbeddingResult> EmbeddingIndex::Search(const std::vector<float>& queryEmbedding,
                                                       size_t topK) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::pair<size_t, float>> scored;
    
    for (size_t i = 0; i < impl_->chunks_.size(); i++) {
        if (impl_->chunks_[i].filePath.empty()) continue; // Removed
        
        float sim = impl_->CosineSimilarity(queryEmbedding, impl_->chunks_[i].embedding);
        scored.push_back({i, sim});
    }
    
    // Sort by similarity descending
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<EmbeddingResult> results;
    for (size_t i = 0; i < std::min(topK, scored.size()); i++) {
        auto& chunk = impl_->chunks_[scored[i].first];
        EmbeddingResult result;
        result.filePath = chunk.filePath;
        result.chunkIndex = chunk.chunkIndex;
        result.content = chunk.content;
        result.similarity = scored[i].second;
        results.push_back(result);
    }
    
    return results;
}

std::vector<EmbeddingResult> EmbeddingIndex::SearchByText(const std::string& text, size_t topK) {
    auto embedding = impl_->TextToEmbedding(text);
    return Search(embedding, topK);
}

void EmbeddingIndex::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->chunks_.clear();
    impl_->fileChunks_.clear();
}

size_t EmbeddingIndex::GetChunkCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->chunks_.size();
}

} // namespace IDE
} // namespace RawrXD

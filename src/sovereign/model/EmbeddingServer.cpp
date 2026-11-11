// ============================================================================
// EmbeddingServer.cpp - Embedding Extraction & Serving Implementation
// ============================================================================

#include "EmbeddingServer.hpp"
#include <cmath>
#include <numeric>
#include <iostream>

namespace Sovereign {

EmbeddingServer::EmbeddingServer() = default;
EmbeddingServer::~EmbeddingServer() { Shutdown(); }

bool EmbeddingServer::Initialize(const EmbeddingConfig& config) {
    config_ = config;
    initialized_ = true;
    return true;
}

void EmbeddingServer::Shutdown() { initialized_ = false; }

EmbeddingResult EmbeddingServer::EmbedText(const std::string& text) {
    EmbeddingResult result;
    result.embedding.resize(config_.dim, 0);
    result.dim = config_.dim;
    result.tokenCount = text.size() / 4;
    
    // Simplified: hash-based embedding
    for (size_t i = 0; i < text.size(); ++i) {
        result.embedding[i % config_.dim] += static_cast<float>(text[i]) / 255.0f;
    }
    
    if (config_.normalize) {
        Normalize(result.embedding);
        result.normalized = true;
    }
    
    stats_.totalEmbeddings++;
    stats_.totalTokens += result.tokenCount;
    return result;
}

std::vector<EmbeddingResult> EmbeddingServer::EmbedTexts(const std::vector<std::string>& texts) {
    std::vector<EmbeddingResult> results;
    for (const auto& text : texts) {
        results.push_back(EmbedText(text));
    }
    return results;
}

float EmbeddingServer::CosineSimilarity(const EmbeddingResult& a, const EmbeddingResult& b) {
    float dot = 0, normA = 0, normB = 0;
    size_t dim = std::min(a.embedding.size(), b.embedding.size());
    for (size_t i = 0; i < dim; ++i) {
        dot += a.embedding[i] * b.embedding[i];
        normA += a.embedding[i] * a.embedding[i];
        normB += b.embedding[i] * b.embedding[i];
    }
    return dot / (std::sqrt(normA) * std::sqrt(normB) + 1e-10f);
}

float EmbeddingServer::DotProduct(const EmbeddingResult& a, const EmbeddingResult& b) {
    float dot = 0;
    size_t dim = std::min(a.embedding.size(), b.embedding.size());
    for (size_t i = 0; i < dim; ++i) dot += a.embedding[i] * b.embedding[i];
    return dot;
}

void EmbeddingServer::Normalize(std::vector<float>& vec) {
    float norm = std::sqrt(std::inner_product(vec.begin(), vec.end(), vec.begin(), 0.0f));
    if (norm > 0) {
        for (auto& v : vec) v /= norm;
    }
}

} // namespace Sovereign

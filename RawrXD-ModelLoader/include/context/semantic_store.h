#pragma once
#include <string>
#include <vector>
#include <optional>

namespace RawrXD {
namespace Context {

struct EmbeddingItem {
    std::string id;        // file:line or custom key
    std::string text;      // snippet
    std::vector<float> vec;
};

struct SearchResult {
    std::string id;
    std::string text;
    float score = 0.0f; // cosine similarity
};

class SemanticStore {
public:
    // Add or update item
    void upsert(const EmbeddingItem& item);
    // Remove item
    bool remove(const std::string& id);
    // Search by query embedding
    std::vector<SearchResult> search(const std::vector<float>& query, size_t top_k = 5) const;
    // Access
    const std::vector<EmbeddingItem>& items() const { return m_items; }

private:
    std::vector<EmbeddingItem> m_items;
};

// Utility
float cosine(const std::vector<float>& a, const std::vector<float>& b);

} // namespace Context
} // namespace RawrXD

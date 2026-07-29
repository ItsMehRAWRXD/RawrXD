<<<<<<< HEAD
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace RawrXD {
namespace Context {

struct EmbeddingItem {
    std::string id;
    std::string text;
    std::vector<float> vec;
};

struct SearchResult {
    std::string id;
    std::string text;
    float score{0.0f};
};

class SemanticStore {
public:
    void upsert(const EmbeddingItem& item);
    bool remove(const std::string& id);
    std::vector<SearchResult> search(const std::vector<float>& query, size_t top_k = 5) const;

private:
    std::vector<EmbeddingItem> m_items;
};

float cosine(const std::vector<float>& a, const std::vector<float>& b);

} // namespace Context
} // namespace RawrXD
=======
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace RawrXD {
namespace Context {

struct EmbeddingItem {
    std::string id;
    std::string text;
    std::vector<float> vec;
};

struct SearchResult {
    std::string id;
    std::string text;
    float score{0.0f};
};

class SemanticStore {
public:
    void upsert(const EmbeddingItem& item);
    bool remove(const std::string& id);
    std::vector<SearchResult> search(const std::vector<float>& query, size_t top_k = 5) const;

private:
    std::vector<EmbeddingItem> m_items;
};

float cosine(const std::vector<float>& a, const std::vector<float>& b);

} // namespace Context
} // namespace RawrXD
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

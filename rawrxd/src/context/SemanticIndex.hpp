#pragma once
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd::context {

// ───────────────────────────────────────────────────────────────
// Semantic document entry
// ───────────────────────────────────────────────────────────────
struct SemanticDocument {
    uint64_t id = 0;
    std::string source_path;
    std::string content;
    std::vector<float> embedding;
    std::vector<std::string> tags;
    std::chrono::steady_clock::time_point indexed_at;
};

struct SemanticMatch {
    uint64_t doc_id = 0;
    float similarity = 0.0f;
    std::string source_path;
    std::string snippet;
};

// ───────────────────────────────────────────────────────────────
// Semantic index — vector-based semantic search over context
// ───────────────────────────────────────────────────────────────
class SemanticIndex {
public:
    SemanticIndex();
    ~SemanticIndex();

    // Lifecycle
    bool Initialize(size_t embedding_dim);
    void Shutdown();
    bool IsInitialized() const;

    // Indexing
    uint64_t AddDocument(const SemanticDocument& doc);
    bool RemoveDocument(uint64_t doc_id);
    bool UpdateDocument(uint64_t doc_id, const SemanticDocument& doc);
    void ClearIndex();

    // Search
    std::vector<SemanticMatch> Search(const std::vector<float>& query_embedding, size_t top_k = 5) const;
    std::vector<SemanticMatch> SearchByText(const std::string& query, size_t top_k = 5) const;

    // Query
    std::optional<SemanticDocument> GetDocument(uint64_t doc_id) const;
    size_t GetDocumentCount() const;
    std::vector<SemanticDocument> GetDocumentsByTag(const std::string& tag) const;

    // Persistence
    bool SaveToFile(const std::string& path) const;
    bool LoadFromFile(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd::context

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd {

// Forward declarations for FAISS/HNSW abstraction
namespace index {
    class VectorIndex;
    class CodeEmbedder;
}

/**
 * @brief Scored code snippet result from semantic search
 */
struct ScoredSnippet {
    std::string code;
    std::string file_path;
    int line_number;
    float similarity_score;
    
    bool operator>(const ScoredSnippet& other) const {
        return similarity_score > other.similarity_score;
    }
};

/**
 * @brief Configuration for semantic index behavior
 */
struct SemanticIndexConfig {
    int vector_dimension = 384;           // Embedding dimension (e.g., all-MiniLM-L6-v2)
    int index_nlist = 100;                // IVF clusters for quantization
    int nprobe = 4;                       // Default clusters to search
    float min_score_threshold = 0.7f;     // Minimum similarity for results
    size_t max_memory_mb = 512;         // Hard memory limit
    bool use_quantization = true;         // Enable IVFPQ for memory efficiency
    std::string index_type = "IVF";       // "IVF", "HNSW", or "FLAT"
};

/**
 * @brief Semantic code search index for intent-driven suggestions
 * 
 * Phase 17: Advanced Intelligence - Workstream 1
 * Provides vector-based semantic search over codebase
 */
class SemanticCodeIndex {
public:
    explicit SemanticCodeIndex(const SemanticIndexConfig& config = {});
    ~SemanticCodeIndex();
    
    // Disable copy, enable move
    SemanticCodeIndex(const SemanticCodeIndex&) = delete;
    SemanticCodeIndex& operator=(const SemanticCodeIndex&) = delete;
    SemanticCodeIndex(SemanticCodeIndex&&) noexcept;
    SemanticCodeIndex& operator=(SemanticCodeIndex&&) noexcept;

    /**
     * @brief Initialize the index (load model, allocate resources)
     * @return true on success, false on failure
     */
    bool initialize();
    
    /**
     * @brief Check if index is ready for queries
     */
    bool is_initialized() const;
    
    /**
     * @brief Check if IVFPQ index is trained (FAISS only)
     * @return true if trained and ready for search, false otherwise
     */
    bool is_trained() const;
    
    /**
     * @brief Get number of vectors waiting for training (FAISS only)
     */
    size_t training_buffer_size() const;
    
    /**
     * @brief Add a code snippet to the index
     * @param snippet The code text
     * @param metadata File path, line number, etc.
     * @return unique ID for the indexed snippet
     */
    int64_t add_snippet(const std::string& snippet, const std::string& metadata);
    
    /**
     * @brief Perform semantic search with natural language query
     * @param intent_query Natural language intent (e.g., "async file I/O patterns")
     * @param top_k Number of results to return
     * @param min_score Minimum similarity threshold (overrides config)
     * @return Vector of scored snippets, sorted by relevance
     */
    std::vector<ScoredSnippet> semantic_search(
        const std::string& intent_query,
        int top_k = 5,
        float min_score = -1.0f
    );
    
    /**
     * @brief Search with latency budget for real-time autocomplete
     * @param query The search query
     * @param budget_ms Maximum allowed latency
     * @param top_k Number of results
     * @return Results within budget, may be empty if timeout
     */
    std::vector<ScoredSnippet> search_with_budget(
        const std::string& query,
        int budget_ms = 10,
        int top_k = 5
    );
    
    /**
     * @brief Remove a snippet from the index
     * @param snippet_id ID returned by add_snippet
     * @return true if removed, false if not found
     */
    bool remove_snippet(int64_t snippet_id);
    
    /**
     * @brief Get current memory usage in bytes
     */
    size_t memory_usage() const;
    
    /**
     * @brief Get number of indexed snippets
     */
    size_t snippet_count() const;
    
    /**
     * @brief Persist index to disk
     * @param path Directory path for index files
     * @return true on success
     */
    bool save(const std::string& path);
    
    /**
     * @brief Load index from disk
     * @param path Directory path for index files
     * @return true on success
     */
    bool load(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    SemanticIndexConfig m_config;
    bool m_initialized;
};

} // namespace rawrxd

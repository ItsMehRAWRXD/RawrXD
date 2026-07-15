#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>

// Phase 17: Semantic Vector Search
// Supports both FAISS (if available) and HNSW fallback

namespace RawrXD {
namespace Intelligence {

// Forward declarations for implementation
#ifdef USE_FAISS
namespace faiss { class Index; }
#else
namespace hnsw { template<typename T> class HierarchicalNSW; }
#endif

struct CodeSnippet {
    std::string id;
    std::string content;
    std::string language;
    std::string file_path;
    int line_start;
    int line_end;
    std::vector<float> embedding;
};

struct ScoredSnippet {
    CodeSnippet snippet;
    float score;
    std::chrono::microseconds query_time;
};

enum class QueryType {
    FAST_PREFIX,      // Route to Trie (Tier 1)
    SEMANTIC,         // Vector search (Tier 2)
    CONTEXT_AWARE     // AST + Vector (Tier 3)
};

// Query classifier for routing decisions
class QueryClassifier {
public:
    static QueryType classify(const std::string& input);
    
private:
    static bool is_prefix_only(const std::string& input);
    static bool contains_natural_language(const std::string& input);
    static bool requires_context(const std::string& input);
};

// Semantic code index with memory-conscious design
class SemanticCodeIndex {
public:
    SemanticCodeIndex();
    ~SemanticCodeIndex();
    
    // Disable copy/move
    SemanticCodeIndex(const SemanticCodeIndex&) = delete;
    SemanticCodeIndex& operator=(const SemanticCodeIndex&) = delete;
    
    // Index management
    bool initialize(int dimension = 384, size_t max_memory_mb = 512);
    void shutdown();
    
    // Add/remove snippets
    bool add_snippet(const CodeSnippet& snippet);
    bool remove_snippet(const std::string& id);
    
    // Search with latency budget
    std::vector<ScoredSnippet> semantic_search(
        const std::string& intent_query,
        int top_k = 5,
        float min_score = 0.7f,
        std::chrono::milliseconds latency_budget = std::chrono::milliseconds(10)
    );
    
    // Memory management
    size_t memory_usage_mb() const;
    bool is_memory_mapped() const;
    
    // Statistics
    struct Stats {
        size_t total_snippets;
        size_t index_size_mb;
        float avg_query_time_ms;
        float p95_query_time_ms;
        size_t cache_hits;
        size_t cache_misses;
    };
    Stats get_stats() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Embedding generation (placeholder for CodeBERT/ONNX)
    std::vector<float> generate_embedding(const std::string& text);
    
    // Adaptive query strategy
    std::vector<ScoredSnippet> query_with_latency_budget(
        const std::string& query,
        std::chrono::milliseconds budget
    );
};

// Hybrid query router
class HybridQueryRouter {
public:
    HybridQueryRouter();
    ~HybridQueryRouter();
    
    void initialize(
        class SymbolIndex* trie_index,
        SemanticCodeIndex* semantic_index
    );
    
    // Main entry point for autocomplete
    std::vector<std::string> complete(
        const std::string& input,
        const std::string& file_context,
        int max_results = 10
    );
    
private:
    SymbolIndex* m_trie_index;
    SemanticCodeIndex* m_semantic_index;
};

} // namespace Intelligence
} // namespace RawrXD

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <variant>
#include <functional>  // Phase 17D.2: For telemetry callback

// Forward declarations
namespace rawrxd {
    class SemanticCodeIndex;
    class ASTContextProvider;
    struct ScoredSnippet;
    struct SymbolContext;
}

namespace rawrxd {

/**
 * @brief Query classification for tiered autocomplete
 */
enum class QueryType {
    FAST_PREFIX,      // Tier 1: Trie only (<3ms)
    SEMANTIC,         // Tier 2: Vector search (<10ms)
    CONTEXT_AWARE     // Tier 3: AST + Semantic (<50ms)
};

/**
 * @brief Unified completion result
 */
struct UnifiedCompletion {
    std::string text;
    std::string label;
    std::string detail;
    float score;
    QueryType source;
    std::string file_path;
    int line_number;
};

/**
 * @brief Cursor context for intelligent routing
 */
struct CursorContext {
    std::string file_path;
    int line;
    int column;
    std::string current_word;
    std::string line_prefix;
    bool is_after_dot;      // e.g., "obj."
    bool is_after_arrow;    // e.g., "obj->"
    bool is_type_context;   // e.g., after "class " or "int "
};

/**
 * @brief Configuration for unified autocomplete
 */
struct UnifiedAutocompleteConfig {
    // Latency budgets (ms)
    int fast_prefix_budget = 3;
    int semantic_budget = 10;
    int context_aware_budget = 50;
    
    // Thresholds
    float semantic_min_score = 0.7f;
    int max_completions = 10;
    
    // Feature flags
    bool enable_semantic = true;
    bool enable_ast = true;
    bool enable_trie = true;
    
    // Phase 17C.4: Model path for CodeEmbedder
    std::string model_path;  // Path to ONNX model (e.g., "models/all-MiniLM-L6-v2.onnx")
};

/**
 * @brief Unified autocomplete engine - Phase 17 Integration
 * 
 * Combines Tier 1 (Trie), Tier 2 (Semantic), and Tier 3 (AST) completion sources
 * into a single intelligent pipeline with adaptive query routing.
 */
class UnifiedAutocompleteEngine {
public:
    explicit UnifiedAutocompleteEngine(const UnifiedAutocompleteConfig& config = {});
    ~UnifiedAutocompleteEngine();
    
    // Disable copy, enable move
    UnifiedAutocompleteEngine(const UnifiedAutocompleteEngine&) = delete;
    UnifiedAutocompleteEngine& operator=(const UnifiedAutocompleteEngine&) = delete;
    UnifiedAutocompleteEngine(UnifiedAutocompleteEngine&&) noexcept;
    UnifiedAutocompleteEngine& operator=(UnifiedAutocompleteEngine&&) noexcept;

    /**
     * @brief Initialize all completion backends
     */
    bool initialize();
    
    /**
     * @brief Get completions at cursor position
     * @param cursor Current cursor context
     * @return Vector of ranked completions
     */
    std::vector<UnifiedCompletion> get_completions(const CursorContext& cursor);
    
    /**
     * @brief Classify query to determine optimal completion strategy
     */
    QueryType classify_query(const CursorContext& cursor) const;
    
    /**
     * @brief Add code snippet to semantic index
     */
    void index_code_snippet(const std::string& code, const std::string& metadata);
    
    /**
     * @brief Parse file for AST-based completions
     */
    void parse_file_for_ast(const std::string& file_path, const std::string& content);
    
    /**
     * @brief Check if engine is ready
     */
    bool is_ready() const;
    
    /**
     * @brief Get last query latency (ms)
     */
    float get_last_latency_ms() const;
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        uint64_t total_queries = 0;
        uint64_t trie_hits = 0;
        uint64_t semantic_hits = 0;
        uint64_t ast_hits = 0;
        uint64_t hybrid_fusion_count = 0;  // Phase 17D.2: Both paths triggered
        uint64_t timeout_count = 0;         // Phase 17D.2: Semantic search timeouts
        float avg_latency_ms = 0.0f;
        float avg_trie_latency_ms = 0.0f;   // Phase 17D.2: Trie-only latency
        float avg_semantic_latency_ms = 0.0f; // Phase 17D.2: Semantic-only latency
        float cache_hit_rate = 0.0f;        // Phase 17D.2: Embedding cache efficiency
    };
    Stats get_stats() const;
    
    /**
     * @brief Phase 17D.2: Export telemetry to external system
     * @param callback Function to receive telemetry data
     */
    using TelemetryCallback = std::function<void(const Stats&)>;
    void set_telemetry_callback(TelemetryCallback callback);
    void flush_telemetry();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    UnifiedAutocompleteConfig m_config;
    
    // Tier-specific completion methods
    std::vector<UnifiedCompletion> get_trie_completions(const CursorContext& cursor);
    std::vector<UnifiedCompletion> get_semantic_completions(const CursorContext& cursor);
    std::vector<UnifiedCompletion> get_ast_completions(const CursorContext& cursor);
    
    // Phase 17C.4: Hybrid retrieval methods
    std::vector<UnifiedCompletion> fuse_results(
        const std::vector<UnifiedCompletion>& trie_results,
        const std::vector<UnifiedCompletion>& semantic_results);
    std::vector<UnifiedCompletion> merge_with_ast(
        const std::vector<UnifiedCompletion>& existing,
        const std::vector<UnifiedCompletion>& ast_results);
    
    // Legacy merge (deprecated in favor of fuse_results)
    std::vector<UnifiedCompletion> merge_results(
        std::vector<UnifiedCompletion>&& trie_results,
        std::vector<UnifiedCompletion>&& semantic_results,
        std::vector<UnifiedCompletion>&& ast_results
    );
};

} // namespace rawrxd
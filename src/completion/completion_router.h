#pragma once

#include <memory>
#include <vector>
#include <string>
#include <string_view>
#include <chrono>

// Forward declarations
namespace rawrxd {
    class SemanticCodeIndex;
    struct ScoredSnippet;
}

namespace RawrXD {

// Forward declarations
class KeywordHashTable;
class AdaptiveFusionEngine;  // Phase 18B: Self-tuning weights

/**
 * @brief Editor context for completion requests
 * 
 * Captures the current state of the editor to provide
 * context-aware suggestions.
 */
struct EditorContext {
    std::string file_path;
    int line_number = 0;
    int column = 0;
    std::string current_line_prefix;
    std::string current_line_suffix;
    std::string surrounding_context;  // +/- 3 lines
    std::string language_id;
    
    // Timing constraints
    int max_latency_ms = 10;  // Hard deadline for autocomplete
};

/**
 * @brief Completion suggestion with metadata
 */
struct CompletionSuggestion {
    std::string text;
    std::string display_text;
    std::string detail;           // Type info, signature, etc.
    std::string documentation;
    float relevance_score = 0.0f;
    enum class Source {
        TRIE_PREFIX,      // Legacy keyword matching
        SEMANTIC_INTENT,  // Vector similarity
        LSP_SYMBOLS,      // Language server
        HYBRID_FUSION     // Combined ranking
    } source = Source::TRIE_PREFIX;
    
    // For semantic results
    std::string matched_intent;
    float semantic_similarity = 0.0f;
};

/**
 * @brief CompletionRouter - Mediator between UI and search backends
 * 
 * Phase 17C: Hybrid completion engine that routes requests between:
 * - Legacy Trie-based prefix matching (fast, deterministic)
 * - SemanticCodeIndex vector search (intent-aware)
 * - LSP symbol providers (language-aware)
 * 
 * Phase 18B: Now uses AdaptiveFusionEngine for self-tuning weights
 * 
 * Design goals:
 * - Thin mediator (minimal latency overhead)
 * - Configurable fusion weights (now adaptive)
 * - Graceful degradation (fallback chains)
 * - Thread-safe for IDE event loop
 */
class CompletionRouter {
public:
    /**
     * @brief Fusion weights for hybrid ranking
     * 
     * DEPRECATED: Use AdaptiveFusionEngine for dynamic weights
     * These are used as initial values only.
     */
    struct FusionWeights {
        float trie_weight = 0.4f;
        float semantic_weight = 0.6f;
        float lsp_weight = 0.0f;  // Optional LSP integration
    };
    
    /**
     * @brief Routing mode for A/B testing and gradual rollout
     */
    enum class Mode {
        TRIE_ONLY,           // Legacy behavior (baseline)
        SEMANTIC_ONLY,       // Pure vector search
        HYBRID_FUSION,       // Weighted combination (default, now adaptive)
        SMART_FALLBACK       // Auto-select based on query type
    };

    CompletionRouter();
    ~CompletionRouter();
    
    // Disable copy/move (holds unique_ptrs)
    CompletionRouter(const CompletionRouter&) = delete;
    CompletionRouter& operator=(const CompletionRouter&) = delete;
    CompletionRouter(CompletionRouter&&) = default;
    CompletionRouter& operator=(CompletionRouter&&) = default;

    /**
     * @brief Initialize the router with dependencies
     * 
     * @param semantic_index Shared pointer to semantic index (may be null)
     * @param trie Unique pointer to legacy trie (required)
     * @return true if initialization successful
     */
    bool initialize(
        std::shared_ptr<rawrxd::SemanticCodeIndex> semantic_index,
        std::unique_ptr<KeywordHashTable> trie
    );
    
    /**
     * @brief Check if router is ready for requests
     */
    bool is_initialized() const { return m_initialized; }
    
    /**
     * @brief Check if semantic index is available
     */
    bool has_semantic_index() const { return m_semantic_index != nullptr; }

    /**
     * @brief Configure fusion weights (initial values only)
     * 
     * Phase 18B: These are now initial values. Actual weights
     * come from AdaptiveFusionEngine.
     */
    void set_weights(const FusionWeights& weights);
    FusionWeights get_weights() const { return m_weights; }
    
    /**
     * @brief Set routing mode
     */
    void set_mode(Mode mode) { m_mode = mode; }
    Mode get_mode() const { return m_mode; }

    /**
     * @brief Main API: Get completion suggestions
     * 
     * Hot-path method optimized for sub-10ms latency.
     * 
     * @param ctx Editor context (position, surrounding code)
     * @param query User's current input/query
     * @param max_results Maximum suggestions to return
     * @return Vector of ranked suggestions
     */
    std::vector<CompletionSuggestion> get_suggestions(
        const EditorContext& ctx,
        std::string_view query,
        int max_results = 10
    );
    
    /**
     * @brief Budget-constrained search for real-time autocomplete
     * 
     * Guarantees return within budget_ms, potentially with fewer results.
     * 
     * @param ctx Editor context
     * @param query User input
     * @param budget_ms Maximum allowed latency
     * @param max_results Target result count
     * @return Suggestions within budget (may be empty)
     */
    std::vector<CompletionSuggestion> get_suggestions_with_budget(
        const EditorContext& ctx,
        std::string_view query,
        int budget_ms,
        int max_results = 10
    );

    /**
     * @brief Report feedback for a suggestion
     * 
     * Phase 18B: Triggers AdaptiveFusionEngine learning
     * 
     * @param suggestion The accepted/rejected suggestion
     * @param accepted true if user accepted, false if dismissed
     */
    void report_feedback(const CompletionSuggestion& suggestion, bool accepted);

    /**
     * @brief Get performance statistics
     */
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t semantic_requests = 0;
        uint64_t trie_requests = 0;
        uint64_t hybrid_requests = 0;
        double avg_latency_ms = 0.0;
        double p95_latency_ms = 0.0;
        uint64_t budget_exceeded_count = 0;
        
        // Phase 18B: Adaptive learning stats
        float current_alpha = 0.75f;
        bool is_converged = false;
    };
    Stats get_stats() const;
    void reset_stats() { m_stats = Stats{}; }

private:
    // Backend implementations
    std::vector<CompletionSuggestion> query_trie(
        std::string_view query,
        int max_results
    );
    
    std::vector<CompletionSuggestion> query_semantic(
        const EditorContext& ctx,
        std::string_view query,
        int max_results
    );
    
    std::vector<CompletionSuggestion> fuse_results(
        const std::vector<CompletionSuggestion>& trie_results,
        const std::vector<CompletionSuggestion>& semantic_results,
        int max_results
    );
    
    // Determine if query is suitable for semantic search
    bool should_use_semantic(std::string_view query) const;
    
    // Get current alpha from AdaptiveFusionEngine
    float get_current_alpha() const;

private:
    // Dependencies
    std::shared_ptr<rawrxd::SemanticCodeIndex> m_semantic_index;
    std::unique_ptr<KeywordHashTable> m_trie;
    
    // Configuration
    FusionWeights m_weights{0.4f, 0.6f, 0.0f};
    Mode m_mode = Mode::HYBRID_FUSION;
    
    // State
    bool m_initialized = false;
    
    // Statistics
    mutable Stats m_stats;
    mutable std::vector<double> m_latency_history;  // For p95 calc
};

} // namespace RawrXD

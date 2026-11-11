#include "completion_router.h"
#include "AdaptiveFusionEngine.h"

#include "../semantic_index/SemanticCodeIndex.h"
#include "../KeywordHashTable.h"

#include <algorithm>
#include <chrono>
#include <cmath>

namespace RawrXD {

// Anonymous namespace for internal helpers
namespace {
    
    // Normalize scores to 0-1 range using min-max scaling
    void normalize_scores(std::vector<CompletionSuggestion>& suggestions) {
        if (suggestions.empty()) return;
        
        float min_score = suggestions.back().relevance_score;
        float max_score = suggestions.front().relevance_score;
        
        if (max_score > min_score) {
            float range = max_score - min_score;
            for (auto& s : suggestions) {
                s.relevance_score = (s.relevance_score - min_score) / range;
            }
        } else {
            // All same score - set to 0.5
            for (auto& s : suggestions) {
                s.relevance_score = 0.5f;
            }
        }
    }
    
    // Deduplicate suggestions by text content
    void deduplicate(std::vector<CompletionSuggestion>& suggestions) {
        auto it = std::unique(suggestions.begin(), suggestions.end(),
            [](const CompletionSuggestion& a, const CompletionSuggestion& b) {
                return a.text == b.text;
            });
        suggestions.erase(it, suggestions.end());
    }
    
    // Calculate latency for statistics
    class LatencyTimer {
    public:
        LatencyTimer() : m_start(std::chrono::steady_clock::now()) {}
        
        double elapsed_ms() const {
            auto end = std::chrono::steady_clock::now();
            return std::chrono::duration<double, std::milli>(end - m_start).count();
        }
        
    private:
        std::chrono::steady_clock::time_point m_start;
    };
    
} // anonymous namespace

CompletionRouter::CompletionRouter() = default;
CompletionRouter::~CompletionRouter() = default;

bool CompletionRouter::initialize(
    std::shared_ptr<rawrxd::SemanticCodeIndex> semantic_index,
    std::unique_ptr<KeywordHashTable> trie) {
    
    if (!trie) {
        return false;  // Trie is required (fallback)
    }
    
    m_semantic_index = std::move(semantic_index);
    m_trie = std::move(trie);
    m_initialized = true;
    
    return true;
}

void CompletionRouter::set_weights(const FusionWeights& weights) {
    // Phase 18B: These are now initial values only
    // Actual weights come from AdaptiveFusionEngine
    m_weights = weights;
    
    // Update AdaptiveFusionEngine initial alpha
    AdaptiveFusionEngine::instance().reset();
}

float CompletionRouter::get_current_alpha() const {
    // Phase 18B: Get dynamic alpha from AdaptiveFusionEngine
    // Alpha = 0.0 means Pure Semantic, 1.0 means Pure Trie
    return AdaptiveFusionEngine::instance().get_alpha();
}

std::vector<CompletionSuggestion> CompletionRouter::get_suggestions(
    const EditorContext& ctx,
    std::string_view query,
    int max_results) {
    
    if (!m_initialized) {
        return {};
    }
    
    LatencyTimer timer;
    m_stats.total_requests++;
    
    std::vector<CompletionSuggestion> results;
    
    switch (m_mode) {
        case Mode::TRIE_ONLY:
            results = query_trie(query, max_results);
            m_stats.trie_requests++;
            break;
            
        case Mode::SEMANTIC_ONLY:
            if (m_semantic_index) {
                results = query_semantic(ctx, query, max_results);
                m_stats.semantic_requests++;
            } else {
                // Fallback to trie if semantic unavailable
                results = query_trie(query, max_results);
                m_stats.trie_requests++;
            }
            break;
            
        case Mode::HYBRID_FUSION:
            if (m_semantic_index && should_use_semantic(query)) {
                auto trie_results = query_trie(query, max_results / 2);
                auto semantic_results = query_semantic(ctx, query, max_results / 2);
                results = fuse_results(trie_results, semantic_results, max_results);
                m_stats.hybrid_requests++;
            } else {
                results = query_trie(query, max_results);
                m_stats.trie_requests++;
            }
            break;
            
        case Mode::SMART_FALLBACK:
            // Auto-select based on query characteristics
            if (query.length() > 3 && m_semantic_index) {
                // Longer queries benefit from semantic search
                auto trie_results = query_trie(query, max_results / 2);
                auto semantic_results = query_semantic(ctx, query, max_results / 2);
                results = fuse_results(trie_results, semantic_results, max_results);
                m_stats.hybrid_requests++;
            } else {
                // Short queries: fast trie lookup
                results = query_trie(query, max_results);
                m_stats.trie_requests++;
            }
            break;
    }
    
    // Update latency statistics
    double latency = timer.elapsed_ms();
    m_stats.avg_latency_ms = (m_stats.avg_latency_ms * (m_stats.total_requests - 1) + latency) 
                               / m_stats.total_requests;
    m_latency_history.push_back(latency);
    
    // Keep only last 1000 samples for p95 calculation
    if (m_latency_history.size() > 1000) {
        m_latency_history.erase(m_latency_history.begin());
    }
    
    // Calculate p95
    if (!m_latency_history.empty()) {
        auto sorted = m_latency_history;
        std::sort(sorted.begin(), sorted.end());
        size_t p95_idx = static_cast<size_t>(sorted.size() * 0.95);
        m_stats.p95_latency_ms = sorted[p95_idx];
    }
    
    // Phase 18B: Update stats with current alpha
    m_stats.current_alpha = get_current_alpha();
    auto af_stats = AdaptiveFusionEngine::instance().get_stats();
    m_stats.is_converged = af_stats.is_converged;
    
    return results;
}

std::vector<CompletionSuggestion> CompletionRouter::get_suggestions_with_budget(
    const EditorContext& ctx,
    std::string_view query,
    int budget_ms,
    int max_results) {
    
    if (!m_initialized) {
        return {};
    }
    
    auto start = std::chrono::steady_clock::now();
    
    // Start with trie results (fastest)
    auto results = query_trie(query, max_results);
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    // If we have time budget remaining, try semantic search
    if (elapsed_ms < budget_ms / 2 && m_semantic_index && should_use_semantic(query)) {
        int remaining_budget = budget_ms - static_cast<int>(elapsed_ms);
        
        auto semantic_results = query_semantic(ctx, query, max_results / 2);
        
        auto semantic_elapsed = std::chrono::steady_clock::now() - start;
        auto semantic_elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            semantic_elapsed).count();
        
        if (semantic_elapsed_ms < budget_ms) {
            results = fuse_results(results, semantic_results, max_results);
        } else {
            m_stats.budget_exceeded_count++;
        }
    }
    
    return results;
}

void CompletionRouter::report_feedback(const CompletionSuggestion& suggestion, bool accepted) {
    // Phase 18B: Update AdaptiveFusionEngine based on user feedback
    // Convert source to string
    std::string source_str = "unknown";
    switch (suggestion.source) {
        case CompletionSuggestion::Source::TRIE_PREFIX:
            source_str = "trie";
            break;
        case CompletionSuggestion::Source::SEMANTIC_INTENT:
            source_str = "semantic";
            break;
        case CompletionSuggestion::Source::HYBRID_FUSION:
            source_str = "hybrid";
            break;
        default:
            break;
    }
    
    // Calculate reward for AdaptiveFusionEngine
    float reward = accepted ? 1.0f : 0.0f;
    
    // Adjust reward based on source
    float adjusted_reward = reward;
    if (source_str == "semantic") {
        adjusted_reward = 1.0f - reward;  // Invert: accept semantic = 0.0 alpha
    } else if (source_str == "trie") {
        adjusted_reward = reward;  // Keep as-is
    } else {
        adjusted_reward = 0.5f;  // Neutral for hybrid/unknown
    }
    
    AdaptiveFusionEngine::instance().update_weights(adjusted_reward);
}

std::vector<CompletionSuggestion> CompletionRouter::query_trie(
    std::string_view query,
    int max_results) {
    
    std::vector<CompletionSuggestion> results;
    
    if (!m_trie || query.empty()) {
        return results;
    }
    
    // Query the legacy Trie
    // Note: KeywordHashTable doesn't have prefix search, so we return empty results
    // This is a placeholder - the actual implementation would need a proper Trie structure
    // with prefix matching capability
    
    return results;
}

std::vector<CompletionSuggestion> CompletionRouter::query_semantic(
    const EditorContext& ctx,
    std::string_view query,
    int max_results) {
    
    std::vector<CompletionSuggestion> results;
    
    if (!m_semantic_index || query.empty()) {
        return results;
    }
    
    // Build intent query from context + current input
    std::string intent_query;
    if (!ctx.surrounding_context.empty()) {
        intent_query = ctx.surrounding_context + " " + std::string(query);
    } else {
        intent_query = query;
    }
    
    // Query semantic index
    auto semantic_results = m_semantic_index->semantic_search(
        intent_query,
        max_results,
        0.5f  // Minimum similarity threshold
    );
    
    for (const auto& snippet : semantic_results) {
        CompletionSuggestion suggestion;
        suggestion.text = snippet.code;
        suggestion.display_text = snippet.code.substr(0, 50);  // Truncate for display
        suggestion.detail = snippet.file_path + ":" + std::to_string(snippet.line_number);
        suggestion.relevance_score = snippet.similarity_score;
        suggestion.semantic_similarity = snippet.similarity_score;
        suggestion.source = CompletionSuggestion::Source::SEMANTIC_INTENT;
        results.push_back(std::move(suggestion));
    }
    
    return results;
}

std::vector<CompletionSuggestion> CompletionRouter::fuse_results(
    const std::vector<CompletionSuggestion>& trie_results,
    const std::vector<CompletionSuggestion>& semantic_results,
    int max_results) {
    
    std::vector<CompletionSuggestion> fused;
    fused.reserve(trie_results.size() + semantic_results.size());
    
    // Phase 18B: Get dynamic alpha from AdaptiveFusionEngine
    float alpha = get_current_alpha();  // 0.0 = Pure Semantic, 1.0 = Pure Trie
    float trie_weight = alpha;
    float semantic_weight = 1.0f - alpha;
    
    // Normalize scores within each result set
    auto trie_normalized = trie_results;
    auto semantic_normalized = semantic_results;
    
    normalize_scores(trie_normalized);
    normalize_scores(semantic_normalized);
    
    // Apply dynamic weights and combine
    for (auto& s : trie_normalized) {
        s.relevance_score *= trie_weight;
        s.source = CompletionSuggestion::Source::HYBRID_FUSION;
        fused.push_back(s);
    }
    
    for (auto& s : semantic_normalized) {
        s.relevance_score *= semantic_weight;
        s.source = CompletionSuggestion::Source::HYBRID_FUSION;
        fused.push_back(s);
    }
    
    // Sort by fused relevance score (descending)
    std::sort(fused.begin(), fused.end(),
        [](const CompletionSuggestion& a, const CompletionSuggestion& b) {
            return a.relevance_score > b.relevance_score;
        });
    
    // Deduplicate by text content
    deduplicate(fused);
    
    // Trim to max_results
    if (fused.size() > static_cast<size_t>(max_results)) {
        fused.resize(max_results);
    }
    
    return fused;
}

bool CompletionRouter::should_use_semantic(std::string_view query) const {
    // Heuristics for when semantic search is beneficial
    
    // 1. Query length - longer queries have more semantic content
    if (query.length() < 3) {
        return false;  // Too short for meaningful semantic search
    }
    
    // 2. Check for natural language patterns (spaces, descriptive words)
    bool has_natural_language = query.find(' ') != std::string_view::npos;
    
    // 3. Check for camelCase/snake_case (likely symbol names - use trie)
    bool looks_like_symbol = 
        (query.find('_') != std::string_view::npos) ||
        std::any_of(query.begin(), query.end(), [](char c) {
            return c >= 'A' && c <= 'Z';  // Has uppercase (camelCase)
        });
    
    // Use semantic if it looks like natural language OR if it's a longer query
    return has_natural_language || (query.length() >= 5 && !looks_like_symbol);
}

CompletionRouter::Stats CompletionRouter::get_stats() const {
    // Phase 18B: Include adaptive learning stats
    Stats stats = m_stats;
    auto af_stats = AdaptiveFusionEngine::instance().get_stats();
    stats.current_alpha = af_stats.current_alpha;
    stats.is_converged = af_stats.is_converged;
    return stats;
}

} // namespace RawrXD

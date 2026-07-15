// Phase 17: Semantic Search Implementation
// Week 1 Prototype: HNSW-based with memory constraints

#include "rawrxd_semantic_search.h"
#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

// HNSW header-only library
#ifdef USE_HNSW
#include "hnswlib/hnswlib.h"
#endif

namespace RawrXD {
namespace Intelligence {

// QueryClassifier implementation
QueryType QueryClassifier::classify(const std::string& input) {
    if (is_prefix_only(input)) {
        return QueryType::FAST_PREFIX;
    }
    if (contains_natural_language(input)) {
        return QueryType::SEMANTIC;
    }
    return QueryType::CONTEXT_AWARE;
}

bool QueryClassifier::is_prefix_only(const std::string& input) {
    // Fast path: single word, no spaces, alphanumeric only
    if (input.empty() || input.length() > 50) return false;
    
    for (char c : input) {
        if (!std::isalnum(c) && c != '_' && c != ':') {
            return false;
        }
    }
    return true;
}

bool QueryClassifier::contains_natural_language(const std::string& input) {
    // Check for natural language patterns
    static const std::unordered_set<std::string> nl_keywords = {
        "find", "show", "get", "how", "what", "where", "why",
        "async", "pattern", "example", "implement", "create"
    };
    
    std::string lower_input = input;
    std::transform(lower_input.begin(), lower_input.end(), 
                   lower_input.begin(), ::tolower);
    
    for (const auto& keyword : nl_keywords) {
        if (lower_input.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool QueryClassifier::requires_context(const std::string& input) {
    // Check if query references current context
    return input.find("this") != std::string::npos ||
           input.find("current") != std::string::npos ||
           input.find("here") != std::string::npos;
}

// SemanticCodeIndex implementation
class SemanticCodeIndex::Impl {
public:
#ifdef USE_HNSW
    std::unique_ptr<hnswlib::HierarchicalNSW<float>> hnsw_index;
    std::unique_ptr<hnswlib::InnerProductSpace> space;
#endif
    
    std::unordered_map<size_t, CodeSnippet> id_to_snippet;
    std::unordered_map<std::string, size_t> content_to_id;
    
    int dimension = 384;
    size_t max_elements = 100000;
    size_t M = 16;  // HNSW parameter
    size_t ef_construction = 200;
    
    // Statistics
    Stats stats{};
    std::vector<float> query_times_ms;
    
    // Cache
    std::unordered_map<std::string, std::vector<ScoredSnippet>> query_cache;
    static constexpr size_t MAX_CACHE_SIZE = 1000;
};

SemanticCodeIndex::SemanticCodeIndex() 
    : m_impl(std::make_unique<Impl>()) {}

SemanticCodeIndex::~SemanticCodeIndex() = default;

bool SemanticCodeIndex::initialize(int dimension, size_t max_memory_mb) {
    m_impl->dimension = dimension;
    
#ifdef USE_HNSW
    // Calculate max elements based on memory budget
    // Each vector: dimension * 4 bytes + overhead
    size_t bytes_per_vector = dimension * sizeof(float) + 1024; // 1KB overhead
    m_impl->max_elements = (max_memory_mb * 1024 * 1024) / bytes_per_vector;
    
    m_impl->space = std::make_unique<hnswlib::InnerProductSpace>(dimension);
    m_impl->hnsw_index = std::make_unique<hnswlib::HierarchicalNSW<float>>(
        m_impl->space.get(),
        m_impl->max_elements,
        m_impl->M,
        m_impl->ef_construction
    );
    
    return true;
#else
    return false; // No backend available
#endif
}

void SemanticCodeIndex::shutdown() {
#ifdef USE_HNSW
    m_impl->hnsw_index.reset();
    m_impl->space.reset();
#endif
    m_impl->id_to_snippet.clear();
    m_impl->content_to_id.clear();
    m_impl->query_cache.clear();
}

bool SemanticCodeIndex::add_snippet(const CodeSnippet& snippet) {
    if (snippet.embedding.empty() || 
        snippet.embedding.size() != static_cast<size_t>(m_impl->dimension)) {
        return false;
    }
    
    // Check for duplicates
    auto it = m_impl->content_to_id.find(snippet.content);
    if (it != m_impl->content_to_id.end()) {
        return true; // Already exists
    }
    
    size_t id = m_impl->id_to_snippet.size();
    
#ifdef USE_HNSW
    if (m_impl->hnsw_index) {
        m_impl->hnsw_index->addPoint(
            snippet.embedding.data(),
            id,
            false  // not thread-safe, caller must synchronize
        );
    }
#endif
    
    m_impl->id_to_snippet[id] = snippet;
    m_impl->content_to_id[snippet.content] = id;
    m_impl->stats.total_snippets++;
    
    return true;
}

bool SemanticCodeIndex::remove_snippet(const std::string& id) {
    // HNSW doesn't support deletion, mark as invalid
    auto it = m_impl->content_to_id.find(id);
    if (it == m_impl->content_to_id.end()) {
        return false;
    }
    
    // Mark as deleted (soft delete)
    m_impl->id_to_snippet.erase(it->second);
    m_impl->content_to_id.erase(it);
    m_impl->stats.total_snippets--;
    
    return true;
}

std::vector<ScoredSnippet> SemanticCodeIndex::semantic_search(
    const std::string& intent_query,
    int top_k,
    float min_score,
    std::chrono::milliseconds latency_budget) {
    
    auto start = std::chrono::steady_clock::now();
    
    // Check cache
    auto cache_it = m_impl->query_cache.find(intent_query);
    if (cache_it != m_impl->query_cache.end()) {
        m_impl->stats.cache_hits++;
        return cache_it->second;
    }
    m_impl->stats.cache_misses++;
    
    // Generate embedding (placeholder - would use CodeBERT)
    auto query_embedding = generate_embedding(intent_query);
    
    std::vector<ScoredSnippet> results;
    
#ifdef USE_HNSW
    if (m_impl->hnsw_index) {
        // Adaptive ef parameter based on latency budget
        int ef = 16;  // default
        if (latency_budget > std::chrono::milliseconds(5)) {
            ef = 32;
        }
        if (latency_budget > std::chrono::milliseconds(8)) {
            ef = 64;
        }
        
        m_impl->hnsw_index->setEf(ef);
        
        auto knn = m_impl->hnsw_index->searchKnn(
            query_embedding.data(),
            top_k * 2  // Get extra for filtering
        );
        
        for (size_t i = 0; i < knn.first.size() && results.size() < static_cast<size_t>(top_k); ++i) {
            size_t id = knn.second[i];
            float dist = knn.first[i];
            float score = 1.0f / (1.0f + dist);  // Convert distance to similarity
            
            if (score >= min_score) {
                auto it = m_impl->id_to_snippet.find(id);
                if (it != m_impl->id_to_snippet.end()) {
                    auto elapsed = std::chrono::steady_clock::now() - start;
                    results.push_back({
                        it->second,
                        score,
                        std::chrono::duration_cast<std::chrono::microseconds>(elapsed)
                    });
                }
            }
        }
    }
#endif
    
    // Update statistics
    auto elapsed = std::chrono::steady_clock::now() - start;
    float elapsed_ms = std::chrono::duration<float, std::milli>(elapsed).count();
    m_impl->query_times_ms.push_back(elapsed_ms);
    
    // Keep only last 1000 query times for P95 calculation
    if (m_impl->query_times_ms.size() > 1000) {
        m_impl->query_times_ms.erase(m_impl->query_times_ms.begin());
    }
    
    // Cache results
    if (m_impl->query_cache.size() < Impl::MAX_CACHE_SIZE) {
        m_impl->query_cache[intent_query] = results;
    }
    
    return results;
}

size_t SemanticCodeIndex::memory_usage_mb() const {
    // Approximate memory usage
    size_t snippet_bytes = m_impl->stats.total_snippets * 
        (m_impl->dimension * sizeof(float) + 1024);
    return snippet_bytes / (1024 * 1024);
}

bool SemanticCodeIndex::is_memory_mapped() const {
    return false; // HNSW uses RAM, not memory-mapped files
}

SemanticCodeIndex::Stats SemanticCodeIndex::get_stats() const {
    Stats stats = m_impl->stats;
    stats.index_size_mb = memory_usage_mb();
    
    if (!m_impl->query_times_ms.empty()) {
        float sum = 0;
        for (float t : m_impl->query_times_ms) {
            sum += t;
        }
        stats.avg_query_time_ms = sum / m_impl->query_times_ms.size();
        
        // Calculate P95
        auto sorted = m_impl->query_times_ms;
        std::sort(sorted.begin(), sorted.end());
        size_t p95_idx = static_cast<size_t>(sorted.size() * 0.95);
        stats.p95_query_time_ms = sorted[p95_idx];
    }
    
    return stats;
}

std::vector<float> SemanticCodeIndex::generate_embedding(const std::string& text) {
    // Placeholder: In production, use CodeBERT via ONNX Runtime
    // For prototype, generate deterministic random embedding
    std::vector<float> embedding(m_impl->dimension);
    
    // Simple hash-based embedding for testing
    size_t hash = std::hash<std::string>{}(text);
    for (int i = 0; i < m_impl->dimension; ++i) {
        hash = hash * 31 + i;
        embedding[i] = static_cast<float>(hash % 1000) / 1000.0f;
    }
    
    // Normalize
    float norm = 0;
    for (float v : embedding) {
        norm += v * v;
    }
    norm = std::sqrt(norm);
    if (norm > 0) {
        for (auto& v : embedding) {
            v /= norm;
        }
    }
    
    return embedding;
}

// HybridQueryRouter implementation
HybridQueryRouter::HybridQueryRouter() = default;
HybridQueryRouter::~HybridQueryRouter() = default;

void HybridQueryRouter::initialize(
    class SymbolIndex* trie_index,
    SemanticCodeIndex* semantic_index) {
    m_trie_index = trie_index;
    m_semantic_index = semantic_index;
}

std::vector<std::string> HybridQueryRouter::complete(
    const std::string& input,
    const std::string& file_context,
    int max_results) {
    
    std::vector<std::string> results;
    
    // Classify query
    auto query_type = QueryClassifier::classify(input);
    
    switch (query_type) {
        case QueryType::FAST_PREFIX:
            // Route to Trie (Tier 1) - guaranteed < 3ms
            if (m_trie_index) {
                // Call Trie autocomplete
                // results = m_trie_index->findByName(input);
            }
            break;
            
        case QueryType::SEMANTIC:
            // Route to Semantic (Tier 2) - < 10ms
            if (m_semantic_index) {
                auto snippets = m_semantic_index->semantic_search(
                    input, max_results, 0.7f
                );
                for (const auto& s : snippets) {
                    results.push_back(s.snippet.content);
                }
            }
            break;
            
        case QueryType::CONTEXT_AWARE:
            // Route to AST + Semantic (Tier 3) - async
            // For now, fall back to semantic
            if (m_semantic_index) {
                auto snippets = m_semantic_index->semantic_search(
                    input, max_results, 0.7f
                );
                for (const auto& s : snippets) {
                    results.push_back(s.snippet.content);
                }
            }
            break;
    }
    
    return results;
}

} // namespace Intelligence
} // namespace RawrXD

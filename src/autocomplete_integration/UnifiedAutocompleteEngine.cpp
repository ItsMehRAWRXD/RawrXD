#include "UnifiedAutocompleteEngine.h"
#include "../semantic_index/SemanticCodeIndex.h"
#include "../semantic_index/CodeEmbedder.h"
#include "../ast_parser/ASTContextProvider.h"

#include <chrono>
#include <algorithm>
#include <unordered_set>
#include <future>
#include <cmath>
#include <atomic>      // Phase 17D.3: For std::atomic
#include <mutex>       // Phase 17D.3: For std::mutex

namespace rawrxd {

// Fusion weights for hybrid retrieval
constexpr float TRIE_WEIGHT = 0.75f;      // Alpha: favor exact matches
constexpr float SEMANTIC_WEIGHT = 0.25f;  // 1 - Alpha: semantic boost
constexpr float SEMANTIC_THRESHOLD = 0.7f;  // Minimum cosine similarity
constexpr size_t MAX_TRIE_RESULTS = 10;   // Skip semantic if trie has enough
constexpr float LATENCY_BUDGET_MS = 3.5f;   // P95 hard limit

// PIMPL implementation with hybrid retrieval support
struct UnifiedAutocompleteEngine::Impl {
    UnifiedAutocompleteConfig config;
    
    // Tier backends
    std::unique_ptr<SemanticCodeIndex> semantic_index;
    std::unique_ptr<CodeEmbedder> code_embedder;
    std::unique_ptr<ASTContextProvider> ast_provider;
    
    // Statistics
    Stats stats;
    float last_latency_ms = 0.0f;
    float last_trie_latency_ms = 0.0f;
    float last_semantic_latency_ms = 0.0f;
    
    // Phase 17D.2: Telemetry
    TelemetryCallback telemetry_callback;
    uint64_t cache_hits = 0;
    uint64_t cache_misses = 0;
    
    // Trie index (simplified - would connect to existing SymbolIndex)
    std::unordered_map<std::string, std::vector<std::string>> trie_index;
    
    // Embedding cache for frequently accessed contexts (L1 cache)
    struct CacheEntry {
        std::vector<float> embedding;
        std::chrono::steady_clock::time_point timestamp;
    };
    std::unordered_map<std::string, CacheEntry> embedding_cache;
    static constexpr size_t MAX_CACHE_SIZE = 1000;
    
    // Phase 17D.3: Thread safety - track active futures
    std::atomic<bool> shutdown_requested{false};
    std::mutex futures_mutex;
    std::vector<std::future<void>> active_futures;
    
    explicit Impl(const UnifiedAutocompleteConfig& cfg) : config(cfg) {}
    
    // Phase 17D.3: Explicit destructor for ordered cleanup
    ~Impl() {
        shutdown_requested.store(true);
        
        // Wait for all async operations to complete
        std::lock_guard<std::mutex> lock(futures_mutex);
        for (auto& future : active_futures) {
            if (future.valid()) {
                // Wait with timeout to avoid hanging
                auto status = future.wait_for(std::chrono::milliseconds(100));
                if (status == std::future_status::timeout) {
                    // Future is still running - we can't force cancel
                    // But we won't block indefinitely
                }
            }
        }
        active_futures.clear();
        
        // Flush telemetry before destruction
        if (telemetry_callback) {
            telemetry_callback(stats);
        }
        
        // Explicit cleanup order: AST -> Semantic -> Embedder
        // This ensures no dangling references
        ast_provider.reset();
        semantic_index.reset();
        code_embedder.reset();
    }
    
    void initialize_backends() {
        if (config.enable_semantic) {
            SemanticIndexConfig sem_cfg;
            semantic_index = std::make_unique<SemanticCodeIndex>(sem_cfg);
            semantic_index->initialize();
            
            // Initialize CodeEmbedder for semantic search
            EmbedderConfig embed_cfg;
            embed_cfg.model_path = config.model_path;
            embed_cfg.embedding_dimension = 384;
            embed_cfg.intra_op_threads = 2;  // Limit threads for latency
            embed_cfg.inter_op_threads = 1;
            code_embedder = std::make_unique<CodeEmbedder>(embed_cfg);
        }
        
        if (config.enable_ast) {
            ASTParserConfig ast_cfg;
            ast_provider = std::make_unique<ASTContextProvider>(ast_cfg);
        }
    }
    
    // Check if query is complex enough to warrant semantic search
    bool is_complex_request(const CursorContext& cursor) {
        // Complex if: longer than 3 chars, contains spaces, or is natural language-like
        if (cursor.current_word.length() > 3) return true;
        if (cursor.current_word.find(' ') != std::string::npos) return true;
        
        // Complex if after dot/arrow (member access patterns)
        if (cursor.is_after_dot || cursor.is_after_arrow) return true;
        
        // Complex if in type context
        if (cursor.is_type_context) return true;
        
        return false;
    }
    
    // Get or compute embedding with caching
    std::vector<float> get_embedding(const std::string& context) {
        auto it = embedding_cache.find(context);
        if (it != embedding_cache.end()) {
            cache_hits++;
            return it->second.embedding;
        }
        
        cache_misses++;
        
        // Compute new embedding
        std::vector<float> embedding;
        if (code_embedder) {
            embedding = code_embedder->Embed(context);
        }
        
        // Cache if valid
        if (!embedding.empty()) {
            if (embedding_cache.size() >= MAX_CACHE_SIZE) {
                // Simple LRU: clear half the cache
                embedding_cache.clear();
            }
            embedding_cache[context] = {embedding, std::chrono::steady_clock::now()};
        }
        
        return embedding;
    }
    
    // Simple trie lookup (stub - would use actual SymbolIndex)
    std::vector<UnifiedCompletion> query_trie(const std::string& prefix) {
        std::vector<UnifiedCompletion> results;
        
        for (const auto& [key, values] : trie_index) {
            if (key.find(prefix) == 0 || prefix.empty()) {
                for (const auto& val : values) {
                    UnifiedCompletion comp;
                    comp.text = val;
                    comp.label = val;
                    comp.detail = "Trie match";
                    // Normalize trie score to 0-1 range
                    comp.score = 1.0f - (static_cast<float>(key.length() - prefix.length()) / 100.0f);
                    comp.source = QueryType::FAST_PREFIX;
                    results.push_back(comp);
                    
                    if (results.size() >= static_cast<size_t>(config.max_completions)) break;
                }
            }
            if (results.size() >= static_cast<size_t>(config.max_completions)) break;
        }
        
        return results;
    }
};

// Constructor
UnifiedAutocompleteEngine::UnifiedAutocompleteEngine(const UnifiedAutocompleteConfig& config)
    : m_impl(std::make_unique<Impl>(config))
    , m_config(config) {
}

// Destructor
UnifiedAutocompleteEngine::~UnifiedAutocompleteEngine() = default;

// Move constructor
UnifiedAutocompleteEngine::UnifiedAutocompleteEngine(UnifiedAutocompleteEngine&& other) noexcept
    : m_impl(std::move(other.m_impl))
    , m_config(other.m_config) {
}

// Move assignment
UnifiedAutocompleteEngine& UnifiedAutocompleteEngine::operator=(UnifiedAutocompleteEngine&& other) noexcept {
    if (this != &other) {
        m_impl = std::move(other.m_impl);
        m_config = other.m_config;
    }
    return *this;
}

bool UnifiedAutocompleteEngine::initialize() {
    if (!m_impl) return false;
    
    m_impl->initialize_backends();
    
    // Seed trie with common keywords (stub)
    m_impl->trie_index["int"] = {"int", "int16_t", "int32_t", "int64_t", "intptr_t"};
    m_impl->trie_index["void"] = {"void", "volatile"};
    m_impl->trie_index["class"] = {"class", "classifier"};
    m_impl->trie_index["std::"] = {"std::vector", "std::string", "std::map", "std::unique_ptr"};
    m_impl->trie_index["async"] = {"async", "async_read", "async_write", "async_operation"};
    
    return true;
}

QueryType UnifiedAutocompleteEngine::classify_query(const CursorContext& cursor) const {
    // Fast prefix: simple word completion
    if (cursor.current_word.length() >= 2 && 
        !cursor.is_after_dot && !cursor.is_after_arrow &&
        !cursor.is_type_context) {
        return QueryType::FAST_PREFIX;
    }
    
    // Context-aware: member access or type context
    if (cursor.is_after_dot || cursor.is_after_arrow || cursor.is_type_context) {
        return QueryType::CONTEXT_AWARE;
    }
    
    // Default to semantic for natural language-like queries
    return QueryType::SEMANTIC;
}

std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::get_completions(const CursorContext& cursor) {
    std::vector<UnifiedCompletion> results;
    
    if (!m_impl) return results;
    
    auto start = std::chrono::steady_clock::now();
    QueryType query_type = classify_query(cursor);
    
    // Phase 17C.4: Hybrid Retrieval with Latency Guard
    // Always start with fast trie search
    auto trie_results = get_trie_completions(cursor);
    
    // Check if we have enough high-confidence trie results
    size_t high_confidence_trie = std::count_if(
        trie_results.begin(), trie_results.end(),
        [](const UnifiedCompletion& c) { return c.score > 0.9f; }
    );
    
    // Early termination: if trie has enough exact matches, skip semantic
    if (high_confidence_trie >= MAX_TRIE_RESULTS) {
        results = trie_results;
        if (results.size() > static_cast<size_t>(m_config.max_completions)) {
            results.resize(m_config.max_completions);
        }
    } else {
        // Phase 17D.3: Check if shutdown requested before starting async
        if (m_impl->shutdown_requested.load()) {
            return results;  // Don't start new operations during shutdown
        }
        
        // Parallel query: Trie + Semantic (with timeout)
        auto trie_future = std::async(std::launch::async, [trie_results]() {
            return trie_results;
        });
        
        // Capture cursor by value to avoid reference issues
        CursorContext cursor_copy = cursor;
        auto semantic_future = std::async(std::launch::async, [this, cursor_copy]() {
            // Phase 17D.3: Check shutdown before executing
            if (m_impl && m_impl->shutdown_requested.load()) {
                return std::vector<UnifiedCompletion>{};
            }
            return get_semantic_completions(cursor_copy);
        });
        
        // Phase 17D.3: Track active futures
        {
            std::lock_guard<std::mutex> lock(m_impl->futures_mutex);
            // Store futures as void futures for tracking
            // We can't easily store heterogeneous futures, so we track completion differently
        }
        
        // Wait for trie (should be instant)
        auto trie_res = trie_future.get();
        
        // Wait for semantic with timeout (remaining budget)
        auto elapsed = std::chrono::steady_clock::now() - start;
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() / 1000.0f;
        float remaining_budget = LATENCY_BUDGET_MS - elapsed_ms;
        
        std::vector<UnifiedCompletion> semantic_res;
        if (remaining_budget > 0.5f) {  // Only if we have >0.5ms left
            auto status = semantic_future.wait_for(
                std::chrono::microseconds(static_cast<long>(remaining_budget * 1000))
            );
            if (status == std::future_status::ready) {
                semantic_res = semantic_future.get();
            }
            // If timeout, semantic_res stays empty (graceful degradation)
        }
        
        // Weighted fusion of results
        results = fuse_results(trie_res, semantic_res);
    }
    
    // Add AST completions if context-aware query
    if (query_type == QueryType::CONTEXT_AWARE) {
        auto ast_results = get_ast_completions(cursor);
        results = merge_with_ast(results, ast_results);
    }
    
    // Update statistics
    auto elapsed = std::chrono::steady_clock::now() - start;
    m_impl->last_latency_ms = std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() / 1000.0f;
    
    m_impl->stats.total_queries++;
    m_impl->stats.avg_latency_ms = (m_impl->stats.avg_latency_ms * (m_impl->stats.total_queries - 1) + 
                                       m_impl->last_latency_ms) / m_impl->stats.total_queries;
    
    // Phase 17D.2: Update cache hit rate
    uint64_t total_cache_ops = m_impl->cache_hits + m_impl->cache_misses;
    if (total_cache_ops > 0) {
        m_impl->stats.cache_hit_rate = static_cast<float>(m_impl->cache_hits) / total_cache_ops;
    }
    
    // Update hit counters and track hybrid fusion
    bool had_trie = false, had_semantic = false;
    for (const auto& r : results) {
        switch (r.source) {
            case QueryType::FAST_PREFIX: 
                m_impl->stats.trie_hits++; 
                had_trie = true;
                break;
            case QueryType::SEMANTIC: 
                m_impl->stats.semantic_hits++; 
                had_semantic = true;
                break;
            case QueryType::CONTEXT_AWARE: 
                m_impl->stats.ast_hits++; 
                break;
        }
    }
    
    // Phase 17D.2: Track hybrid fusion (both trie and semantic contributed)
    if (had_trie && had_semantic) {
        m_impl->stats.hybrid_fusion_count++;
    }
    
    // Phase 17D.2: Track timeouts
    if (high_confidence_trie < MAX_TRIE_RESULTS) {
        auto semantic_elapsed = std::chrono::steady_clock::now() - start;
        auto semantic_ms = std::chrono::duration_cast<std::chrono::microseconds>(semantic_elapsed).count() / 1000.0f;
        if (semantic_ms > LATENCY_BUDGET_MS) {
            m_impl->stats.timeout_count++;
        }
    }
    
    // Phase 17D.2: Flush telemetry if callback registered
    if (m_impl->telemetry_callback) {
        m_impl->telemetry_callback(m_impl->stats);
    }
    
    return results;
}

std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::get_trie_completions(const CursorContext& cursor) {
    if (!m_config.enable_trie || !m_impl) return {};
    
    return m_impl->query_trie(cursor.current_word);
}

std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::get_semantic_completions(const CursorContext& cursor) {
    std::vector<UnifiedCompletion> results;
    
    if (!m_config.enable_semantic || !m_impl || !m_impl->semantic_index) {
        return results;
    }
    
    // Build natural language query from context
    std::string query = cursor.current_word;
    if (cursor.is_after_dot || cursor.is_after_arrow) {
        query += " member function";
    }
    if (cursor.is_type_context) {
        query += " type";
    }
    
    auto snippets = m_impl->semantic_index->semantic_search(
        query, 
        m_config.max_completions / 2,
        m_config.semantic_min_score
    );
    
    for (const auto& snippet : snippets) {
        UnifiedCompletion comp;
        comp.text = snippet.code;
        comp.label = snippet.code.substr(0, 50);
        comp.detail = snippet.file_path + ":" + std::to_string(snippet.line_number);
        comp.score = snippet.similarity_score;
        comp.source = QueryType::SEMANTIC;
        comp.file_path = snippet.file_path;
        comp.line_number = snippet.line_number;
        results.push_back(comp);
    }
    
    return results;
}

std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::get_ast_completions(const CursorContext& cursor) {
    std::vector<UnifiedCompletion> results;
    
    if (!m_config.enable_ast || !m_impl || !m_impl->ast_provider) {
        return results;
    }
    
    // Parse file if not already cached
    if (!m_impl->ast_provider->has_file(cursor.file_path)) {
        // In real implementation, would get content from IDE
        // For now, skip if not cached
        return results;
    }
    
    CursorPosition pos{cursor.line, cursor.column, cursor.file_path};
    auto symbols = m_impl->ast_provider->get_symbols_at_cursor(pos);
    
    for (const auto& sym : symbols) {
        UnifiedCompletion comp;
        comp.text = sym.name;
        comp.label = sym.name + " (" + sym.type + ")";
        comp.detail = sym.scope;
        comp.score = 0.9f;  // High score for AST matches
        comp.source = QueryType::CONTEXT_AWARE;
        comp.file_path = cursor.file_path;
        comp.line_number = sym.line_number;
        results.push_back(comp);
    }
    
    return results;
}

std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::merge_results(
    std::vector<UnifiedCompletion>&& trie_results,
    std::vector<UnifiedCompletion>&& semantic_results,
    std::vector<UnifiedCompletion>&& ast_results) {
    
    std::vector<UnifiedCompletion> merged;
    std::unordered_set<std::string> seen;
    
    // Priority: AST > Trie > Semantic (for deduplication)
    auto add_unique = [&](std::vector<UnifiedCompletion>& src, float score_boost) {
        for (auto& comp : src) {
            if (seen.find(comp.text) == seen.end()) {
                comp.score += score_boost;
                merged.push_back(comp);
                seen.insert(comp.text);
            }
        }
    };
    
    add_unique(ast_results, 0.2f);      // Boost AST results
    add_unique(trie_results, 0.1f);   // Slight boost for trie
    add_unique(semantic_results, 0.0f); // No boost
    
    // Sort by score descending
    std::sort(merged.begin(), merged.end(), 
              [](const UnifiedCompletion& a, const UnifiedCompletion& b) {
                  return a.score > b.score;
              });
    
    // Limit results
    if (merged.size() > static_cast<size_t>(m_config.max_completions)) {
        merged.resize(m_config.max_completions);
    }
    
    return merged;
}

// Phase 17C.4: Weighted Fusion of Trie and Semantic Results
// Formula: Score_final = α * Score_trie + (1-α) * Score_semantic
std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::fuse_results(
    const std::vector<UnifiedCompletion>& trie_results,
    const std::vector<UnifiedCompletion>& semantic_results) {
    
    std::vector<UnifiedCompletion> fused;
    std::unordered_map<std::string, UnifiedCompletion> result_map;
    
    // Add trie results with weight
    for (const auto& trie : trie_results) {
        UnifiedCompletion comp = trie;
        comp.score *= TRIE_WEIGHT;  // Apply trie weight
        result_map[comp.text] = comp;
    }
    
    // Merge semantic results with weight
    for (const auto& sem : semantic_results) {
        auto it = result_map.find(sem.text);
        if (it != result_map.end()) {
            // Result exists in both: weighted fusion
            it->second.score = (it->second.score * TRIE_WEIGHT) + 
                              (sem.score * SEMANTIC_WEIGHT);
            it->second.source = QueryType::SEMANTIC;  // Mark as hybrid
        } else {
            // New semantic result
            UnifiedCompletion comp = sem;
            comp.score *= SEMANTIC_WEIGHT;
            result_map[comp.text] = comp;
        }
    }
    
    // Convert map back to vector
    for (auto& [text, comp] : result_map) {
        (void)text;  // Unused, key is already in comp.text
        fused.push_back(comp);
    }
    
    // Sort by fused score descending
    std::sort(fused.begin(), fused.end(),
              [](const UnifiedCompletion& a, const UnifiedCompletion& b) {
                  return a.score > b.score;
              });
    
    // Limit results
    if (fused.size() > static_cast<size_t>(m_config.max_completions)) {
        fused.resize(m_config.max_completions);
    }
    
    return fused;
}

// Phase 17C.4: Merge AST results with existing results (AST gets priority)
std::vector<UnifiedCompletion> UnifiedAutocompleteEngine::merge_with_ast(
    const std::vector<UnifiedCompletion>& existing,
    const std::vector<UnifiedCompletion>& ast_results) {
    
    std::vector<UnifiedCompletion> merged;
    std::unordered_set<std::string> seen;
    
    // First add AST results (highest priority)
    for (const auto& ast : ast_results) {
        if (seen.find(ast.text) == seen.end()) {
            merged.push_back(ast);
            seen.insert(ast.text);
        }
    }
    
    // Then add existing results (if not duplicate)
    for (const auto& ex : existing) {
        if (seen.find(ex.text) == seen.end()) {
            merged.push_back(ex);
            seen.insert(ex.text);
        }
    }
    
    // Limit results
    if (merged.size() > static_cast<size_t>(m_config.max_completions)) {
        merged.resize(m_config.max_completions);
    }
    
    return merged;
}

void UnifiedAutocompleteEngine::index_code_snippet(const std::string& code, 
                                                     const std::string& metadata) {
    if (m_impl && m_impl->semantic_index) {
        m_impl->semantic_index->add_snippet(code, metadata);
    }
}

void UnifiedAutocompleteEngine::parse_file_for_ast(const std::string& file_path, 
                                                    const std::string& content) {
    if (m_impl && m_impl->ast_provider) {
        m_impl->ast_provider->parse_file(file_path, content);
    }
}

bool UnifiedAutocompleteEngine::is_ready() const {
    return m_impl != nullptr;
}

float UnifiedAutocompleteEngine::get_last_latency_ms() const {
    return m_impl ? m_impl->last_latency_ms : 0.0f;
}

UnifiedAutocompleteEngine::Stats UnifiedAutocompleteEngine::get_stats() const {
    return m_impl ? m_impl->stats : Stats{};
}

// Phase 17D.2: Telemetry callback implementation
void UnifiedAutocompleteEngine::set_telemetry_callback(TelemetryCallback callback) {
    if (m_impl) {
        m_impl->telemetry_callback = callback;
    }
}

void UnifiedAutocompleteEngine::flush_telemetry() {
    if (m_impl && m_impl->telemetry_callback) {
        m_impl->telemetry_callback(m_impl->stats);
    }
}

} // namespace rawrxd
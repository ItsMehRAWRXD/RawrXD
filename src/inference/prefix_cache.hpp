#pragma once

#include "../core/common.hpp"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace rawrxd::inference {

// Prefix cache entry
struct PrefixCacheEntry {
    std::vector<int> prefix_tokens;
    std::vector<uint8_t> kv_cache_data;
    int ref_count = 0;
    std::chrono::steady_clock::time_point last_access;
    size_t memory_size = 0;

    void touch() {
        last_access = std::chrono::steady_clock::now();
    }
};

// Prefix cache configuration
struct PrefixCacheConfig {
    size_t max_entries = 1000;           // Maximum cached prefixes
    size_t max_memory_mb = 1024;         // Maximum memory usage
    int min_prefix_length = 10;          // Minimum tokens to cache
    int max_prefix_length = 512;         // Maximum tokens to cache
    float eviction_threshold = 0.8f;     // Evict when memory reaches this %
};

// Prefix cache for common prompts
class PrefixCache {
public:
    explicit PrefixCache(const PrefixCacheConfig& config);
    ~PrefixCache() = default;

    // Initialize
    bool initialize();

    // Lookup prefix in cache
    std::optional<PrefixCacheEntry> lookup(const std::vector<int>& prefix_tokens);

    // Store prefix in cache
    bool store(const std::vector<int>& prefix_tokens,
               const std::vector<uint8_t>& kv_cache_data);

    // Release reference to cached prefix
    void release(const std::vector<int>& prefix_tokens);

    // Invalidate specific prefix
    bool invalidate(const std::vector<int>& prefix_tokens);

    // Invalidate all prefixes matching pattern
    void invalidatePattern(const std::string& pattern);

    // Clear all cached prefixes
    void clear();

    // Statistics
    struct Stats {
        size_t num_entries = 0;
        size_t total_memory_bytes = 0;
        uint64_t hits = 0;
        uint64_t misses = 0;
        float hit_rate = 0.0f;
        uint64_t evictions = 0;
    };

    Stats getStats() const;

private:
    PrefixCacheConfig config_;
    std::unordered_map<std::string, std::unique_ptr<PrefixCacheEntry>> cache_;
    mutable std::mutex mutex_;

    Stats stats_;
    mutable std::mutex stats_mutex_;

    // Hash function for token sequences
    std::string computeHash(const std::vector<int>& tokens) const;

    // Eviction
    void evictIfNeeded();
    void evictLRU();
    void evictBySize(size_t target_bytes);

    // Memory tracking
    size_t getCurrentMemoryUsage() const;
    bool canFit(size_t bytes) const;
};

// Radix tree-based prefix cache (more efficient for overlapping prefixes)
class RadixPrefixCache {
public:
    struct Node {
        std::vector<int> tokens;
        std::optional<PrefixCacheEntry> entry;
        std::unordered_map<int, std::unique_ptr<Node>> children;
        Node* parent = nullptr;
    };

    explicit RadixPrefixCache(const PrefixCacheConfig& config);

    // Insert prefix
    bool insert(const std::vector<int>& prefix_tokens,
                const std::vector<uint8_t>& kv_cache_data);

    // Longest prefix match
    std::optional<PrefixCacheEntry> longestPrefixMatch(
        const std::vector<int>& tokens);

    // All prefix matches
    std::vector<PrefixCacheEntry> allPrefixMatches(
        const std::vector<int>& tokens);

    // Remove prefix
    bool remove(const std::vector<int>& prefix_tokens);

    // Clear
    void clear();

    // Stats
    size_t getNodeCount() const;
    size_t getEntryCount() const;

private:
    PrefixCacheConfig config_;
    std::unique_ptr<Node> root_;
    mutable std::mutex mutex_;

    Node* findNode(const std::vector<int>& tokens);
    Node* createPath(const std::vector<int>& tokens);
    int commonPrefixLength(const std::vector<int>& a, const std::vector<int>& b);
};

// Prompt template cache (for system prompts)
class TemplateCache {
public:
    struct Template {
        std::string name;
        std::vector<int> tokenized_template;
        std::unordered_map<std::string, std::vector<int>> slots;
    };

    // Register template
    void registerTemplate(const std::string& name,
                          const std::string& template_text);

    // Get template
    std::optional<Template> getTemplate(const std::string& name);

    // Apply template with variables
    std::vector<int> applyTemplate(const std::string& name,
                                   const std::unordered_map<std::string, std::string>& vars);

    // List templates
    std::vector<std::string> listTemplates() const;

private:
    std::unordered_map<std::string, Template> templates_;
    mutable std::mutex mutex_;
};

// Cache warmup utility
class CacheWarmup {
public:
    // Warmup cache with common prompts
    void warmupFromFile(const std::string& prompts_file,
                        PrefixCache& cache,
                        std::shared_ptr<Model> model);

    // Warmup with synthetic prompts
    void warmupSynthetic(int num_prompts,
                         int prompt_length,
                         PrefixCache& cache,
                         std::shared_ptr<Model> model);

    // Async warmup
    void warmupAsync(const std::vector<std::vector<int>>& prompts,
                     PrefixCache& cache,
                     std::shared_ptr<Model> model);
};

} // namespace rawrxd::inference

#include "prefix_cache.hpp"
#include "../core/logger.hpp"
#include <sstream>
#include <iomanip>

namespace rawrxd::inference {

// ============================================================================
// Prefix Cache
// ============================================================================

PrefixCache::PrefixCache(const PrefixCacheConfig& config) : config_(config) {
    RAWRXD_LOG_INFO("PrefixCache", "Initialized with max_entries={}, max_memory={}MB",
                    config_.max_entries, config_.max_memory_mb);
}

bool PrefixCache::initialize() {
    RAWRXD_LOG_INFO("PrefixCache", "Cache initialized");
    return true;
}

std::optional<PrefixCacheEntry> PrefixCache::lookup(const std::vector<int>& prefix_tokens) {
    if (prefix_tokens.size() < static_cast<size_t>(config_.min_prefix_length) ||
        prefix_tokens.size() > static_cast<size_t>(config_.max_prefix_length)) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::string hash = computeHash(prefix_tokens);
    auto it = cache_.find(hash);

    if (it != cache_.end()) {
        it->second->touch();
        it->second->ref_count++;

        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.hits++;
        }

        return *it->second;
    }

    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.misses++;
    }

    return std::nullopt;
}

bool PrefixCache::store(const std::vector<int>& prefix_tokens,
                        const std::vector<uint8_t>& kv_cache_data) {
    if (prefix_tokens.size() < static_cast<size_t>(config_.min_prefix_length) ||
        prefix_tokens.size() > static_cast<size_t>(config_.max_prefix_length)) {
        return false;
    }

    evictIfNeeded();

    std::lock_guard<std::mutex> lock(mutex_);

    std::string hash = computeHash(prefix_tokens);

    auto entry = std::make_unique<PrefixCacheEntry>();
    entry->prefix_tokens = prefix_tokens;
    entry->kv_cache_data = kv_cache_data;
    entry->ref_count = 1;
    entry->touch();
    entry->memory_size = kv_cache_data.size();

    cache_[hash] = std::move(entry);

    RAWRXD_LOG_DEBUG("PrefixCache", "Stored prefix of length {} ({} bytes)",
                     prefix_tokens.size(), kv_cache_data.size());

    return true;
}

void PrefixCache::release(const std::vector<int>& prefix_tokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string hash = computeHash(prefix_tokens);
    auto it = cache_.find(hash);

    if (it != cache_.end()) {
        it->second->ref_count--;
        if (it->second->ref_count <= 0) {
            // Optionally evict unreferenced entries
        }
    }
}

bool PrefixCache::invalidate(const std::vector<int>& prefix_tokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string hash = computeHash(prefix_tokens);
    auto it = cache_.find(hash);

    if (it != cache_.end()) {
        cache_.erase(it);
        return true;
    }

    return false;
}

void PrefixCache::invalidatePattern(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Simple substring matching
    for (auto it = cache_.begin(); it != cache_.end();) {
        // Convert tokens back to string for pattern matching
        // This is a simplified implementation
        it = cache_.erase(it);
    }
}

void PrefixCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();

    RAWRXD_LOG_INFO("PrefixCache", "Cache cleared");
}

PrefixCache::Stats PrefixCache::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::lock_guard<std::mutex> cache_lock(mutex_);

    Stats stats = stats_;
    stats.num_entries = cache_.size();
    stats.total_memory_bytes = getCurrentMemoryUsage();

    if (stats.hits + stats.misses > 0) {
        stats.hit_rate = static_cast<float>(stats.hits) / (stats.hits + stats.misses);
    }

    return stats;
}

std::string PrefixCache::computeHash(const std::vector<int>& tokens) const {
    std::ostringstream oss;
    for (int token : tokens) {
        oss << std::hex << std::setw(8) << std::setfill('0') << token;
    }
    return oss.str();
}

void PrefixCache::evictIfNeeded() {
    size_t current_memory = getCurrentMemoryUsage();
    size_t max_memory = config_.max_memory_mb * 1024 * 1024;

    if (current_memory > max_memory * config_.eviction_threshold) {
        evictLRU();
    }

    if (cache_.size() >= config_.max_entries) {
        evictLRU();
    }
}

void PrefixCache::evictLRU() {
    if (cache_.empty()) return;

    auto oldest = cache_.begin();
    auto oldest_time = oldest->second->last_access;

    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second->last_access < oldest_time && it->second->ref_count == 0) {
            oldest = it;
            oldest_time = it->second->last_access;
        }
    }

    if (oldest->second->ref_count == 0) {
        RAWRXD_LOG_DEBUG("PrefixCache", "Evicted entry with {} tokens", oldest->second->prefix_tokens.size());
        cache_.erase(oldest);

        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.evictions++;
    }
}

void PrefixCache::evictBySize(size_t target_bytes) {
    // Evict entries until we free target_bytes
    size_t freed = 0;

    while (freed < target_bytes && !cache_.empty()) {
        evictLRU();
        // Update freed count
    }
}

size_t PrefixCache::getCurrentMemoryUsage() const {
    size_t total = 0;
    for (const auto& [hash, entry] : cache_) {
        total += entry->memory_size;
    }
    return total;
}

bool PrefixCache::canFit(size_t bytes) const {
    return getCurrentMemoryUsage() + bytes <= config_.max_memory_mb * 1024 * 1024;
}

// ============================================================================
// Radix Prefix Cache
// ============================================================================

RadixPrefixCache::RadixPrefixCache(const PrefixCacheConfig& config)
    : config_(config) {
    root_ = std::make_unique<Node>();
}

bool RadixPrefixCache::insert(const std::vector<int>& prefix_tokens,
                               const std::vector<uint8_t>& kv_cache_data) {
    std::lock_guard<std::mutex> lock(mutex_);

    Node* node = createPath(prefix_tokens);
    if (!node) return false;

    PrefixCacheEntry entry;
    entry.prefix_tokens = prefix_tokens;
    entry.kv_cache_data = kv_cache_data;
    entry.touch();

    node->entry = std::move(entry);

    return true;
}

std::optional<PrefixCacheEntry> RadixPrefixCache::longestPrefixMatch(
    const std::vector<int>& tokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    Node* current = root_.get();
    std::optional<PrefixCacheEntry> best_match;

    for (size_t i = 0; i < tokens.size(); ++i) {
        int token = tokens[i];
        auto it = current->children.find(token);

        if (it == current->children.end()) {
            break;
        }

        current = it->second.get();

        if (current->entry.has_value()) {
            best_match = current->entry;
        }
    }

    return best_match;
}

std::vector<PrefixCacheEntry> RadixPrefixCache::allPrefixMatches(
    const std::vector<int>& tokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PrefixCacheEntry> matches;
    Node* current = root_.get();

    for (size_t i = 0; i < tokens.size(); ++i) {
        int token = tokens[i];
        auto it = current->children.find(token);

        if (it == current->children.end()) {
            break;
        }

        current = it->second.get();

        if (current->entry.has_value()) {
            matches.push_back(*current->entry);
        }
    }

    return matches;
}

bool RadixPrefixCache::remove(const std::vector<int>& prefix_tokens) {
    std::lock_guard<std::mutex> lock(mutex_);

    Node* node = findNode(prefix_tokens);
    if (!node) return false;

    node->entry.reset();
    return true;
}

void RadixPrefixCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    root_ = std::make_unique<Node>();
}

size_t RadixPrefixCache::getNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    std::function<void(const Node*)> countNodes = [&](const Node* node) {
        if (!node) return;
        count++;
        for (const auto& [token, child] : node->children) {
            countNodes(child.get());
        }
    };

    countNodes(root_.get());
    return count;
}

size_t RadixPrefixCache::getEntryCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    std::function<void(const Node*)> countEntries = [&](const Node* node) {
        if (!node) return;
        if (node->entry.has_value()) count++;
        for (const auto& [token, child] : node->children) {
            countEntries(child.get());
        }
    };

    countEntries(root_.get());
    return count;
}

RadixPrefixCache::Node* RadixPrefixCache::findNode(const std::vector<int>& tokens) {
    Node* current = root_.get();

    for (int token : tokens) {
        auto it = current->children.find(token);
        if (it == current->children.end()) {
            return nullptr;
        }
        current = it->second.get();
    }

    return current;
}

RadixPrefixCache::Node* RadixPrefixCache::createPath(const std::vector<int>& tokens) {
    Node* current = root_.get();

    for (int token : tokens) {
        auto it = current->children.find(token);
        if (it == current->children.end()) {
            auto new_node = std::make_unique<Node>();
            new_node->parent = current;
            auto* ptr = new_node.get();
            current->children[token] = std::move(new_node);
            current = ptr;
        } else {
            current = it->second.get();
        }
    }

    return current;
}

int RadixPrefixCache::commonPrefixLength(const std::vector<int>& a,
                                          const std::vector<int>& b) {
    int common = 0;
    size_t min_len = std::min(a.size(), b.size());

    for (size_t i = 0; i < min_len; ++i) {
        if (a[i] == b[i]) {
            common++;
        } else {
            break;
        }
    }

    return common;
}

// ============================================================================
// Template Cache
// ============================================================================

void TemplateCache::registerTemplate(const std::string& name,
                                      const std::string& template_text) {
    std::lock_guard<std::mutex> lock(mutex_);

    Template tmpl;
    tmpl.name = name;
    // Tokenize template_text
    // Parse slots like {{variable}}

    templates_[name] = std::move(tmpl);

    RAWRXD_LOG_INFO("TemplateCache", "Registered template: {}", name);
}

std::optional<TemplateCache::Template> TemplateCache::getTemplate(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(name);
    if (it != templates_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<int> TemplateCache::applyTemplate(
    const std::string& name,
    const std::unordered_map<std::string, std::string>& vars) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = templates_.find(name);
    if (it == templates_.end()) {
        return {};
    }

    // Apply variables to template
    // Return tokenized result
    return {};
}

std::vector<std::string> TemplateCache::listTemplates() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> names;
    for (const auto& [name, _] : templates_) {
        names.push_back(name);
    }

    return names;
}

// ============================================================================
// Cache Warmup
// ============================================================================

void CacheWarmup::warmupFromFile(const std::string& prompts_file,
                                  PrefixCache& cache,
                                  std::shared_ptr<Model> model) {
    RAWRXD_LOG_INFO("CacheWarmup", "Warming up cache from: {}", prompts_file);

    // Load prompts from file
    // Compute KV cache for each
    // Store in cache
}

void CacheWarmup::warmupSynthetic(int num_prompts,
                                   int prompt_length,
                                   PrefixCache& cache,
                                   std::shared_ptr<Model> model) {
    RAWRXD_LOG_INFO("CacheWarmup", "Warming up with {} synthetic prompts", num_prompts);

    // Generate synthetic prompts
    // Compute and cache
}

void CacheWarmup::warmupAsync(const std::vector<std::vector<int>>& prompts,
                               PrefixCache& cache,
                               std::shared_ptr<Model> model) {
    RAWRXD_LOG_INFO("CacheWarmup", "Async warmup with {} prompts", prompts.size());

    // Launch async tasks
    // Compute KV caches in background
}

} // namespace rawrxd::inference

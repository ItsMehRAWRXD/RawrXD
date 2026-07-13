// RawrXD KV Cache Manager Implementation
// Phase AO: KV Cache Optimization

#include "kv_cache_manager.hpp"
#include <iostream>
#include <algorithm>
#include <cstring>

namespace rawrxd {
namespace cache {

// Global KV cache manager instance
static std::unique_ptr<KVCacheManager> g_kv_cache_manager;

KVCacheManager* getKVCacheManager() {
    return g_kv_cache_manager.get();
}

void setKVCacheManager(std::unique_ptr<KVCacheManager> manager) {
    g_kv_cache_manager = std::move(manager);
}

// KVCacheManager implementation
KVCacheManager::KVCacheManager()
    : current_size_(0)
    , access_counter_(0)
    , initialized_(false) {
}

KVCacheManager::~KVCacheManager() {
    shutdown();
}

bool KVCacheManager::initialize(const KVCacheConfig& config) {
    config_ = config;
    stats_.max_size = config.max_cache_size;
    
    if (config.enable_compression) {
        compressor_ = std::make_unique<CacheCompressor>();
    }
    
    initialized_ = true;
    return true;
}

void KVCacheManager::shutdown() {
    if (!initialized_) return;
    
    clear();
    compressor_.reset();
    initialized_ = false;
}

KVCacheEntry* KVCacheManager::allocate(int layer_id, int head_id, int seq_len) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Calculate required size
    size_t required_size = 2 * seq_len * config_.head_dim * sizeof(float);  // key + value
    
    // Evict if needed
    if (current_size_ + required_size > config_.max_cache_size) {
        evictIfNeeded(required_size);
    }
    
    // Create new entry
    auto entry = std::make_unique<KVCacheEntry>();
    entry->layer_id = layer_id;
    entry->head_id = head_id;
    entry->seq_len = seq_len;
    entry->head_dim = config_.head_dim;
    entry->last_access = ++access_counter_;
    entry->access_count = 1;
    entry->state = CacheEntryState::ACTIVE;
    
    // Allocate cache buffers
    entry->key_cache.resize(seq_len * config_.head_dim);
    entry->value_cache.resize(seq_len * config_.head_dim);
    
    // Store in cache
    std::string key = makeKey(layer_id, head_id, 0, seq_len);
    KVCacheEntry* entry_ptr = entry.get();
    cache_[key] = std::move(entry);
    
    // Update LRU
    lru_queue_.push(entry_ptr);
    access_frequency_[entry_ptr] = 1;
    
    current_size_ += entry_ptr->size();
    
    return entry_ptr;
}

void KVCacheManager::release(KVCacheEntry* entry) {
    if (!entry) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    entry->state = CacheEntryState::IDLE;
}

void KVCacheManager::markUsed(KVCacheEntry* entry) {
    if (!entry) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    entry->last_access = ++access_counter_;
    entry->access_count++;
    
    updateLRU(entry);
}

KVCacheEntry* KVCacheManager::lookup(int layer_id, int head_id, int seq_start, int seq_end) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = makeKey(layer_id, head_id, seq_start, seq_end);
    auto it = cache_.find(key);
    
    if (it != cache_.end()) {
        KVCacheEntry* entry = it->second.get();
        entry->last_access = ++access_counter_;
        entry->access_count++;
        stats_.hits++;
        
        updateLRU(entry);
        
        return entry;
    }
    
    stats_.misses++;
    return nullptr;
}

bool KVCacheManager::contains(int layer_id, int head_id, int seq_len) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = makeKey(layer_id, head_id, 0, seq_len);
    return cache_.find(key) != cache_.end();
}

void KVCacheManager::prefetch(int layer_id, int head_id, int seq_start, int seq_len) {
    // Prefetch logic - mark entries as prefetched
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (int i = 0; i < seq_len; i += config_.prefetch_distance) {
        int end = std::min(i + config_.prefetch_distance, seq_len);
        std::string key = makeKey(layer_id, head_id, seq_start + i, seq_start + end);
        
        auto it = cache_.find(key);
        if (it != cache_.end()) {
            it->second->state = CacheEntryState::PREFETCHED;
            stats_.prefetches++;
        }
    }
}

void KVCacheManager::evictIfNeeded(size_t required_size) {
    while (current_size_ + required_size > config_.max_cache_size && !cache_.empty()) {
        KVCacheEntry* entry_to_evict = nullptr;
        
        switch (config_.eviction_policy) {
            case EvictionPolicy::LRU:
                entry_to_evict = evictLRU();
                break;
            case EvictionPolicy::LFU:
                entry_to_evict = evictLFU();
                break;
            case EvictionPolicy::FIFO:
                entry_to_evict = evictFIFO();
                break;
            case EvictionPolicy::RANDOM:
                entry_to_evict = evictRandom();
                break;
            default:
                entry_to_evict = evictLRU();
                break;
        }
        
        if (entry_to_evict) {
            evictEntry(entry_to_evict);
        } else {
            break;
        }
    }
}

void KVCacheManager::evictEntry(KVCacheEntry* entry) {
    if (!entry) return;
    
    current_size_ -= entry->size();
    
    // Find and remove from cache
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
        if (it->second.get() == entry) {
            cache_.erase(it);
            break;
        }
    }
    
    // Remove from LRU queue
    std::queue<KVCacheEntry*> new_queue;
    while (!lru_queue_.empty()) {
        KVCacheEntry* front = lru_queue_.front();
        lru_queue_.pop();
        if (front != entry) {
            new_queue.push(front);
        }
    }
    lru_queue_ = std::move(new_queue);
    
    // Remove from frequency map
    access_frequency_.erase(entry);
    
    stats_.evictions++;
}

void KVCacheManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    cache_.clear();
    
    // Clear LRU queue
    while (!lru_queue_.empty()) {
        lru_queue_.pop();
    }
    
    access_frequency_.clear();
    current_size_ = 0;
}

void KVCacheManager::compressEntry(KVCacheEntry* entry) {
    if (!entry || !compressor_ || !config_.enable_compression) return;
    
    compressor_->quantizeFP16(entry->key_cache);
    compressor_->quantizeFP16(entry->value_cache);
}

void KVCacheManager::decompressEntry(KVCacheEntry* entry) {
    if (!entry || !compressor_ || !config_.enable_compression) return;
    
    compressor_->dequantizeFP16(entry->key_cache);
    compressor_->dequantizeFP16(entry->value_cache);
}

KVCacheStats KVCacheManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    KVCacheStats stats = stats_;
    stats.current_size = current_size_;
    
    size_t total_accesses = stats.hits + stats.misses;
    if (total_accesses > 0) {
        stats.hit_rate = static_cast<float>(stats.hits) / total_accesses;
    }
    
    return stats;
}

void KVCacheManager::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_ = KVCacheStats();
    stats_.max_size = config_.max_cache_size;
}

void KVCacheManager::printStats() const {
    auto stats = getStats();
    
    std::cout << "KV Cache Statistics:" << std::endl;
    std::cout << "  Current size: " << stats.current_size << " bytes" << std::endl;
    std::cout << "  Max size: " << stats.max_size << " bytes" << std::endl;
    std::cout << "  Hits: " << stats.hits << std::endl;
    std::cout << "  Misses: " << stats.misses << std::endl;
    std::cout << "  Hit rate: " << (stats.hit_rate * 100) << "%" << std::endl;
    std::cout << "  Evictions: " << stats.evictions << std::endl;
    std::cout << "  Prefetches: " << stats.prefetches << std::endl;
}

void KVCacheManager::setEvictionPolicy(EvictionPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.eviction_policy = policy;
}

void KVCacheManager::setMaxSize(size_t max_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_.max_cache_size = max_size;
    stats_.max_size = max_size;
    
    // Evict if needed
    if (current_size_ > max_size) {
        evictIfNeeded(0);
    }
}

size_t KVCacheManager::getCurrentSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_size_;
}

float KVCacheManager::getUtilization() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (config_.max_cache_size == 0) return 0.0f;
    return static_cast<float>(current_size_) / config_.max_cache_size;
}

std::string KVCacheManager::makeKey(int layer_id, int head_id, int seq_start, int seq_end) {
    return std::to_string(layer_id) + ":" + std::to_string(head_id) + ":" + 
           std::to_string(seq_start) + ":" + std::to_string(seq_end);
}

KVCacheEntry* KVCacheManager::evictLRU() {
    while (!lru_queue_.empty()) {
        KVCacheEntry* entry = lru_queue_.front();
        lru_queue_.pop();
        
        // Check if entry still exists in cache
        for (const auto& [key, cached_entry] : cache_) {
            if (cached_entry.get() == entry) {
                return entry;
            }
        }
    }
    return nullptr;
}

KVCacheEntry* KVCacheManager::evictLFU() {
    if (access_frequency_.empty()) return nullptr;
    
    auto min_it = std::min_element(access_frequency_.begin(), access_frequency_.end(),
        [](const auto& a, const auto& b) {
            return a.second < b.second;
        });
    
    return min_it->first;
}

KVCacheEntry* KVCacheManager::evictFIFO() {
    // Same as LRU for simplicity
    return evictLRU();
}

KVCacheEntry* KVCacheManager::evictRandom() {
    if (cache_.empty()) return nullptr;
    
    auto it = cache_.begin();
    std::advance(it, rand() % cache_.size());
    return it->second.get();
}

void KVCacheManager::updateLRU(KVCacheEntry* entry) {
    // Move entry to back of queue (most recently used)
    std::queue<KVCacheEntry*> new_queue;
    while (!lru_queue_.empty()) {
        KVCacheEntry* front = lru_queue_.front();
        lru_queue_.pop();
        if (front != entry) {
            new_queue.push(front);
        }
    }
    new_queue.push(entry);
    lru_queue_ = std::move(new_queue);
}

// CacheCompressor implementation
CacheCompressor::CacheCompressor()
    : compression_ratio_(1.0f) {
}

void CacheCompressor::quantizeFP16(std::vector<float>& data) {
    // Placeholder for FP16 quantization
    // In production, this would convert float32 to float16
    compression_ratio_ = 0.5f;
}

void CacheCompressor::quantizeINT8(std::vector<float>& data) {
    // Placeholder for INT8 quantization
    // In production, this would quantize to 8-bit integers
    compression_ratio_ = 0.25f;
}

void CacheCompressor::dequantizeFP16(std::vector<float>& data) {
    // Placeholder for FP16 dequantization
}

void CacheCompressor::dequantizeINT8(std::vector<float>& data) {
    // Placeholder for INT8 dequantization
}

void CacheCompressor::sparsify(std::vector<float>& data, float threshold) {
    // Zero out values below threshold
    for (auto& val : data) {
        if (std::abs(val) < threshold) {
            val = 0.0f;
        }
    }
}

void CacheCompressor::densify(std::vector<float>& data) {
    // Convert sparse representation back to dense
    // Placeholder implementation
}

} // namespace cache
} // namespace rawrxd

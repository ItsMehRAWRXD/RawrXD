#include "rawrxd/performance/KVCacheManager.hpp"
#include <algorithm>
#include <chrono>

namespace rawrxd {
namespace performance {

// KVCacheManager implementation
KVCacheManager::KVCacheManager() = default;

KVCacheManager::~KVCacheManager() {
    Clear();
}

bool KVCacheManager::Initialize(const KVCacheConfig& config) {
    config_ = config;
    stats_.maxSizeBytes = config.maxCacheSizeMB * 1024 * 1024;
    return true;
}

int KVCacheManager::AllocateCache(int numLayers, int numHeads, int headDim, int maxSeqLen) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if we need to evict
    if (config_.enableEviction) {
        EvictIfNeeded();
    }
    
    int cacheId;
    if (!freeIds_.empty()) {
        cacheId = freeIds_.front();
        freeIds_.pop();
    } else {
        cacheId = nextId_++;
    }
    
    auto entry = std::make_shared<KVCacheEntry>();
    entry->numLayers = numLayers;
    entry->numHeads = numHeads;
    entry->headDim = headDim;
    entry->sequenceLength = 0;
    entry->lastAccess = std::chrono::system_clock::now();
    entry->accessCount = 0;
    
    // Pre-allocate for max sequence length
    size_t cacheSize = static_cast<size_t>(numLayers) * numHeads * maxSeqLen * headDim;
    entry->keyCache.reserve(cacheSize);
    entry->valueCache.reserve(cacheSize);
    
    caches_[cacheId] = entry;
    stats_.numEntries = static_cast<int>(caches_.size());
    
    return cacheId;
}

std::shared_ptr<KVCacheEntry> KVCacheManager::GetCache(int cacheId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = caches_.find(cacheId);
    if (it != caches_.end()) {
        it->second->lastAccess = std::chrono::system_clock::now();
        it->second->accessCount++;
        stats_.numHits++;
        return it->second;
    }
    
    stats_.numMisses++;
    return nullptr;
}

bool KVCacheManager::AppendToCache(int cacheId, const std::vector<float>& newKeys,
                                   const std::vector<float>& newValues,
                                   int numNewTokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = caches_.find(cacheId);
    if (it == caches_.end()) {
        return false;
    }
    
    auto& entry = it->second;
    entry->keyCache.insert(entry->keyCache.end(), newKeys.begin(), newKeys.end());
    entry->valueCache.insert(entry->valueCache.end(), newValues.begin(), newValues.end());
    entry->sequenceLength += numNewTokens;
    entry->lastAccess = std::chrono::system_clock::now();
    
    stats_.totalSizeBytes += (newKeys.size() + newValues.size()) * sizeof(float);
    
    return true;
}

void KVCacheManager::FreeCache(int cacheId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = caches_.find(cacheId);
    if (it != caches_.end()) {
        stats_.totalSizeBytes -= it->second->GetSizeBytes();
        caches_.erase(it);
        freeIds_.push(cacheId);
        stats_.numEntries = static_cast<int>(caches_.size());
    }
}

KVCacheManager::Stats KVCacheManager::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats = stats_;
    int totalAccesses = stats.numHits + stats.numMisses;
    if (totalAccesses > 0) {
        stats.hitRate = 100.0f * stats.numHits / totalAccesses;
    }
    
    return stats;
}

void KVCacheManager::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    caches_.clear();
    while (!freeIds_.empty()) {
        freeIds_.pop();
    }
    
    stats_.totalSizeBytes = 0;
    stats_.numEntries = 0;
}

void KVCacheManager::Compact() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Shrink vectors to fit actual size
    for (auto& pair : caches_) {
        auto& entry = pair.second;
        entry->keyCache.shrink_to_fit();
        entry->valueCache.shrink_to_fit();
    }
}

size_t KVCacheManager::GetMemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_.totalSizeBytes;
}

void KVCacheManager::EvictIfNeeded() {
    while (stats_.totalSizeBytes > stats_.maxSizeBytes && !caches_.empty()) {
        int candidate = SelectEvictionCandidate();
        if (candidate >= 0) {
            EvictEntry(candidate);
        } else {
            break;
        }
    }
}

int KVCacheManager::SelectEvictionCandidate() const {
    if (caches_.empty()) {
        return -1;
    }
    
    if (config_.evictionPolicy == "lru") {
        // Least Recently Used
        auto it = std::min_element(caches_.begin(), caches_.end(),
            [](const auto& a, const auto& b) {
                return a.second->lastAccess < b.second->lastAccess;
            });
        return it->first;
    } else if (config_.evictionPolicy == "lfu") {
        // Least Frequently Used
        auto it = std::min_element(caches_.begin(), caches_.end(),
            [](const auto& a, const auto& b) {
                return a.second->accessCount < b.second->accessCount;
            });
        return it->first;
    } else {
        // FIFO - first entry
        return caches_.begin()->first;
    }
}

void KVCacheManager::EvictEntry(int cacheId) {
    auto it = caches_.find(cacheId);
    if (it != caches_.end()) {
        stats_.totalSizeBytes -= it->second->GetSizeBytes();
        caches_.erase(it);
        freeIds_.push(cacheId);
        stats_.evictions++;
        stats_.numEntries = static_cast<int>(caches_.size());
    }
}

// PagedKVCache implementation
PagedKVCache::PagedKVCache() = default;

PagedKVCache::~PagedKVCache() = default;

bool PagedKVCache::Initialize(int numLayers, int numHeads, int headDim, int maxPages) {
    numLayers_ = numLayers;
    numHeads_ = numHeads;
    headDim_ = headDim;
    maxPages_ = maxPages;
    
    // Calculate page size
    size_t tokensPerPage = PAGE_SIZE;
    size_t pageSize = static_cast<size_t>(numLayers) * numHeads * tokensPerPage * headDim * sizeof(float);
    
    pages_.resize(maxPages);
    for (int i = 0; i < maxPages; ++i) {
        pages_[i].keyData.resize(pageSize / sizeof(float));
        pages_[i].valueData.resize(pageSize / sizeof(float));
        pages_[i].allocated = false;
        freePageList_.push_back(i);
    }
    
    return true;
}

std::vector<int> PagedKVCache::AllocatePages(int numTokens) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    int numPages = (numTokens + PAGE_SIZE - 1) / PAGE_SIZE;
    std::vector<int> allocatedPages;
    
    for (int i = 0; i < numPages && !freePageList_.empty(); ++i) {
        int pageId = freePageList_.back();
        freePageList_.pop_back();
        pages_[pageId].allocated = true;
        allocatedPages.push_back(pageId);
    }
    
    return allocatedPages;
}

PagedKVCache::Page* PagedKVCache::GetPage(int pageId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (pageId >= 0 && pageId < static_cast<int>(pages_.size()) && pages_[pageId].allocated) {
        return &pages_[pageId];
    }
    
    return nullptr;
}

void PagedKVCache::FreePages(const std::vector<int>& pageIds) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (int pageId : pageIds) {
        if (pageId >= 0 && pageId < static_cast<int>(pages_.size())) {
            pages_[pageId].allocated = false;
            freePageList_.push_back(pageId);
        }
    }
}

size_t PagedKVCache::GetMemoryUsage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t usedPages = maxPages_ - freePageList_.size();
    if (!pages_.empty()) {
        return usedPages * pages_[0].keyData.size() * sizeof(float) * 2;  // Keys + values
    }
    return 0;
}

PagedKVCache::Stats PagedKVCache::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats;
    stats.totalPages = maxPages_;
    stats.allocatedPages = maxPages_ - static_cast<int>(freePageList_.size());
    stats.freePages = static_cast<int>(freePageList_.size());
    if (!pages_.empty()) {
        stats.pageSizeBytes = pages_[0].keyData.size() * sizeof(float);
    }
    return stats;
}

} // namespace performance
} // namespace rawrxd

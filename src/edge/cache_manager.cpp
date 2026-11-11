/**
 * @file cache_manager.cpp
 * @brief Edge cache manager implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "cache_manager.hpp"
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <shared_mutex>

namespace rawrxd {
namespace edge {

// ============================================================================
// EdgeCacheManager Implementation
// ============================================================================

class EdgeCacheManager::Impl {
public:
    size_t max_size_ = 0;
    size_t current_size_ = 0;
    std::string cache_directory_;
    std::map<std::string, CacheEntry> entries_;
    mutable std::shared_mutex mutex_;
    CacheStats stats_;

    bool initialize(size_t max_cache_size, const std::string& cache_directory) {
        max_size_ = max_cache_size;
        cache_directory_ = cache_directory;
        
        // Create cache directory if it doesn't exist
        std::filesystem::create_directories(cache_directory_);
        
        // Load existing cache entries
        loadExistingEntries();
        
        return true;
    }

    void loadExistingEntries() {
        if (!std::filesystem::exists(cache_directory_)) {
            return;
        }

        for (const auto& entry : std::filesystem::directory_iterator(cache_directory_)) {
            if (entry.is_regular_file()) {
                std::string model_id = entry.path().stem().string();
                size_t file_size = entry.file_size();
                
                CacheEntry cache_entry;
                cache_entry.model_id = model_id;
                cache_entry.size_bytes = file_size;
                cache_entry.loaded_time = std::chrono::steady_clock::now();
                cache_entry.last_access = cache_entry.loaded_time;
                cache_entry.access_count = 0;
                cache_entry.priority_score = 1.0f;
                
                entries_[model_id] = cache_entry;
                current_size_ += file_size;
            }
        }
    }

    bool cacheModel(const std::string& model_id, const std::vector<uint8_t>& data, float priority) {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        // Check if we need to evict
        if (current_size_ + data.size() > max_size_) {
            evictToFreeSpace(data.size());
        }

        // Check again if we have space
        if (data.size() > max_size_) {
            return false;
        }

        // Write to cache directory
        std::string file_path = cache_directory_ + "/" + model_id + ".bin";
        std::ofstream file(file_path, std::ios::binary);
        if (!file) {
            return false;
        }

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();

        // Update entry
        CacheEntry entry;
        entry.model_id = model_id;
        entry.size_bytes = data.size();
        entry.loaded_time = std::chrono::steady_clock::now();
        entry.last_access = entry.loaded_time;
        entry.access_count = 0;
        entry.priority_score = priority;

        entries_[model_id] = entry;
        current_size_ += data.size();

        return true;
    }

    std::optional<std::vector<uint8_t>> getModel(const std::string& model_id) {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        auto it = entries_.find(model_id);
        if (it == entries_.end()) {
            stats_.miss_count++;
            return std::nullopt;
        }

        // Update access info
        it->second.last_access = std::chrono::steady_clock::now();
        it->second.access_count++;

        // Read from disk
        std::string file_path = cache_directory_ + "/" + model_id + ".bin";
        std::ifstream file(file_path, std::ios::binary | std::ios::ate);
        if (!file) {
            stats_.miss_count++;
            return std::nullopt;
        }

        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> data(size);
        file.read(reinterpret_cast<char*>(data.data()), size);

        stats_.hit_count++;
        return data;
    }

    bool isCached(const std::string& model_id) const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return entries_.find(model_id) != entries_.end();
    }

    bool evictModel(const std::string& model_id) {
        std::unique_lock<std::shared_mutex> lock(mutex_);

        auto it = entries_.find(model_id);
        if (it == entries_.end()) {
            return false;
        }

        // Delete file
        std::string file_path = cache_directory_ + "/" + model_id + ".bin";
        std::filesystem::remove(file_path);

        current_size_ -= it->second.size_bytes;
        entries_.erase(it);
        stats_.eviction_count++;

        return true;
    }

    size_t evictToFreeSpace(size_t required_space) {
        size_t freed = 0;

        // Sort by last access time (LRU)
        std::vector<std::pair<std::string, CacheEntry>> sorted_entries(
            entries_.begin(), entries_.end()
        );
        
        std::sort(sorted_entries.begin(), sorted_entries.end(),
            [](const auto& a, const auto& b) {
                return a.second.last_access < b.second.last_access;
            });

        for (const auto& [id, entry] : sorted_entries) {
            if (current_size_ + freed + required_space <= max_size_) {
                break;
            }

            std::string file_path = cache_directory_ + "/" + id + ".bin";
            std::filesystem::remove(file_path);
            freed += entry.size_bytes;
            entries_.erase(id);
            stats_.eviction_count++;
        }

        current_size_ -= freed;
        return freed;
    }

    std::vector<std::string> getCachedModels() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        std::vector<std::string> models;
        for (const auto& [id, _] : entries_) {
            models.push_back(id);
        }
        return models;
    }

    CacheStats getStats() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        CacheStats stats = stats_;
        stats.total_size = current_size_;
        stats.max_size = max_size_;
        stats.entry_count = entries_.size();
        
        size_t total = stats.hit_count + stats.miss_count;
        stats.hit_rate = total > 0 ? static_cast<float>(stats.hit_count) / total : 0.0f;
        
        return stats;
    }

    void clearCache() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        
        for (const auto& [id, _] : entries_) {
            std::string file_path = cache_directory_ + "/" + id + ".bin";
            std::filesystem::remove(file_path);
        }
        
        entries_.clear();
        current_size_ = 0;
    }

    size_t getCurrentSize() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return current_size_;
    }

    size_t getMaxSize() const {
        return max_size_;
    }

    void setMaxSize(size_t max_size) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        max_size_ = max_size;
        
        // Evict if necessary
        if (current_size_ > max_size_) {
            evictToFreeSpace(0);
        }
    }
};

// Public interface implementation
EdgeCacheManager::EdgeCacheManager() : impl_(std::make_unique<Impl>()) {}
EdgeCacheManager::~EdgeCacheManager() = default;

bool EdgeCacheManager::initialize(size_t max_cache_size, const std::string& cache_directory) {
    return impl_->initialize(max_cache_size, cache_directory);
}

bool EdgeCacheManager::initialize(const DeviceProfile& profile, const std::string& cache_directory) {
    // Calculate cache size based on device profile
    size_t cache_size = profile.available_storage / 4;  // Use 25% of storage
    return impl_->initialize(cache_size, cache_directory);
}

bool EdgeCacheManager::cacheModel(const std::string& model_id, const std::vector<uint8_t>& data, float priority) {
    return impl_->cacheModel(model_id, data, priority);
}

std::optional<std::vector<uint8_t>> EdgeCacheManager::getModel(const std::string& model_id) {
    return impl_->getModel(model_id);
}

bool EdgeCacheManager::isCached(const std::string& model_id) const {
    return impl_->isCached(model_id);
}

bool EdgeCacheManager::evictModel(const std::string& model_id) {
    return impl_->evictModel(model_id);
}

size_t EdgeCacheManager::evictToFreeSpace(size_t required_space) {
    return impl_->evictToFreeSpace(required_space);
}

std::vector<std::string> EdgeCacheManager::getCachedModels() const {
    return impl_->getCachedModels();
}

CacheStats EdgeCacheManager::getStats() const {
    return impl_->getStats();
}

void EdgeCacheManager::clearCache() {
    impl_->clearCache();
}

size_t EdgeCacheManager::getCurrentSize() const {
    return impl_->getCurrentSize();
}

size_t EdgeCacheManager::getMaxSize() const {
    return impl_->getMaxSize();
}

void EdgeCacheManager::setMaxSize(size_t max_size) {
    impl_->setMaxSize(max_size);
}

} // namespace edge
} // namespace rawrxd

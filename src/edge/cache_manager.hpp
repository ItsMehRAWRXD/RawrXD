#pragma once

/**
 * @file cache_manager.hpp
 * @brief Edge cache manager for model storage and retrieval
 * @details Manages local model cache with LRU eviction and predictive preloading
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <memory>
#include <chrono>

namespace rawrxd {
namespace edge {

/**
 * @brief Cache entry metadata
 */
struct CacheEntry {
    std::string model_id;
    size_t size_bytes;
    std::chrono::steady_clock::time_point last_access;
    std::chrono::steady_clock::time_point created;
    uint32_t access_count;
    float priority_score;  // For predictive preloading
};

/**
 * @brief Cache statistics
 */
struct CacheStats {
    size_t total_size;
    size_t max_size;
    size_t entry_count;
    size_t hit_count;
    size_t miss_count;
    float hit_rate;
    size_t eviction_count;
};

/**
 * @brief Device profile for cache sizing
 */
struct DeviceProfile {
    enum class Type {
        MOBILE,     // Smartphones, tablets
        IOT,        // IoT sensors, controllers
        EMBEDDED,   // Industrial edge devices
        BROWSER     // Web/WASM environments
    };
    
    Type type;
    size_t available_memory;
    size_t available_storage;
    bool has_gpu;
    size_t gpu_memory;
};

/**
 * @brief Edge cache manager with LRU eviction
 *
 * Manages local storage of compressed models with:
 * - LRU eviction policy
 * - Predictive preloading
 * - Cache warming
 * - Memory pressure handling
 */
class EdgeCacheManager {
public:
    EdgeCacheManager();
    ~EdgeCacheManager();

    /**
     * @brief Initialize cache manager
     * @param max_cache_size Maximum cache size in bytes
     * @param cache_directory Directory for cache storage
     * @return true if initialization successful
     */
    bool initialize(size_t max_cache_size, const std::string& cache_directory);

    /**
     * @brief Initialize with device profile
     * @param profile Device profile for automatic sizing
     * @param cache_directory Directory for cache storage
     * @return true if initialization successful
     */
    bool initialize(const DeviceProfile& profile, const std::string& cache_directory);

    /**
     * @brief Cache a model
     * @param model_id Unique model identifier
     * @param data Model binary data
     * @param priority Priority score for retention (higher = keep longer)
     * @return true if cached successfully
     */
    bool cacheModel(
        const std::string& model_id,
        const std::vector<uint8_t>& data,
        float priority = 1.0f
    );

    /**
     * @brief Get cached model
     * @param model_id Model identifier
     * @return Model data if cached, nullopt otherwise
     */
    std::optional<std::vector<uint8_t>> getModel(const std::string& model_id);

    /**
     * @brief Check if model is cached
     * @param model_id Model identifier
     * @return true if model is in cache
     */
    bool isCached(const std::string& model_id) const;

    /**
     * @brief Remove model from cache
     * @param model_id Model identifier
     * @return true if model was removed
     */
    bool evictModel(const std::string& model_id);

    /**
     * @brief Evict models to free space
     * @param required_space Space needed in bytes
     * @return Amount of space freed
     */
    size_t evictToFreeSpace(size_t required_space);

    /**
     * @brief Get all cached model IDs
     * @return Vector of cached model IDs
     */
    std::vector<std::string> getCachedModels() const;

    /**
     * @brief Get cache statistics
     * @return Current cache statistics
     */
    CacheStats getStats() const;

    /**
     * @brief Clear entire cache
     */
    void clearCache();

    /**
     * @brief Preload models based on predicted usage
     * @param model_ids Models to preload
     * @param source Source to load from (e.g., URL, local path)
     * @return Number of models successfully preloaded
     */
    size_t preloadModels(
        const std::vector<std::string>& model_ids,
        const std::string& source
    );

    /**
     * @brief Update priority score for model
     * @param model_id Model identifier
     * @param priority New priority score
     */
    void updatePriority(const std::string& model_id, float priority);

    /**
     * @brief Get cache entry metadata
     * @param model_id Model identifier
     * @return Entry metadata if cached
     */
    std::optional<CacheEntry> getEntryInfo(const std::string& model_id) const;

    /**
     * @brief Check if there's enough space for model
     * @param size_bytes Size needed in bytes
     * @return true if space available (possibly after eviction)
     */
    bool hasSpaceFor(size_t size_bytes);

    /**
     * @brief Get current cache size
     * @return Total size in bytes
     */
    size_t getCurrentSize() const;

    /**
     * @brief Get maximum cache size
     * @return Maximum size in bytes
     */
    size_t getMaxSize() const;

    /**
     * @brief Set maximum cache size
     * @param max_size New maximum size in bytes
     */
    void setMaxSize(size_t max_size);

    /**
     * @brief Handle memory pressure
     * @param target_reduction Target size reduction in bytes
     * @return Amount of space freed
     */
    size_t handleMemoryPressure(size_t target_reduction);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Cache warming utility
 *
 * Pre-populates cache with frequently used models
 */
class CacheWarmer {
public:
    /**
     * @brief Warm cache from model registry
     * @param cache_manager Cache manager to warm
     * @param registry_url URL of model registry
     * @param top_n Number of top models to cache
     * @return Number of models warmed
     */
    static size_t warmFromRegistry(
        EdgeCacheManager& cache_manager,
        const std::string& registry_url,
        size_t top_n = 10
    );

    /**
     * @brief Warm cache based on usage history
     * @param cache_manager Cache manager to warm
     * @param history_file Path to usage history
     * @return Number of models warmed
     */
    static size_t warmFromHistory(
        EdgeCacheManager& cache_manager,
        const std::string& history_file
    );
};

/**
 * @brief Predictive preloader
 *
 * Predicts which models will be needed and preloads them
 */
class PredictivePreloader {
public:
    /**
     * @brief Initialize preloader
     * @param cache_manager Cache manager to use
     */
    explicit PredictivePreloader(EdgeCacheManager& cache_manager);

    /**
     * @brief Record model usage for prediction
     * @param model_id Model that was used
     */
    void recordUsage(const std::string& model_id);

    /**
     * @brief Predict next likely models
     * @param n Number of predictions
     * @return Vector of predicted model IDs
     */
    std::vector<std::string> predictNext(size_t n = 3) const;

    /**
     * @brief Preload predicted models
     * @return Number of models preloaded
     */
    size_t preloadPredicted();

    /**
     * @brief Set prediction confidence threshold
     * @param threshold Threshold (0.0 - 1.0)
     */
    void setThreshold(float threshold);

private:
    EdgeCacheManager& cache_manager_;
    float threshold_;
};

} // namespace edge
} // namespace rawrxd

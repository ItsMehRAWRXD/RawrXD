// RawrXD Model Zoo
// Phase AP: Model Zoo & Registry

#pragma once

#include "../registry/model_registry.hpp"
#include <functional>
#include <future>

namespace rawrxd {
namespace zoo {

// Pretrained model info
struct PretrainedModel {
    std::string id;
    std::string name;
    std::string description;
    std::string base_model;
    std::string organization;
    std::string license;
    registry::ModelType type;
    
    // Model specs
    size_t parameter_count;
    size_t context_length;
    std::vector<std::string> languages;
    std::vector<std::string> capabilities;
    
    // Download info
    std::string download_url;
    std::string config_url;
    std::string tokenizer_url;
    size_t size_bytes;
    std::string checksum;
    
    // Metadata
    std::vector<std::string> tags;
    std::vector<std::string> tasks;
    float rating;
    size_t download_count;
    
    PretrainedModel()
        : type(registry::ModelType::LLM)
        , parameter_count(0)
        , context_length(0)
        , size_bytes(0)
        , rating(0.0f)
        , download_count(0) {}
};

// Model collection
struct ModelCollection {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> model_ids;
    std::vector<std::string> tags;
    
    ModelCollection() = default;
};

// Download progress callback
using DownloadProgressCallback = std::function<void(const std::string& model_id, float progress)>;
using DownloadCompleteCallback = std::function<void(const std::string& model_id, bool success)>;

// Zoo configuration
struct ZooConfig {
    std::string zoo_path;
    std::string cache_path;
    std::string remote_url;
    bool enable_remote;
    int max_concurrent_downloads;
    size_t max_cache_size_gb;
    
    ZooConfig()
        : zoo_path("zoo")
        , cache_path("cache/zoo")
        , remote_url("https://zoo.rawrxd.ai")
        , enable_remote(true)
        , max_concurrent_downloads(3)
        , max_cache_size_gb(100) {}
};

// Forward declarations
class ModelZoo;
class ModelDownloader;

/**
 * ModelZoo - Pretrained model catalog
 */
class ModelZoo {
public:
    ModelZoo();
    ~ModelZoo();
    
    // Initialize
    bool initialize(const ZooConfig& config);
    void shutdown();
    
    // Model catalog
    bool addModel(const PretrainedModel& model);
    bool removeModel(const std::string& model_id);
    PretrainedModel getModel(const std::string& model_id) const;
    std::vector<PretrainedModel> getAllModels() const;
    
    // Search and filter
    std::vector<PretrainedModel> search(const std::string& query) const;
    std::vector<PretrainedModel> getModelsByTask(const std::string& task) const;
    std::vector<PretrainedModel> getModelsByLanguage(const std::string& language) const;
    std::vector<PretrainedModel> getModelsByCapability(const std::string& capability) const;
    std::vector<PretrainedModel> getModelsBySize(size_t min_params, size_t max_params) const;
    
    // Collections
    bool createCollection(const ModelCollection& collection);
    bool deleteCollection(const std::string& collection_id);
    ModelCollection getCollection(const std::string& collection_id) const;
    std::vector<ModelCollection> getAllCollections() const;
    std::vector<PretrainedModel> getCollectionModels(const std::string& collection_id) const;
    
    // Popular and featured
    std::vector<PretrainedModel> getPopularModels(size_t count = 10) const;
    std::vector<PretrainedModel> getFeaturedModels() const;
    std::vector<PretrainedModel> getNewReleases(size_t count = 10) const;
    
    // Download management
    bool downloadModel(const std::string& model_id,
                       DownloadProgressCallback progress = nullptr,
                       DownloadCompleteCallback complete = nullptr);
    bool downloadModelAsync(const std::string& model_id,
                            DownloadProgressCallback progress = nullptr,
                            DownloadCompleteCallback complete = nullptr);
    bool isModelDownloaded(const std::string& model_id) const;
    bool deleteDownloadedModel(const std::string& model_id);
    std::string getModelPath(const std::string& model_id) const;
    
    // Batch operations
    bool downloadModels(const std::vector<std::string>& model_ids,
                        DownloadProgressCallback progress = nullptr);
    std::vector<std::string> getDownloadedModels() const;
    
    // Cache management
    void clearCache();
    size_t getCacheSize() const;
    void setMaxCacheSize(size_t size_gb);
    
    // Remote sync
    bool syncWithRemote();
    bool updateCatalog();
    
    // Statistics
    size_t getModelCount() const;
    size_t getDownloadedCount() const;
    
    // Import/Export
    bool exportCatalog(const std::string& path) const;
    bool importCatalog(const std::string& path);
    
private:
    ZooConfig config_;
    std::unordered_map<std::string, PretrainedModel> models_;
    std::unordered_map<std::string, ModelCollection> collections_;
    std::unordered_map<std::string, std::string> downloaded_paths_;
    std::vector<std::string> featured_models_;
    
    mutable std::mutex mutex_;
    bool initialized_;
    
    std::unique_ptr<ModelDownloader> downloader_;
    
    // Internal methods
    bool loadCatalog();
    bool saveCatalog() const;
    std::string getCatalogFile() const;
    std::string getModelCachePath(const std::string& model_id) const;
};

/**
 * ModelDownloader - Async model downloader
 */
class ModelDownloader {
public:
    ModelDownloader();
    ~ModelDownloader();
    
    bool initialize(int max_concurrent);
    void shutdown();
    
    // Download operations
    bool download(const std::string& model_id,
                  const std::string& url,
                  const std::string& destination,
                  DownloadProgressCallback progress = nullptr,
                  DownloadCompleteCallback complete = nullptr);
    
    std::future<bool> downloadAsync(const std::string& model_id,
                                    const std::string& url,
                                    const std::string& destination,
                                    DownloadProgressCallback progress = nullptr);
    
    // Queue management
    void cancelDownload(const std::string& model_id);
    void cancelAllDownloads();
    bool isDownloading(const std::string& model_id) const;
    std::vector<std::string> getActiveDownloads() const;
    
    // Statistics
    size_t getQueueSize() const;
    size_t getActiveCount() const;
    
private:
    int max_concurrent_;
    std::unordered_map<std::string, std::future<bool>> active_downloads_;
    std::queue<std::tuple<std::string, std::string, std::string>> download_queue_;
    mutable std::mutex mutex_;
    bool running_;
    
    void processQueue();
    bool downloadFile(const std::string& url,
                      const std::string& destination,
                      std::function<void(float)> progress);
};

// Global zoo accessor
ModelZoo* getModelZoo();
void setModelZoo(std::unique_ptr<ModelZoo> zoo);

// Utility functions
std::vector<PretrainedModel> getRecommendedModels(const std::string& task);
std::vector<PretrainedModel> getCompatibleModels(const std::string& base_model);
bool compareModelRatings(const PretrainedModel& a, const PretrainedModel& b);
bool compareModelDownloads(const PretrainedModel& a, const PretrainedModel& b);

} // namespace zoo
} // namespace rawrxd

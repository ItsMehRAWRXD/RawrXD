// RawrXD Model Registry
// Phase AP: Model Zoo & Registry

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <mutex>
#include <chrono>

namespace rawrxd {
namespace registry {

// Model status
enum class ModelStatus {
    PENDING,        // Registration pending
    AVAILABLE,      // Available for use
    DOWNLOADING,    // Download in progress
    ERROR,          // Error state
    DEPRECATED,     // Deprecated
    REMOVED         // Removed from registry
};

// Model type
enum class ModelType {
    LLM,            // Large Language Model
    EMBEDDING,      // Embedding model
    CLASSIFIER,     // Classification model
    GENERATIVE,     // Generative model
    MULTIMODAL,     // Multimodal model
    CUSTOM          // Custom model type
};

// Model metadata
struct ModelMetadata {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::string license;
    ModelType type;
    ModelStatus status;
    
    // Technical specs
    size_t parameter_count;
    size_t context_length;
    std::vector<std::string> architectures;
    std::vector<std::string> quantization_types;
    
    // Files
    std::string model_url;
    std::string config_url;
    std::string tokenizer_url;
    size_t model_size_bytes;
    std::string checksum;
    
    // Timestamps
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    
    // Tags and categories
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    
    // Usage stats
    size_t download_count;
    float average_rating;
    
    ModelMetadata()
        : type(ModelType::LLM)
        , status(ModelStatus::PENDING)
        , parameter_count(0)
        , context_length(0)
        , model_size_bytes(0)
        , download_count(0)
        , average_rating(0.0f) {}
};

// Registry configuration
struct RegistryConfig {
    std::string registry_path;
    std::string cache_path;
    std::string remote_url;
    bool enable_remote;
    bool auto_update;
    int update_interval_hours;
    
    RegistryConfig()
        : registry_path("registry")
        , cache_path("cache/models")
        , remote_url("https://models.rawrxd.ai")
        , enable_remote(true)
        , auto_update(true)
        , update_interval_hours(24) {}
};

// Search filters
struct ModelSearchFilter {
    std::string query;
    ModelType type;
    std::vector<std::string> tags;
    std::vector<std::string> categories;
    size_t min_parameters;
    size_t max_parameters;
    std::string author;
    std::string license;
    
    ModelSearchFilter()
        : type(ModelType::CUSTOM)
        , min_parameters(0)
        , max_parameters(SIZE_MAX) {}
};

// Forward declarations
class ModelRegistry;
class VersionManager;

/**
 * ModelRegistry - Central model registry
 */
class ModelRegistry {
public:
    ModelRegistry();
    ~ModelRegistry();
    
    // Initialize registry
    bool initialize(const RegistryConfig& config);
    void shutdown();
    
    // Model registration
    bool registerModel(const ModelMetadata& metadata);
    bool unregisterModel(const std::string& model_id);
    bool updateModel(const std::string& model_id, const ModelMetadata& metadata);
    
    // Model queries
    ModelMetadata getModel(const std::string& model_id) const;
    std::vector<ModelMetadata> getAllModels() const;
    std::vector<ModelMetadata> getModelsByType(ModelType type) const;
    std::vector<ModelMetadata> getModelsByTag(const std::string& tag) const;
    std::vector<ModelMetadata> getModelsByAuthor(const std::string& author) const;
    
    // Search
    std::vector<ModelMetadata> search(const ModelSearchFilter& filter) const;
    std::vector<ModelMetadata> search(const std::string& query) const;
    
    // Version management
    std::vector<std::string> getVersions(const std::string& model_id) const;
    bool setActiveVersion(const std::string& model_id, const std::string& version);
    std::string getActiveVersion(const std::string& model_id) const;
    
    // Status management
    bool setModelStatus(const std::string& model_id, ModelStatus status);
    ModelStatus getModelStatus(const std::string& model_id) const;
    
    // Download management
    bool isModelDownloaded(const std::string& model_id) const;
    std::string getModelPath(const std::string& model_id) const;
    bool setModelPath(const std::string& model_id, const std::string& path);
    
    // Statistics
    size_t getModelCount() const;
    size_t getDownloadedModelCount() const;
    
    // Import/Export
    bool exportRegistry(const std::string& path) const;
    bool importRegistry(const std::string& path);
    
    // Remote sync
    bool syncWithRemote();
    bool checkForUpdates();
    bool downloadModel(const std::string& model_id, 
                       std::function<void(float)> progress_callback = nullptr);
    
    // Cache management
    void clearCache();
    size_t getCacheSize() const;
    
private:
    RegistryConfig config_;
    std::unordered_map<std::string, ModelMetadata> models_;
    std::unordered_map<std::string, std::string> model_paths_;
    std::unordered_map<std::string, std::string> active_versions_;
    
    mutable std::mutex mutex_;
    bool initialized_;
    
    std::unique_ptr<VersionManager> version_manager_;
    
    // Internal methods
    bool loadRegistry();
    bool saveRegistry() const;
    std::string getRegistryFile() const;
    bool matchesFilter(const ModelMetadata& metadata, const ModelSearchFilter& filter) const;
};

/**
 * VersionManager - Model version management
 */
class VersionManager {
public:
    VersionManager();
    
    // Version operations
    bool addVersion(const std::string& model_id, const std::string& version);
    bool removeVersion(const std::string& model_id, const std::string& version);
    std::vector<std::string> getVersions(const std::string& model_id) const;
    
    // Version comparison
    int compareVersions(const std::string& v1, const std::string& v2) const;
    bool isValidVersion(const std::string& version) const;
    std::string getLatestVersion(const std::string& model_id) const;
    
private:
    std::unordered_map<std::string, std::vector<std::string>> versions_;
    mutable std::mutex mutex_;
};

// Global registry accessor
ModelRegistry* getModelRegistry();
void setModelRegistry(std::unique_ptr<ModelRegistry> registry);

// Utility functions
std::string modelTypeToString(ModelType type);
std::string modelStatusToString(ModelStatus status);
ModelType stringToModelType(const std::string& str);
ModelStatus stringToModelStatus(const std::string& str);

} // namespace registry
} // namespace rawrxd

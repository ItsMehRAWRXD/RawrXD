#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace rawrxd {
namespace serving {

// Model version information
struct ModelVersion {
    std::string version_id;
    std::string model_id;
    std::string path;
    std::string format;  // "gguf", "safetensors", "onnx", etc.
    size_t size_bytes;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    std::unordered_map<std::string, std::string> metadata;
    bool is_active;
    
    // Performance characteristics
    struct Performance {
        float avg_latency_ms;
        float throughput_qps;
        float error_rate;
        size_t total_requests;
        size_t successful_requests;
    } performance;
};

// Model entry in registry
struct ModelEntry {
    std::string model_id;
    std::string name;
    std::string description;
    std::vector<std::string> tags;
    std::vector<ModelVersion> versions;
    std::string default_version;
    std::chrono::system_clock::time_point created_at;
    std::unordered_map<std::string, std::string> metadata;
};

// Registry configuration
struct RegistryConfig {
    std::string storage_path = "models/registry";
    size_t max_models = 100;
    size_t max_versions_per_model = 10;
    bool enable_caching = true;
    std::chrono::seconds cache_ttl{300};
    bool persist_registry = true;
};

// Model registry for multi-model serving
class ModelRegistry {
public:
    explicit ModelRegistry(const RegistryConfig& config = {});
    ~ModelRegistry();
    
    // Model management
    bool registerModel(const ModelEntry& entry);
    bool unregisterModel(const std::string& model_id);
    std::optional<ModelEntry> getModel(const std::string& model_id) const;
    std::vector<ModelEntry> listModels(const std::vector<std::string>& tags = {}) const;
    
    // Version management
    bool addVersion(const std::string& model_id, const ModelVersion& version);
    bool removeVersion(const std::string& model_id, const std::string& version_id);
    bool setDefaultVersion(const std::string& model_id, const std::string& version_id);
    std::optional<ModelVersion> getVersion(const std::string& model_id, 
                                           const std::string& version_id = "") const;
    std::vector<ModelVersion> listVersions(const std::string& model_id) const;
    
    // Performance tracking
    void updatePerformance(const std::string& model_id, 
                          const std::string& version_id,
                          const ModelVersion::Performance& perf);
    
    // Search and discovery
    std::vector<ModelEntry> search(const std::string& query) const;
    std::vector<ModelEntry> findByCapability(const std::string& capability) const;
    
    // Import/Export
    bool exportRegistry(const std::string& path) const;
    bool importRegistry(const std::string& path);
    
    // Statistics
    struct Stats {
        size_t total_models;
        size_t total_versions;
        size_t active_models;
        size_t cache_hits;
        size_t cache_misses;
    };
    Stats getStats() const;
    
    // Event callbacks
    using ModelCallback = std::function<void(const ModelEntry&)>;
    using VersionCallback = std::function<void(const std::string&, const ModelVersion&)>;
    
    void onModelRegistered(ModelCallback callback);
    void onModelUnregistered(ModelCallback callback);
    void onVersionAdded(VersionCallback callback);
    void onVersionRemoved(VersionCallback callback);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Global registry instance
ModelRegistry& getGlobalRegistry();

} // namespace serving
} // namespace rawrxd

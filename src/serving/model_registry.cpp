#include "model_registry.hpp"
#include <fstream>
#include <algorithm>
#include <nlohmann/json.hpp>

namespace rawrxd {
namespace serving {

using json = nlohmann::json;

class ModelRegistry::Impl {
public:
    RegistryConfig config_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, ModelEntry> models_;
    mutable std::unordered_map<std::string, std::pair<ModelEntry, std::chrono::system_clock::time_point>> cache_;
    
    // Callbacks
    std::vector<ModelCallback> on_registered_;
    std::vector<ModelCallback> on_unregistered_;
    std::vector<VersionCallback> on_version_added_;
    std::vector<VersionCallback> on_version_removed_;
    
    // Stats
    mutable std::atomic<size_t> cache_hits_{0};
    mutable std::atomic<size_t> cache_misses_{0};
    
    explicit Impl(const RegistryConfig& config) : config_(config) {
        if (config_.persist_registry) {
            loadFromDisk();
        }
    }
    
    ~Impl() {
        if (config_.persist_registry) {
            saveToDisk();
        }
    }
    
    void loadFromDisk() {
        std::ifstream file(config_.storage_path + "/registry.json");
        if (!file.is_open()) return;
        
        try {
            json j;
            file >> j;
            
            for (const auto& item : j["models"]) {
                ModelEntry entry;
                entry.model_id = item["model_id"];
                entry.name = item["name"];
                entry.description = item["description"];
                entry.tags = item["tags"].get<std::vector<std::string>>();
                entry.default_version = item["default_version"];
                entry.metadata = item["metadata"].get<std::unordered_map<std::string, std::string>>();
                
                for (const auto& v : item["versions"]) {
                    ModelVersion version;
                    version.version_id = v["version_id"];
                    version.model_id = v["model_id"];
                    version.path = v["path"];
                    version.format = v["format"];
                    version.size_bytes = v["size_bytes"];
                    version.is_active = v["is_active"];
                    version.metadata = v["metadata"].get<std::unordered_map<std::string, std::string>>();
                    entry.versions.push_back(version);
                }
                
                models_[entry.model_id] = entry;
            }
        } catch (...) {
            // Ignore load errors
        }
    }
    
    void saveToDisk() {
        std::ofstream file(config_.storage_path + "/registry.json");
        if (!file.is_open()) return;
        
        json j;
        j["models"] = json::array();
        
        for (const auto& [id, entry] : models_) {
            json item;
            item["model_id"] = entry.model_id;
            item["name"] = entry.name;
            item["description"] = entry.description;
            item["tags"] = entry.tags;
            item["default_version"] = entry.default_version;
            item["metadata"] = entry.metadata;
            
            item["versions"] = json::array();
            for (const auto& v : entry.versions) {
                json ver;
                ver["version_id"] = v.version_id;
                ver["model_id"] = v.model_id;
                ver["path"] = v.path;
                ver["format"] = v.format;
                ver["size_bytes"] = v.size_bytes;
                ver["is_active"] = v.is_active;
                ver["metadata"] = v.metadata;
                item["versions"].push_back(ver);
            }
            
            j["models"].push_back(item);
        }
        
        file << j.dump(2);
    }
    
    void invalidateCache(const std::string& model_id) {
        cache_.erase(model_id);
    }
};

ModelRegistry::ModelRegistry(const RegistryConfig& config) 
    : impl_(std::make_unique<Impl>(config)) {}

ModelRegistry::~ModelRegistry() = default;

bool ModelRegistry::registerModel(const ModelEntry& entry) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    if (impl_->models_.size() >= impl_->config_.max_models) {
        return false;
    }
    
    impl_->models_[entry.model_id] = entry;
    impl_->invalidateCache(entry.model_id);
    
    for (auto& cb : impl_->on_registered_) {
        cb(entry);
    }
    
    if (impl_->config_.persist_registry) {
        impl_->saveToDisk();
    }
    
    return true;
}

bool ModelRegistry::unregisterModel(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return false;
    }
    
    auto entry = it->second;
    impl_->models_.erase(it);
    impl_->invalidateCache(model_id);
    
    for (auto& cb : impl_->on_unregistered_) {
        cb(entry);
    }
    
    if (impl_->config_.persist_registry) {
        impl_->saveToDisk();
    }
    
    return true;
}

std::optional<ModelEntry> ModelRegistry::getModel(const std::string& model_id) const {
    // Check cache first
    if (impl_->config_.enable_caching) {
        std::lock_guard<std::mutex> lock(impl_->mutex_);
        auto it = impl_->cache_.find(model_id);
        if (it != impl_->cache_.end()) {
            auto age = std::chrono::system_clock::now() - it->second.second;
            if (age < impl_->config_.cache_ttl) {
                impl_->cache_hits_++;
                return it->second.first;
            }
        }
        impl_->cache_misses_++;
    }
    
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return std::nullopt;
    }
    
    // Update cache
    if (impl_->config_.enable_caching) {
        impl_->cache_[model_id] = {it->second, std::chrono::system_clock::now()};
    }
    
    return it->second;
}

std::vector<ModelEntry> ModelRegistry::listModels(const std::vector<std::string>& tags) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<ModelEntry> result;
    for (const auto& [id, entry] : impl_->models_) {
        if (tags.empty()) {
            result.push_back(entry);
        } else {
            // Check if entry has any of the specified tags
            for (const auto& tag : tags) {
                if (std::find(entry.tags.begin(), entry.tags.end(), tag) != entry.tags.end()) {
                    result.push_back(entry);
                    break;
                }
            }
        }
    }
    
    return result;
}

bool ModelRegistry::addVersion(const std::string& model_id, const ModelVersion& version) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return false;
    }
    
    if (it->second.versions.size() >= impl_->config_.max_versions_per_model) {
        return false;
    }
    
    it->second.versions.push_back(version);
    impl_->invalidateCache(model_id);
    
    for (auto& cb : impl_->on_version_added_) {
        cb(model_id, version);
    }
    
    if (impl_->config_.persist_registry) {
        impl_->saveToDisk();
    }
    
    return true;
}

bool ModelRegistry::removeVersion(const std::string& model_id, const std::string& version_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return false;
    }
    
    auto& versions = it->second.versions;
    auto vit = std::find_if(versions.begin(), versions.end(),
        [&version_id](const ModelVersion& v) { return v.version_id == version_id; });
    
    if (vit == versions.end()) {
        return false;
    }
    
    auto version = *vit;
    versions.erase(vit);
    impl_->invalidateCache(model_id);
    
    for (auto& cb : impl_->on_version_removed_) {
        cb(model_id, version);
    }
    
    if (impl_->config_.persist_registry) {
        impl_->saveToDisk();
    }
    
    return true;
}

bool ModelRegistry::setDefaultVersion(const std::string& model_id, const std::string& version_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return false;
    }
    
    auto& versions = it->second.versions;
    auto vit = std::find_if(versions.begin(), versions.end(),
        [&version_id](const ModelVersion& v) { return v.version_id == version_id; });
    
    if (vit == versions.end()) {
        return false;
    }
    
    it->second.default_version = version_id;
    impl_->invalidateCache(model_id);
    
    if (impl_->config_.persist_registry) {
        impl_->saveToDisk();
    }
    
    return true;
}

std::optional<ModelVersion> ModelRegistry::getVersion(const std::string& model_id,
                                                       const std::string& version_id) const {
    auto entry = getModel(model_id);
    if (!entry) {
        return std::nullopt;
    }
    
    std::string vid = version_id.empty() ? entry->default_version : version_id;
    
    for (const auto& v : entry->versions) {
        if (v.version_id == vid) {
            return v;
        }
    }
    
    return std::nullopt;
}

std::vector<ModelVersion> ModelRegistry::listVersions(const std::string& model_id) const {
    auto entry = getModel(model_id);
    if (!entry) {
        return {};
    }
    return entry->versions;
}

void ModelRegistry::updatePerformance(const std::string& model_id,
                                       const std::string& version_id,
                                       const ModelVersion::Performance& perf) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    auto it = impl_->models_.find(model_id);
    if (it == impl_->models_.end()) {
        return;
    }
    
    for (auto& v : it->second.versions) {
        if (v.version_id == version_id) {
            v.performance = perf;
            break;
        }
    }
}

std::vector<ModelEntry> ModelRegistry::search(const std::string& query) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<ModelEntry> result;
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    for (const auto& [id, entry] : impl_->models_) {
        std::string name_lower = entry.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        
        std::string desc_lower = entry.description;
        std::transform(desc_lower.begin(), desc_lower.end(), desc_lower.begin(), ::tolower);
        
        if (name_lower.find(lower_query) != std::string::npos ||
            desc_lower.find(lower_query) != std::string::npos ||
            entry.model_id.find(lower_query) != std::string::npos) {
            result.push_back(entry);
        }
    }
    
    return result;
}

std::vector<ModelEntry> ModelRegistry::findByCapability(const std::string& capability) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::vector<ModelEntry> result;
    for (const auto& [id, entry] : impl_->models_) {
        auto it = entry.metadata.find("capabilities");
        if (it != entry.metadata.end()) {
            if (it->second.find(capability) != std::string::npos) {
                result.push_back(entry);
            }
        }
    }
    
    return result;
}

bool ModelRegistry::exportRegistry(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    json j;
    j["models"] = json::array();
    
    for (const auto& [id, entry] : impl_->models_) {
        json item;
        item["model_id"] = entry.model_id;
        item["name"] = entry.name;
        item["description"] = entry.description;
        item["tags"] = entry.tags;
        item["default_version"] = entry.default_version;
        item["metadata"] = entry.metadata;
        
        item["versions"] = json::array();
        for (const auto& v : entry.versions) {
            json ver;
            ver["version_id"] = v.version_id;
            ver["model_id"] = v.model_id;
            ver["path"] = v.path;
            ver["format"] = v.format;
            ver["size_bytes"] = v.size_bytes;
            ver["is_active"] = v.is_active;
            ver["metadata"] = v.metadata;
            item["versions"].push_back(ver);
        }
        
        j["models"].push_back(item);
    }
    
    file << j.dump(2);
    return true;
}

bool ModelRegistry::importRegistry(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    try {
        json j;
        file >> j;
        
        impl_->models_.clear();
        impl_->cache_.clear();
        
        for (const auto& item : j["models"]) {
            ModelEntry entry;
            entry.model_id = item["model_id"];
            entry.name = item["name"];
            entry.description = item["description"];
            entry.tags = item["tags"].get<std::vector<std::string>>();
            entry.default_version = item["default_version"];
            entry.metadata = item["metadata"].get<std::unordered_map<std::string, std::string>>();
            
            for (const auto& v : item["versions"]) {
                ModelVersion version;
                version.version_id = v["version_id"];
                version.model_id = v["model_id"];
                version.path = v["path"];
                version.format = v["format"];
                version.size_bytes = v["size_bytes"];
                version.is_active = v["is_active"];
                version.metadata = v["metadata"].get<std::unordered_map<std::string, std::string>>();
                entry.versions.push_back(version);
            }
            
            impl_->models_[entry.model_id] = entry;
        }
        
        if (impl_->config_.persist_registry) {
            impl_->saveToDisk();
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

ModelRegistry::Stats ModelRegistry::getStats() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    
    Stats stats{};
    stats.total_models = impl_->models_.size();
    stats.cache_hits = impl_->cache_hits_.load();
    stats.cache_misses = impl_->cache_misses_.load();
    
    for (const auto& [id, entry] : impl_->models_) {
        stats.total_versions += entry.versions.size();
        if (entry.versions.empty() || 
            std::any_of(entry.versions.begin(), entry.versions.end(),
                [](const ModelVersion& v) { return v.is_active; })) {
            stats.active_models++;
        }
    }
    
    return stats;
}

void ModelRegistry::onModelRegistered(ModelCallback callback) {
    impl_->on_registered_.push_back(callback);
}

void ModelRegistry::onModelUnregistered(ModelCallback callback) {
    impl_->on_unregistered_.push_back(callback);
}

void ModelRegistry::onVersionAdded(VersionCallback callback) {
    impl_->on_version_added_.push_back(callback);
}

void ModelRegistry::onVersionRemoved(VersionCallback callback) {
    impl_->on_version_removed_.push_back(callback);
}

// Global registry instance
ModelRegistry& getGlobalRegistry() {
    static ModelRegistry registry;
    return registry;
}

} // namespace serving
} // namespace rawrxd

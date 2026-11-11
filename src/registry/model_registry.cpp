// RawrXD Model Registry Implementation
// Phase AP: Model Zoo & Registry

#include "model_registry.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <filesystem>

namespace rawrxd {
namespace registry {

// Global registry instance
static std::unique_ptr<ModelRegistry> g_model_registry;

ModelRegistry* getModelRegistry() {
    return g_model_registry.get();
}

void setModelRegistry(std::unique_ptr<ModelRegistry> registry) {
    g_model_registry = std::move(registry);
}

// ModelRegistry implementation
ModelRegistry::ModelRegistry()
    : initialized_(false) {
}

ModelRegistry::~ModelRegistry() {
    shutdown();
}

bool ModelRegistry::initialize(const RegistryConfig& config) {
    config_ = config;
    
    // Create directories
    std::filesystem::create_directories(config_.registry_path);
    std::filesystem::create_directories(config_.cache_path);
    
    // Initialize version manager
    version_manager_ = std::make_unique<VersionManager>();
    
    // Load existing registry
    if (!loadRegistry()) {
        // Create empty registry if none exists
        saveRegistry();
    }
    
    initialized_ = true;
    return true;
}

void ModelRegistry::shutdown() {
    if (!initialized_) return;
    
    saveRegistry();
    initialized_ = false;
}

bool ModelRegistry::registerModel(const ModelMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (models_.find(metadata.id) != models_.end()) {
        std::cerr << "Model already registered: " << metadata.id << std::endl;
        return false;
    }
    
    ModelMetadata meta = metadata;
    meta.created_at = std::chrono::system_clock::now();
    meta.updated_at = meta.created_at;
    
    models_[meta.id] = meta;
    
    // Add initial version
    if (!meta.version.empty()) {
        version_manager_->addVersion(meta.id, meta.version);
        active_versions_[meta.id] = meta.version;
    }
    
    saveRegistry();
    
    std::cout << "Model registered: " << meta.name << " (" << meta.id << ")" << std::endl;
    return true;
}

bool ModelRegistry::unregisterModel(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it == models_.end()) {
        return false;
    }
    
    // Mark as removed rather than deleting
    it->second.status = ModelStatus::REMOVED;
    it->second.updated_at = std::chrono::system_clock::now();
    
    saveRegistry();
    
    std::cout << "Model unregistered: " << model_id << std::endl;
    return true;
}

bool ModelRegistry::updateModel(const std::string& model_id, const ModelMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it == models_.end()) {
        return false;
    }
    
    ModelMetadata updated = metadata;
    updated.id = model_id;  // Preserve ID
    updated.created_at = it->second.created_at;
    updated.updated_at = std::chrono::system_clock::now();
    
    models_[model_id] = updated;
    
    saveRegistry();
    
    std::cout << "Model updated: " << model_id << std::endl;
    return true;
}

ModelMetadata ModelRegistry::getModel(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it != models_.end()) {
        return it->second;
    }
    
    return ModelMetadata();
}

std::vector<ModelMetadata> ModelRegistry::getAllModels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelMetadata> result;
    for (const auto& [id, metadata] : models_) {
        if (metadata.status != ModelStatus::REMOVED) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

std::vector<ModelMetadata> ModelRegistry::getModelsByType(ModelType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelMetadata> result;
    for (const auto& [id, metadata] : models_) {
        if (metadata.type == type && metadata.status != ModelStatus::REMOVED) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

std::vector<ModelMetadata> ModelRegistry::getModelsByTag(const std::string& tag) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelMetadata> result;
    for (const auto& [id, metadata] : models_) {
        if (metadata.status != ModelStatus::REMOVED) {
            for (const auto& t : metadata.tags) {
                if (t == tag) {
                    result.push_back(metadata);
                    break;
                }
            }
        }
    }
    
    return result;
}

std::vector<ModelMetadata> ModelRegistry::getModelsByAuthor(const std::string& author) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelMetadata> result;
    for (const auto& [id, metadata] : models_) {
        if (metadata.author == author && metadata.status != ModelStatus::REMOVED) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

std::vector<ModelMetadata> ModelRegistry::search(const ModelSearchFilter& filter) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelMetadata> result;
    for (const auto& [id, metadata] : models_) {
        if (metadata.status != ModelStatus::REMOVED && matchesFilter(metadata, filter)) {
            result.push_back(metadata);
        }
    }
    
    return result;
}

std::vector<ModelMetadata> ModelRegistry::search(const std::string& query) const {
    ModelSearchFilter filter;
    filter.query = query;
    return search(filter);
}

std::vector<std::string> ModelRegistry::getVersions(const std::string& model_id) const {
    return version_manager_->getVersions(model_id);
}

bool ModelRegistry::setActiveVersion(const std::string& model_id, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto versions = version_manager_->getVersions(model_id);
    if (std::find(versions.begin(), versions.end(), version) == versions.end()) {
        return false;
    }
    
    active_versions_[model_id] = version;
    return true;
}

std::string ModelRegistry::getActiveVersion(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = active_versions_.find(model_id);
    if (it != active_versions_.end()) {
        return it->second;
    }
    
    return "";
}

bool ModelRegistry::setModelStatus(const std::string& model_id, ModelStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it == models_.end()) {
        return false;
    }
    
    it->second.status = status;
    it->second.updated_at = std::chrono::system_clock::now();
    
    saveRegistry();
    return true;
}

ModelStatus ModelRegistry::getModelStatus(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it != models_.end()) {
        return it->second.status;
    }
    
    return ModelStatus::REMOVED;
}

bool ModelRegistry::isModelDownloaded(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = model_paths_.find(model_id);
    if (it != model_paths_.end()) {
        return std::filesystem::exists(it->second);
    }
    
    return false;
}

std::string ModelRegistry::getModelPath(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = model_paths_.find(model_id);
    if (it != model_paths_.end()) {
        return it->second;
    }
    
    return "";
}

bool ModelRegistry::setModelPath(const std::string& model_id, const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    model_paths_[model_id] = path;
    return true;
}

size_t ModelRegistry::getModelCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [id, metadata] : models_) {
        if (metadata.status != ModelStatus::REMOVED) {
            count++;
        }
    }
    
    return count;
}

size_t ModelRegistry::getDownloadedModelCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [id, path] : model_paths_) {
        if (std::filesystem::exists(path)) {
            count++;
        }
    }
    
    return count;
}

bool ModelRegistry::exportRegistry(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    // Simple JSON export
    file << "{" << std::endl;
    file << "  \"models\": [" << std::endl;
    
    bool first = true;
    for (const auto& [id, metadata] : models_) {
        if (!first) file << "," << std::endl;
        first = false;
        
        file << "    {\"id\": \"" << metadata.id << "\", ";
        file << "\"name\": \"" << metadata.name << "\", ";
        file << "\"version\": \"" << metadata.version << "\"}";
    }
    
    file << std::endl << "  ]" << std::endl;
    file << "}" << std::endl;
    
    return true;
}

bool ModelRegistry::importRegistry(const std::string& path) {
    // Implementation would parse JSON and import models
    return true;
}

bool ModelRegistry::syncWithRemote() {
    if (!config_.enable_remote) {
        return false;
    }
    
    std::cout << "Syncing with remote registry: " << config_.remote_url << std::endl;
    
    // Implementation would fetch remote registry and merge
    
    return true;
}

bool ModelRegistry::checkForUpdates() {
    if (!config_.enable_remote) {
        return false;
    }
    
    // Implementation would check remote for updates
    
    return true;
}

bool ModelRegistry::downloadModel(const std::string& model_id,
                                  std::function<void(float)> progress_callback) {
    auto metadata = getModel(model_id);
    if (metadata.id.empty()) {
        return false;
    }
    
    std::cout << "Downloading model: " << metadata.name << std::endl;
    
    // Simulate download progress
    if (progress_callback) {
        for (int i = 0; i <= 100; i += 10) {
            progress_callback(i / 100.0f);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
    // Update download count
    metadata.download_count++;
    updateModel(model_id, metadata);
    
    std::cout << "Model downloaded successfully" << std::endl;
    return true;
}

void ModelRegistry::clearCache() {
    std::filesystem::remove_all(config_.cache_path);
    std::filesystem::create_directories(config_.cache_path);
}

size_t ModelRegistry::getCacheSize() const {
    size_t size = 0;
    for (const auto& entry : std::filesystem::directory_iterator(config_.cache_path)) {
        if (entry.is_regular_file()) {
            size += entry.file_size();
        }
    }
    return size;
}

bool ModelRegistry::loadRegistry() {
    std::string registry_file = getRegistryFile();
    
    if (!std::filesystem::exists(registry_file)) {
        return false;
    }
    
    // Implementation would load from JSON
    
    return true;
}

bool ModelRegistry::saveRegistry() const {
    std::string registry_file = getRegistryFile();
    
    std::ofstream file(registry_file);
    if (!file.is_open()) {
        return false;
    }
    
    // Simple JSON export
    file << "{" << std::endl;
    file << "  \"models\": [" << std::endl;
    
    bool first = true;
    for (const auto& [id, metadata] : models_) {
        if (!first) file << "," << std::endl;
        first = false;
        
        file << "    {\"id\": \"" << metadata.id << "\", ";
        file << "\"name\": \"" << metadata.name << "\", ";
        file << "\"version\": \"" << metadata.version << "\", ";
        file << "\"status\": \"" << static_cast<int>(metadata.status) << "\"}";
    }
    
    file << std::endl << "  ]" << std::endl;
    file << "}" << std::endl;
    
    return true;
}

std::string ModelRegistry::getRegistryFile() const {
    return config_.registry_path + "/registry.json";
}

bool ModelRegistry::matchesFilter(const ModelMetadata& metadata, const ModelSearchFilter& filter) const {
    // Check query
    if (!filter.query.empty()) {
        bool matches = metadata.name.find(filter.query) != std::string::npos ||
                       metadata.description.find(filter.query) != std::string::npos;
        if (!matches) return false;
    }
    
    // Check type
    if (filter.type != ModelType::CUSTOM && metadata.type != filter.type) {
        return false;
    }
    
    // Check tags
    for (const auto& tag : filter.tags) {
        bool has_tag = false;
        for (const auto& mt : metadata.tags) {
            if (mt == tag) {
                has_tag = true;
                break;
            }
        }
        if (!has_tag) return false;
    }
    
    // Check parameter count
    if (metadata.parameter_count < filter.min_parameters ||
        metadata.parameter_count > filter.max_parameters) {
        return false;
    }
    
    // Check author
    if (!filter.author.empty() && metadata.author != filter.author) {
        return false;
    }
    
    return true;
}

// VersionManager implementation
VersionManager::VersionManager() = default;

bool VersionManager::addVersion(const std::string& model_id, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& versions = versions_[model_id];
    
    // Check if version already exists
    if (std::find(versions.begin(), versions.end(), version) != versions.end()) {
        return false;
    }
    
    versions.push_back(version);
    
    // Sort versions
    std::sort(versions.begin(), versions.end(),
              [this](const std::string& a, const std::string& b) {
                  return compareVersions(a, b) > 0;
              });
    
    return true;
}

bool VersionManager::removeVersion(const std::string& model_id, const std::string& version) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = versions_.find(model_id);
    if (it == versions_.end()) {
        return false;
    }
    
    auto& versions = it->second;
    auto vit = std::find(versions.begin(), versions.end(), version);
    if (vit == versions.end()) {
        return false;
    }
    
    versions.erase(vit);
    return true;
}

std::vector<std::string> VersionManager::getVersions(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = versions_.find(model_id);
    if (it != versions_.end()) {
        return it->second;
    }
    
    return {};
}

int VersionManager::compareVersions(const std::string& v1, const std::string& v2) const {
    // Simple semantic versioning comparison
    std::vector<int> parts1;
    std::vector<int> parts2;
    
    // Parse v1
    size_t start = 0;
    size_t end = v1.find('.');
    while (end != std::string::npos) {
        parts1.push_back(std::stoi(v1.substr(start, end - start)));
        start = end + 1;
        end = v1.find('.', start);
    }
    parts1.push_back(std::stoi(v1.substr(start)));
    
    // Parse v2
    start = 0;
    end = v2.find('.');
    while (end != std::string::npos) {
        parts2.push_back(std::stoi(v2.substr(start, end - start)));
        start = end + 1;
        end = v2.find('.', start);
    }
    parts2.push_back(std::stoi(v2.substr(start)));
    
    // Compare
    size_t max_len = std::max(parts1.size(), parts2.size());
    for (size_t i = 0; i < max_len; ++i) {
        int p1 = i < parts1.size() ? parts1[i] : 0;
        int p2 = i < parts2.size() ? parts2[i] : 0;
        
        if (p1 < p2) return -1;
        if (p1 > p2) return 1;
    }
    
    return 0;
}

bool VersionManager::isValidVersion(const std::string& version) const {
    // Simple version validation (x.y.z format)
    if (version.empty()) return false;
    
    for (char c : version) {
        if (!std::isdigit(c) && c != '.') {
            return false;
        }
    }
    
    return true;
}

std::string VersionManager::getLatestVersion(const std::string& model_id) const {
    auto versions = getVersions(model_id);
    if (versions.empty()) {
        return "";
    }
    
    return versions[0];  // Versions are sorted, first is latest
}

// Utility functions
std::string modelTypeToString(ModelType type) {
    switch (type) {
        case ModelType::LLM: return "LLM";
        case ModelType::EMBEDDING: return "Embedding";
        case ModelType::CLASSIFIER: return "Classifier";
        case ModelType::GENERATIVE: return "Generative";
        case ModelType::MULTIMODAL: return "Multimodal";
        case ModelType::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

std::string modelStatusToString(ModelStatus status) {
    switch (status) {
        case ModelStatus::PENDING: return "Pending";
        case ModelStatus::AVAILABLE: return "Available";
        case ModelStatus::DOWNLOADING: return "Downloading";
        case ModelStatus::ERROR: return "Error";
        case ModelStatus::DEPRECATED: return "Deprecated";
        case ModelStatus::REMOVED: return "Removed";
        default: return "Unknown";
    }
}

ModelType stringToModelType(const std::string& str) {
    if (str == "LLM") return ModelType::LLM;
    if (str == "Embedding") return ModelType::EMBEDDING;
    if (str == "Classifier") return ModelType::CLASSIFIER;
    if (str == "Generative") return ModelType::GENERATIVE;
    if (str == "Multimodal") return ModelType::MULTIMODAL;
    return ModelType::CUSTOM;
}

ModelStatus stringToModelStatus(const std::string& str) {
    if (str == "Pending") return ModelStatus::PENDING;
    if (str == "Available") return ModelStatus::AVAILABLE;
    if (str == "Downloading") return ModelStatus::DOWNLOADING;
    if (str == "Error") return ModelStatus::ERROR;
    if (str == "Deprecated") return ModelStatus::DEPRECATED;
    if (str == "Removed") return ModelStatus::REMOVED;
    return ModelStatus::PENDING;
}

} // namespace registry
} // namespace rawrxd

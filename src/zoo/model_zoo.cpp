// RawrXD Model Zoo Implementation
// Phase AP: Model Zoo & Registry

#include "model_zoo.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <thread>

namespace rawrxd {
namespace zoo {

// Global zoo instance
static std::unique_ptr<ModelZoo> g_model_zoo;

ModelZoo* getModelZoo() {
    return g_model_zoo.get();
}

void setModelZoo(std::unique_ptr<ModelZoo> zoo) {
    g_model_zoo = std::move(zoo);
}

// ModelZoo implementation
ModelZoo::ModelZoo()
    : initialized_(false) {
}

ModelZoo::~ModelZoo() {
    shutdown();
}

bool ModelZoo::initialize(const ZooConfig& config) {
    config_ = config;
    
    // Create directories
    std::filesystem::create_directories(config_.zoo_path);
    std::filesystem::create_directories(config_.cache_path);
    
    // Initialize downloader
    downloader_ = std::make_unique<ModelDownloader>();
    downloader_->initialize(config_.max_concurrent_downloads);
    
    // Load existing catalog
    if (!loadCatalog()) {
        // Create empty catalog if none exists
        saveCatalog();
    }
    
    // Add default featured models
    featured_models_ = {
        "llama-3-8b",
        "qwen2.5-7b",
        "mistral-7b",
        "phi-4"
    };
    
    initialized_ = true;
    return true;
}

void ModelZoo::shutdown() {
    if (!initialized_) return;
    
    if (downloader_) {
        downloader_->shutdown();
    }
    
    saveCatalog();
    initialized_ = false;
}

bool ModelZoo::addModel(const PretrainedModel& model) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (models_.find(model.id) != models_.end()) {
        std::cerr << "Model already exists: " << model.id << std::endl;
        return false;
    }
    
    models_[model.id] = model;
    saveCatalog();
    
    std::cout << "Model added to zoo: " << model.name << " (" << model.id << ")" << std::endl;
    return true;
}

bool ModelZoo::removeModel(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it == models_.end()) {
        return false;
    }
    
    models_.erase(it);
    saveCatalog();
    
    std::cout << "Model removed from zoo: " << model_id << std::endl;
    return true;
}

PretrainedModel ModelZoo::getModel(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(model_id);
    if (it != models_.end()) {
        return it->second;
    }
    
    return PretrainedModel();
}

std::vector<PretrainedModel> ModelZoo::getAllModels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& [id, model] : models_) {
        result.push_back(model);
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::search(const std::string& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);
    
    for (const auto& [id, model] : models_) {
        std::string name_lower = model.name;
        std::string desc_lower = model.description;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
        std::transform(desc_lower.begin(), desc_lower.end(), desc_lower.begin(), ::tolower);
        
        if (name_lower.find(lower_query) != std::string::npos ||
            desc_lower.find(lower_query) != std::string::npos ||
            model.id.find(query) != std::string::npos) {
            result.push_back(model);
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getModelsByTask(const std::string& task) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& [id, model] : models_) {
        for (const auto& t : model.tasks) {
            if (t == task) {
                result.push_back(model);
                break;
            }
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getModelsByLanguage(const std::string& language) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& [id, model] : models_) {
        for (const auto& lang : model.languages) {
            if (lang == language) {
                result.push_back(model);
                break;
            }
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getModelsByCapability(const std::string& capability) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& [id, model] : models_) {
        for (const auto& cap : model.capabilities) {
            if (cap == capability) {
                result.push_back(model);
                break;
            }
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getModelsBySize(size_t min_params, size_t max_params) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& [id, model] : models_) {
        if (model.parameter_count >= min_params && model.parameter_count <= max_params) {
            result.push_back(model);
        }
    }
    
    return result;
}

bool ModelZoo::createCollection(const ModelCollection& collection) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (collections_.find(collection.id) != collections_.end()) {
        return false;
    }
    
    collections_[collection.id] = collection;
    saveCatalog();
    
    std::cout << "Collection created: " << collection.name << std::endl;
    return true;
}

bool ModelZoo::deleteCollection(const std::string& collection_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = collections_.find(collection_id);
    if (it == collections_.end()) {
        return false;
    }
    
    collections_.erase(it);
    saveCatalog();
    
    std::cout << "Collection deleted: " << collection_id << std::endl;
    return true;
}

ModelCollection ModelZoo::getCollection(const std::string& collection_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = collections_.find(collection_id);
    if (it != collections_.end()) {
        return it->second;
    }
    
    return ModelCollection();
}

std::vector<ModelCollection> ModelZoo::getAllCollections() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<ModelCollection> result;
    for (const auto& [id, collection] : collections_) {
        result.push_back(collection);
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getCollectionModels(const std::string& collection_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    auto it = collections_.find(collection_id);
    if (it == collections_.end()) {
        return result;
    }
    
    for (const auto& model_id : it->second.model_ids) {
        auto mit = models_.find(model_id);
        if (mit != models_.end()) {
            result.push_back(mit->second);
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getPopularModels(size_t count) const {
    auto all = getAllModels();
    
    // Sort by download count
    std::sort(all.begin(), all.end(),
              [](const PretrainedModel& a, const PretrainedModel& b) {
                  return a.download_count > b.download_count;
              });
    
    if (all.size() > count) {
        all.resize(count);
    }
    
    return all;
}

std::vector<PretrainedModel> ModelZoo::getFeaturedModels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PretrainedModel> result;
    for (const auto& model_id : featured_models_) {
        auto it = models_.find(model_id);
        if (it != models_.end()) {
            result.push_back(it->second);
        }
    }
    
    return result;
}

std::vector<PretrainedModel> ModelZoo::getNewReleases(size_t count) const {
    // For now, return first N models (in real implementation would sort by release date)
    auto all = getAllModels();
    
    if (all.size() > count) {
        all.resize(count);
    }
    
    return all;
}

bool ModelZoo::downloadModel(const std::string& model_id,
                              DownloadProgressCallback progress,
                              DownloadCompleteCallback complete) {
    auto model = getModel(model_id);
    if (model.id.empty()) {
        std::cerr << "Model not found: " << model_id << std::endl;
        return false;
    }
    
    std::string dest_path = getModelCachePath(model_id);
    std::filesystem::create_directories(std::filesystem::path(dest_path).parent_path());
    
    std::cout << "Downloading model: " << model.name << std::endl;
    
    // Simulate download
    if (progress) {
        for (int i = 0; i <= 100; i += 10) {
            progress(model_id, i / 100.0f);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    // Update download count
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = models_.find(model_id);
        if (it != models_.end()) {
            it->second.download_count++;
        }
        downloaded_paths_[model_id] = dest_path;
    }
    
    if (complete) {
        complete(model_id, true);
    }
    
    std::cout << "Model downloaded: " << model_id << std::endl;
    return true;
}

bool ModelZoo::downloadModelAsync(const std::string& model_id,
                                   DownloadProgressCallback progress,
                                   DownloadCompleteCallback complete) {
    // Start async download
    std::thread([this, model_id, progress, complete]() {
        downloadModel(model_id, progress, complete);
    }).detach();
    
    return true;
}

bool ModelZoo::isModelDownloaded(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = downloaded_paths_.find(model_id);
    if (it != downloaded_paths_.end()) {
        return std::filesystem::exists(it->second);
    }
    
    return false;
}

bool ModelZoo::deleteDownloadedModel(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = downloaded_paths_.find(model_id);
    if (it == downloaded_paths_.end()) {
        return false;
    }
    
    if (std::filesystem::exists(it->second)) {
        std::filesystem::remove_all(it->second);
    }
    
    downloaded_paths_.erase(it);
    
    std::cout << "Downloaded model deleted: " << model_id << std::endl;
    return true;
}

std::string ModelZoo::getModelPath(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = downloaded_paths_.find(model_id);
    if (it != downloaded_paths_.end()) {
        return it->second;
    }
    
    return "";
}

bool ModelZoo::downloadModels(const std::vector<std::string>& model_ids,
                               DownloadProgressCallback progress) {
    size_t total = model_ids.size();
    size_t completed = 0;
    
    for (const auto& model_id : model_ids) {
        downloadModel(model_id,
                      [progress, model_id, &completed, total](const std::string& id, float p) {
                          if (progress) {
                              float overall = (completed + p) / total;
                              progress(id, overall);
                          }
                      },
                      [&completed](const std::string&, bool) {
                          completed++;
                      });
    }
    
    return true;
}

std::vector<std::string> ModelZoo::getDownloadedModels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [id, path] : downloaded_paths_) {
        if (std::filesystem::exists(path)) {
            result.push_back(id);
        }
    }
    
    return result;
}

void ModelZoo::clearCache() {
    std::filesystem::remove_all(config_.cache_path);
    std::filesystem::create_directories(config_.cache_path);
    
    std::lock_guard<std::mutex> lock(mutex_);
    downloaded_paths_.clear();
}

size_t ModelZoo::getCacheSize() const {
    size_t size = 0;
    for (const auto& entry : std::filesystem::directory_iterator(config_.cache_path)) {
        if (entry.is_regular_file()) {
            size += entry.file_size();
        } else if (entry.is_directory()) {
            for (const auto& sub : std::filesystem::recursive_directory_iterator(entry)) {
                if (sub.is_regular_file()) {
                    size += sub.file_size();
                }
            }
        }
    }
    return size;
}

void ModelZoo::setMaxCacheSize(size_t size_gb) {
    config_.max_cache_size_gb = size_gb;
}

bool ModelZoo::syncWithRemote() {
    if (!config_.enable_remote) {
        return false;
    }
    
    std::cout << "Syncing with remote zoo: " << config_.remote_url << std::endl;
    
    // Implementation would fetch remote catalog
    
    return true;
}

bool ModelZoo::updateCatalog() {
    std::cout << "Updating model catalog..." << std::endl;
    
    // Implementation would update from remote
    
    return true;
}

size_t ModelZoo::getModelCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return models_.size();
}

size_t ModelZoo::getDownloadedCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [id, path] : downloaded_paths_) {
        if (std::filesystem::exists(path)) {
            count++;
        }
    }
    
    return count;
}

bool ModelZoo::exportCatalog(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    // Simple JSON export
    file << "{" << std::endl;
    file << "  \"models\": [" << std::endl;
    
    bool first = true;
    for (const auto& [id, model] : models_) {
        if (!first) file << "," << std::endl;
        first = false;
        
        file << "    {\"id\": \"" << model.id << "\", ";
        file << "\"name\": \"" << model.name << "\", ";
        file << "\"parameter_count\": " << model.parameter_count << "}";
    }
    
    file << std::endl << "  ]" << std::endl;
    file << "}" << std::endl;
    
    return true;
}

bool ModelZoo::importCatalog(const std::string& path) {
    // Implementation would parse JSON and import
    return true;
}

bool ModelZoo::loadCatalog() {
    std::string catalog_file = getCatalogFile();
    
    if (!std::filesystem::exists(catalog_file)) {
        return false;
    }
    
    // Implementation would load from JSON
    
    return true;
}

bool ModelZoo::saveCatalog() const {
    std::string catalog_file = getCatalogFile();
    
    std::ofstream file(catalog_file);
    if (!file.is_open()) {
        return false;
    }
    
    // Simple JSON export
    file << "{" << std::endl;
    file << "  \"models\": [" << std::endl;
    
    bool first = true;
    for (const auto& [id, model] : models_) {
        if (!first) file << "," << std::endl;
        first = false;
        
        file << "    {\"id\": \"" << model.id << "\", ";
        file << "\"name\": \"" << model.name << "\", ";
        file << "\"parameter_count\": " << model.parameter_count << "}";
    }
    
    file << std::endl << "  ]" << std::endl;
    file << "}" << std::endl;
    
    return true;
}

std::string ModelZoo::getCatalogFile() const {
    return config_.zoo_path + "/catalog.json";
}

std::string ModelZoo::getModelCachePath(const std::string& model_id) const {
    return config_.cache_path + "/" + model_id + "/model.bin";
}

// ModelDownloader implementation
ModelDownloader::ModelDownloader()
    : max_concurrent_(3)
    , running_(false) {
}

ModelDownloader::~ModelDownloader() {
    shutdown();
}

bool ModelDownloader::initialize(int max_concurrent) {
    max_concurrent_ = max_concurrent;
    running_ = true;
    return true;
}

void ModelDownloader::shutdown() {
    running_ = false;
    cancelAllDownloads();
}

bool ModelDownloader::download(const std::string& model_id,
                                const std::string& url,
                                const std::string& destination,
                                DownloadProgressCallback progress,
                                DownloadCompleteCallback complete) {
    // Simulate download
    if (progress) {
        progress(model_id, 0.0f);
    }
    
    // Simulate download time
    for (int i = 0; i <= 100; i += 5) {
        if (!running_) return false;
        
        if (progress) {
            progress(model_id, i / 100.0f);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (complete) {
        complete(model_id, true);
    }
    
    return true;
}

std::future<bool> ModelDownloader::downloadAsync(const std::string& model_id,
                                                  const std::string& url,
                                                  const std::string& destination,
                                                  DownloadProgressCallback progress) {
    return std::async(std::launch::async, [this, model_id, url, destination, progress]() {
        return download(model_id, url, destination, progress, nullptr);
    });
}

void ModelDownloader::cancelDownload(const std::string& model_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = active_downloads_.find(model_id);
    if (it != active_downloads_.end()) {
        // Cancel logic would go here
        active_downloads_.erase(it);
    }
}

void ModelDownloader::cancelAllDownloads() {
    std::lock_guard<std::mutex> lock(mutex_);
    active_downloads_.clear();
}

bool ModelDownloader::isDownloading(const std::string& model_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_downloads_.find(model_id) != active_downloads_.end();
}

std::vector<std::string> ModelDownloader::getActiveDownloads() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [id, _] : active_downloads_) {
        result.push_back(id);
    }
    
    return result;
}

size_t ModelDownloader::getQueueSize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return download_queue_.size();
}

size_t ModelDownloader::getActiveCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_downloads_.size();
}

void ModelDownloader::processQueue() {
    // Queue processing logic
}

bool ModelDownloader::downloadFile(const std::string& url,
                                    const std::string& destination,
                                    std::function<void(float)> progress) {
    // Actual download implementation would go here
    return true;
}

// Utility functions
std::vector<PretrainedModel> getRecommendedModels(const std::string& task) {
    if (auto* zoo = getModelZoo()) {
        return zoo->getModelsByTask(task);
    }
    return {};
}

std::vector<PretrainedModel> getCompatibleModels(const std::string& base_model) {
    // Find models compatible with base model
    std::vector<PretrainedModel> result;
    
    if (auto* zoo = getModelZoo()) {
        auto all = zoo->getAllModels();
        for (const auto& model : all) {
            if (model.base_model == base_model) {
                result.push_back(model);
            }
        }
    }
    
    return result;
}

bool compareModelRatings(const PretrainedModel& a, const PretrainedModel& b) {
    return a.rating > b.rating;
}

bool compareModelDownloads(const PretrainedModel& a, const PretrainedModel& b) {
    return a.download_count > b.download_count;
}

} // namespace zoo
} // namespace rawrxd

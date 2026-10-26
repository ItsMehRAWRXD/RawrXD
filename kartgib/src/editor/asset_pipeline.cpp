#include "asset_pipeline.hpp"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <random>
#include <chrono>
#include <thread>

namespace kartgib::editor {

AssetImporter::~AssetImporter() {}

AssetImportResult ModelImporter::import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) {
    AssetImportResult result;
    result.success = false;

    try {
        // Simulate model import - in a real implementation this would use Assimp or similar
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            result.errorMessage = "Failed to open file: " + path;
            return result;
        }

        // Simulate processing time
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        result.success = true;
        result.assetGUID = generateGUID();
        result.createdAssetGUIDs.push_back(result.assetGUID);
        result.importTimeMs = 100;
        result.fileSize = std::filesystem::file_size(path);
        result.outputSize = result.fileSize * 2; // Estimated output size
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
    }

    return result;
}

AssetImportResult TextureImporter::import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) {
    AssetImportResult result;
    result.success = false;

    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            result.errorMessage = "Failed to open file: " + path;
            return result;
        }

        // Simulate texture processing
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        result.success = true;
        result.assetGUID = generateGUID();
        result.createdAssetGUIDs.push_back(result.assetGUID);
        result.importTimeMs = 50;
        result.fileSize = std::filesystem::file_size(path);
        result.outputSize = result.fileSize * 2;
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
    }

    return result;
}

AssetImportResult AudioImporter::import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) {
    AssetImportResult result;
    result.success = false;

    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            result.errorMessage = "Failed to open file: " + path;
            return result;
        }

        // Simulate audio processing
        std::this_thread::sleep_for(std::chrono::milliseconds(200));

        result.success = true;
        result.assetGUID = generateGUID();
        result.createdAssetGUIDs.push_back(result.assetGUID);
        result.importTimeMs = 200;
        result.fileSize = std::filesystem::file_size(path);
        result.outputSize = result.fileSize * 2;
    } catch (const std::exception& e) {
        result.errorMessage = e.what();
    }

    return result;
}

std::string AssetDatabase::generateGUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::string guid = "{" + std::to_string(dis(gen));
    for (int i = 0; i < 7; ++i) guid += std::to_string(dis(gen));
    guid += "-";
    for (int i = 0; i < 4; ++i) guid += std::to_string(dis(gen));
    guid += "-";
    for (int i = 0; i < 4; ++i) guid += std::to_string(dis(gen));
    guid += "-";
    for (int i = 0; i < 4; ++i) guid += std::to_string(dis(gen));
    guid += "-";
    for (int i = 0; i < 12; ++i) guid += std::to_string(dis(gen));
    guid += "}";
    
    return guid;
}

void AssetDatabase::registerDefaultImporters() {
    importers_["model"] = std::make_unique<ModelImporter>();
    importers_["texture"] = std::make_unique<TextureImporter>();
    importers_["audio"] = std::make_unique<AudioImporter>();
}

void AssetDatabase::processImportQueue() {
    std::unique_lock<std::mutex> lock(queueMutex_);
    while (importQueue_.empty() && !stopImportThreads_) {
        queueCV_.wait(lock);
    }
    
    if (stopImportThreads_ && importQueue_.empty()) return;
    
    if (!importQueue_.empty()) {
        auto job = importQueue_.front();
        importQueue_.pop();
        lock.unlock();
        
        activeImports_++;
        
        // Find appropriate importer
        AssetImporter* importer = nullptr;
        for (auto& [name, imp] : importers_) {
            if (imp->canImport(job.path)) {
                importer = imp.get();
                break;
            }
        }
        
        if (importer) {
            auto result = processImport(importer, job.path, job.settings);
            
            std::lock_guard<std::mutex> lock2(mutex_);
            if (result.success) {
                AssetMetadata meta;
                meta.guid = result.assetGUID;
                meta.path = job.path;
                meta.type = importer->getSupportedType();
                meta.status = ImportStatus::Completed;
                meta.fileSize = result.fileSize;
                meta.importTime = result.importTimeMs;
                meta.lastModified = std::filesystem::last_write_time(job.path).time_since_epoch().count();
                assets_[meta.guid] = meta;
                pathToGUID_[job.path] = meta.guid;
                
                if (onAssetImported) onAssetImported(meta.guid);
            }
            
            job.promise.set_value(result);
        } else {
            job.promise.set_value(AssetImportResult{false, "No importer found for file"});
        }
        
        activeImports_--;
    }
}

void AssetDatabase::importThreadWorker() {
    while (!stopImportThreads_) {
        processImportQueue();
    }
}

AssetImportResult AssetDatabase::processImport(AssetImporter* importer, const std::string& path, const ImportSettings& settings) {
    return importer->import(path, settings, libraryPath_);
}

void AssetDatabase::writeMetadata(const AssetMetadata& metadata) {
    std::string metaPath = libraryPath_ + "/" + metadata.guid + ".meta";
    std::ofstream file(metaPath);
    if (file.is_open()) {
        file << "GUID: " << metadata.guid << "\n";
        file << "Path: " << metadata.originalPath << "\n";
        file << "Type: " << static_cast<int>(metadata.type) << "\n";
        file << "Status: " << static_cast<int>(metadata.status) << "\n";
        file << "Size: " << metadata.fileSize << "\n";
        file << "Hash: " << metadata.hash << "\n";
        file << "Time: " << metadata.importTime << "\n";
        file << "Modified: " << metadata.lastModified << "\n";
        for (const auto& [key, value] : metadata.metadata) {
            file << key << ": " << value << "\n";
        }
        file.close();
    }
}

AssetMetadata AssetDatabase::readMetadata(const std::string& guid) {
    AssetMetadata meta;
    meta.guid = guid;
    
    std::string metaPath = libraryPath_ + "/" + guid + ".meta";
    std::ifstream file(metaPath);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line)) {
            size_t pos = line.find(": ");
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 2);
                if (key == "Path") meta.originalPath = value;
                else if (key == "Type") meta.type = static_cast<AssetType>(std::stoi(value));
                else if (key == "Status") meta.status = static_cast<ImportStatus>(std::stoi(value));
                else if (key == "Size") meta.fileSize = std::stoull(value);
                else if (key == "Hash") meta.hash = value;
                else if (key == "Time") meta.importTime = std::stoull(value);
                else if (key == "Modified") meta.lastModified = std::stoull(value);
                else metadata.metadata[key] = value;
            }
        }
        file.close();
    }
    
    return meta;
}

void AssetDatabase::scanAssetDirectory(const std::filesystem::path& dir) {
    if (!std::filesystem::exists(dir)) return;
    
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_directory()) {
            scanAssetDirectory(entry.path());
        } else if (entry.is_regular_file()) {
            processFile(entry.path());
        }
    }
}

void AssetDatabase::processFile(const std::filesystem::path& file) {
    // Check if file is already imported
    std::string path = file.string();
    if (pathToGUID_.find(path) != pathToGUID_.end()) return;
    
    // Find appropriate importer
    AssetImporter* importer = nullptr;
    for (auto& [name, imp] : importers_) {
        if (imp->canImport(path)) {
            importer = imp.get();
            break;
        }
    }
    
    if (importer) {
        ImportSettings settings;
        auto result = processImport(importer, path, settings);
        
        if (result.success) {
            AssetMetadata meta;
            meta.guid = result.assetGUID;
            meta.originalPath = path;
            meta.type = importer->getSupportedType();
            meta.status = ImportStatus::Completed;
            meta.fileSize = result.fileSize;
            meta.importTime = result.importTimeMs;
            meta.lastModified = std::filesystem::last_write_time(file).time_since_epoch().count();
            assets_[meta.guid] = meta;
            pathToGUID_[path] = meta.guid;
            
            writeMetadata(meta);
            
            if (onAssetImported) onAssetImported(meta.guid);
        }
    }
}

void AssetDatabase::updateDependencies(const std::string& guid, const std::vector<std::string>& newDeps) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.dependencies = newDeps;
        for (const auto& dep : newDeps) {
            auto depIt = assets_.find(dep);
            if (depIt != assets_.end()) {
                depIt->second.dependents.push_back(guid);
            }
        }
    }
}

AssetDatabase::AssetDatabase(const std::string& assetRoot, const std::string& libraryPath)
    : assetRoot_(assetRoot), libraryPath_(libraryPath) {
    registerDefaultImporters();
}

AssetDatabase::~AssetDatabase() {
    shutdown();
}

void AssetDatabase::initialize() {
    std::filesystem::create_directories(assetRoot_);
    std::filesystem::create_directories(libraryPath_);
    
    // Start import threads
    for (int i = 0; i < maxConcurrentImports_; ++i) {
        importThreads_.emplace_back([this]() { importThreadWorker(); });
    }
}

void AssetDatabase::shutdown() {
    stopImportThreads_ = true;
    queueCV_.notify_all();
    for (auto& thread : importThreads_) {
        if (thread.joinable()) thread.join();
    }
}

void AssetDatabase::scanAssets() {
    scanning_ = true;
    scanAssetDirectory(assetRoot_);
    scanning_ = false;
}

void AssetDatabase::refresh() {
    scanAssets();
}

std::optional<AssetMetadata> AssetDatabase::getAsset(const std::string& guid) const {
    auto it = assets_.find(guid);
    if (it != assets_.end()) return it->second;
    return std::nullopt;
}

std::optional<AssetMetadata> AssetDatabase::getAssetByPath(const std::string& path) const {
    auto it = pathToGUID_.find(path);
    if (it != pathToGUID_.end()) {
        auto assetIt = assets_.find(it->second);
        if (assetIt != assets_.end()) return assetIt->second;
    }
    return std::nullopt;
}

std::vector<AssetMetadata> AssetDatabase::getAssetsByType(AssetType type) const {
    std::vector<AssetMetadata> result;
    for (const auto& [guid, meta] : assets_) {
        if (meta.type == type) result.push_back(meta);
    }
    return result;
}

std::vector<std::string> AssetDatabase::findAssets(const std::string& pattern, AssetType type) const {
    std::vector<std::string> results;
    for (const auto& [guid, meta] : assets_) {
        if (type != AssetType::Unknown && meta.type != type) continue;
        if (meta.originalPath.find(pattern) != std::string::npos || meta.guid.find(pattern) != std::string::npos) {
            results.push_back(guid);
        }
    }
    return results;
}

std::string AssetDatabase::importAsset(const std::string& path, const ImportSettings& settings) {
    AssetImporter* importer = nullptr;
    for (auto& [name, imp] : importers_) {
        if (imp->canImport(path)) {
            importer = imp.get();
            break;
        }
    }
    
    if (!importer) return "";
    
    auto result = processImport(importer, path, settings);
    if (result.success) {
        AssetMetadata meta;
        meta.guid = result.assetGUID;
        meta.originalPath = path;
        meta.type = importer->getSupportedType();
        meta.status = ImportStatus::Completed;
        meta.fileSize = result.fileSize;
        meta.importTime = result.importTimeMs;
        meta.lastModified = std::filesystem::last_write_time(path).time_since_epoch().count();
        assets_[meta.guid] = meta;
        pathToGUID_[path] = meta.guid;
        writeMetadata(meta);
        
        if (onAssetImported) onAssetImported(meta.guid);
        return meta.guid;
    }
    
    return "";
}

std::future<AssetImportResult> AssetDatabase::importAssetAsync(const std::string& path, const ImportSettings& settings, int priority) {
    std::promise<AssetImportResult> promise;
    auto future = promise.get_future();
    
    ImportJob job;
    job.path = path;
    job.settings = settings;
    job.promise = std::move(promise);
    job.queuedTime = std::chrono::steady_clock::now();
    job.priority = priority;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        importQueue_.push(std::move(job));
    }
    queueCV_.notify_one();
    
    return future;
}

void AssetDatabase::deleteAsset(const std::string& guid) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        // Remove from path map
        pathToGUID_.erase(it->second.originalPath);
        
        // Remove dependencies
        for (const auto& dep : it->second.dependencies) {
            auto depIt = assets_.find(dep);
            if (depIt != assets_.end()) {
                auto& dependents = depIt->second.dependents;
                dependents.erase(std::remove(dependents.begin(), dependents.end(), guid), dependents.end());
            }
        }
        
        assets_.erase(it);
        
        if (onAssetDeleted) onAssetDeleted(guid);
    }
}

void AssetDatabase::moveAsset(const std::string& guid, const std::string& newPath) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        pathToGUID_.erase(it->second.originalPath);
        it->second.originalPath = newPath;
        pathToGUID_[newPath] = guid;
        
        if (onAssetMoved) onAssetMoved(guid, newPath);
    }
}

void AssetDatabase::renameAsset(const std::string& guid, const std::string& newName) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        std::filesystem::path p(it->second.originalPath);
        std::string newPath = p.parent_path().string() + "/" + newName;
        moveAsset(guid, newPath);
    }
}

void AssetDatabase::setAssetReadOnly(const std::string& guid, bool readOnly) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.isReadOnly = readOnly;
    }
}

void AssetDatabase::setAssetHidden(const std::string& guid, bool hidden) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.isHidden = hidden;
    }
}

void AssetDatabase::setAssetTags(const std::string& guid, const std::string& tags) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.tags = tags;
    }
}

void AssetDatabase::addDependency(const std::string& guid, const std::string& dependencyGUID) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.dependencies.push_back(dependencyGUID);
    }
    
    auto depIt = assets_.find(dependencyGUID);
    if (depIt != assets_.end()) {
        depIt->second.dependents.push_back(guid);
    }
}

void AssetDatabase::removeDependency(const std::string& guid, const std::string& dependencyGUID) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        it->second.dependencies.erase(
            std::remove(it->second.dependencies.begin(), it->second.dependencies.end(), dependencyGUID),
            it->second.dependencies.end());
    }
    
    auto depIt = assets_.find(dependencyGUID);
    if (depIt != assets_.end()) {
        depIt->second.dependents.erase(
            std::remove(depIt->second.dependents.begin(), depIt->second.dependents.end(), guid),
            depIt->second.dependents.end());
    }
}

std::vector<std::string> AssetDatabase::getDependencies(const std::string& guid) const {
    auto it = assets_.find(guid);
    if (it != assets_.end()) return it->second.dependencies;
    return {};
}

std::vector<std::string> AssetDatabase::getDependents(const std::string& guid) const {
    auto it = assets_.find(guid);
    if (it != assets_.end()) return it->second.dependents;
    return {};
}

void AssetDatabase::refreshAsset(const std::string& guid) {
    auto it = assets_.find(guid);
    if (it != assets_.end()) {
        importAsset(it->second.originalPath, ImportSettings());
    }
}

void AssetDatabase::refreshAll() {
    for (auto& [guid, meta] : assets_) {
        importAsset(meta.originalPath, ImportSettings());
    }
}

} // namespace kartgib::editor
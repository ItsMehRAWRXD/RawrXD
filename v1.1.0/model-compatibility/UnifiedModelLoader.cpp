// RawrXD Sovereign v1.1.0 - Model Compatibility Framework
// UnifiedModelLoader.cpp - Implementation

#include "UnifiedModelLoader.hpp"
#include <filesystem>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace RawrXD {
namespace ModelCompatibility {

// UnifiedModelLoader::Impl
class UnifiedModelLoader::Impl {
public:
    std::map<ModelFormat, std::shared_ptr<IModelLoader>> loaders_;
    mutable std::mutex loaders_mutex_;
    
    std::atomic<size_t> total_loads_{0};
    std::atomic<size_t> successful_loads_{0};
    std::atomic<size_t> failed_loads_{0};
    std::atomic<int64_t> total_load_time_ms_{0};
    
    bool initialized_ = false;
    FormatDetector detector_;
};

UnifiedModelLoader::UnifiedModelLoader() : pImpl(std::make_unique<Impl>()) {}
UnifiedModelLoader::~UnifiedModelLoader() = default;

void UnifiedModelLoader::Initialize() {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    
    // Register built-in loaders here when implemented
    // pImpl->loaders_[ModelFormat::GGUF] = std::make_shared<GGUFLoader>();
    // pImpl->loaders_[ModelFormat::ONNX] = std::make_shared<ONNXLoader>();
    // pImpl->loaders_[ModelFormat::TENSORRT] = std::make_shared<TensorRTLoader>();
    
    pImpl->initialized_ = true;
}

bool UnifiedModelLoader::IsInitialized() const {
    return pImpl->initialized_;
}

void UnifiedModelLoader::RegisterLoader(std::shared_ptr<IModelLoader> loader) {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    pImpl->loaders_[loader->GetFormat()] = loader;
}

void UnifiedModelLoader::UnregisterLoader(ModelFormat format) {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    pImpl->loaders_.erase(format);
}

bool UnifiedModelLoader::HasLoader(ModelFormat format) const {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    return pImpl->loaders_.find(format) != pImpl->loaders_.end();
}

std::shared_ptr<IModelLoader> UnifiedModelLoader::GetLoader(ModelFormat format) const {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    auto it = pImpl->loaders_.find(format);
    if (it == pImpl->loaders_.end()) {
        return nullptr;
    }
    return it->second;
}

LoadResult UnifiedModelLoader::Load(const std::string& path) {
    ModelFormat format = DetectFormat(path);
    if (format == ModelFormat::UNKNOWN) {
        return LoadResult::Failure("Unable to detect model format for: " + path);
    }
    return Load(path, format);
}

LoadResult UnifiedModelLoader::Load(const std::string& path, const LoadOptions& options) {
    ModelFormat format = DetectFormat(path);
    if (format == ModelFormat::UNKNOWN) {
        return LoadResult::Failure("Unable to detect model format for: " + path);
    }
    return Load(path, format, options);
}

LoadResult UnifiedModelLoader::Load(const std::string& path, ModelFormat format) {
    return Load(path, format, LoadOptions());
}

LoadResult UnifiedModelLoader::Load(const std::string& path, ModelFormat format, const LoadOptions& options) {
    return LoadInternal(path, format, options);
}

LoadResult UnifiedModelLoader::LoadFromMemory(const std::vector<uint8_t>& data) {
    ModelFormat format = DetectFormat(data);
    if (format == ModelFormat::UNKNOWN) {
        return LoadResult::Failure("Unable to detect model format from memory");
    }
    return LoadFromMemory(data, format);
}

LoadResult UnifiedModelLoader::LoadFromMemory(const std::vector<uint8_t>& data, ModelFormat format) {
    return LoadFromMemory(data, format, LoadOptions());
}

LoadResult UnifiedModelLoader::LoadFromMemory(const std::vector<uint8_t>& data, 
                                               ModelFormat format, 
                                               const LoadOptions& options) {
    return LoadFromMemoryInternal(data, format, options);
}

LoadResult UnifiedModelLoader::LoadInternal(const std::string& path, 
                                            ModelFormat format,
                                            const LoadOptions& options) {
    pImpl->total_loads_++;
    auto start = std::chrono::steady_clock::now();
    
    // Check if loader exists
    auto loader = GetLoader(format);
    if (!loader) {
        pImpl->failed_loads_++;
        return LoadResult::Failure("No loader registered for format: " + 
                                    ModelFormatUtils::FormatToString(format));
    }
    
    // Validate file exists
    if (!LoaderUtils::FileExists(path)) {
        pImpl->failed_loads_++;
        return LoadResult::Failure("File not found: " + path);
    }
    
    // Validate format
    std::string error;
    if (!loader->Validate(path, error)) {
        pImpl->failed_loads_++;
        return LoadResult::Failure("Validation failed: " + error);
    }
    
    // Load model
    try {
        auto model = loader->Load(path);
        auto end = std::chrono::steady_clock::now();
        int64_t load_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        pImpl->successful_loads_++;
        pImpl->total_load_time_ms_ += load_time;
        
        size_t memory_used = model ? model->GetMemoryUsage() : 0;
        
        return LoadResult::Success(model, format, load_time, memory_used);
    } catch (const std::exception& e) {
        pImpl->failed_loads_++;
        return LoadResult::Failure(std::string("Load exception: ") + e.what());
    }
}

LoadResult UnifiedModelLoader::LoadFromMemoryInternal(const std::vector<uint8_t>& data,
                                                       ModelFormat format,
                                                       const LoadOptions& options) {
    pImpl->total_loads_++;
    auto start = std::chrono::steady_clock::now();
    
    // Check if loader exists
    auto loader = GetLoader(format);
    if (!loader) {
        pImpl->failed_loads_++;
        return LoadResult::Failure("No loader registered for format: " + 
                                    ModelFormatUtils::FormatToString(format));
    }
    
    // Check if loader supports memory loading
    if (!loader->CanLoadFromMemory()) {
        pImpl->failed_loads_++;
        return LoadResult::Failure("Loader does not support memory loading");
    }
    
    // Load model
    try {
        auto model = loader->LoadFromMemory(data);
        auto end = std::chrono::steady_clock::now();
        int64_t load_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        pImpl->successful_loads_++;
        pImpl->total_load_time_ms_ += load_time;
        
        size_t memory_used = model ? model->GetMemoryUsage() : 0;
        
        return LoadResult::Success(model, format, load_time, memory_used);
    } catch (const std::exception& e) {
        pImpl->failed_loads_++;
        return LoadResult::Failure(std::string("Load exception: ") + e.what());
    }
}

ModelFormat UnifiedModelLoader::DetectFormat(const std::string& path) const {
    return pImpl->detector_.Detect(path).format;
}

ModelFormat UnifiedModelLoader::DetectFormat(const std::vector<uint8_t>& data) const {
    return pImpl->detector_.DetectFromData(data).format;
}

FormatDetectionResult UnifiedModelLoader::DetectFormatDetailed(const std::string& path) const {
    return pImpl->detector_.Detect(path);
}

bool UnifiedModelLoader::CanLoad(const std::string& path) const {
    ModelFormat format = DetectFormat(path);
    return CanLoad(path, format);
}

bool UnifiedModelLoader::CanLoad(const std::string& path, ModelFormat format) const {
    auto loader = GetLoader(format);
    if (!loader) {
        return false;
    }
    return loader->CanLoad(path);
}

bool UnifiedModelLoader::Validate(const std::string& path, std::string& error) const {
    ModelFormat format = DetectFormat(path);
    if (format == ModelFormat::UNKNOWN) {
        error = "Unable to detect model format";
        return false;
    }
    
    auto loader = GetLoader(format);
    if (!loader) {
        error = "No loader available for format: " + ModelFormatUtils::FormatToString(format);
        return false;
    }
    
    return loader->Validate(path, error);
}

ModelMetadata UnifiedModelLoader::ExtractMetadata(const std::string& path) const {
    ModelFormat format = DetectFormat(path);
    return ExtractMetadata(path, format);
}

ModelMetadata UnifiedModelLoader::ExtractMetadata(const std::string& path, ModelFormat format) const {
    auto loader = GetLoader(format);
    if (!loader) {
        return ModelMetadata();
    }
    
    try {
        return loader->ExtractMetadata(path);
    } catch (...) {
        return ModelMetadata();
    }
}

std::vector<ModelFormat> UnifiedModelLoader::GetSupportedFormats() const {
    std::lock_guard<std::mutex> lock(pImpl->loaders_mutex_);
    std::vector<ModelFormat> formats;
    for (const auto& [format, _] : pImpl->loaders_) {
        formats.push_back(format);
    }
    return formats;
}

std::vector<FormatInfo> UnifiedModelLoader::GetSupportedFormatInfo() const {
    std::vector<FormatInfo> info;
    for (auto format : GetSupportedFormats()) {
        info.push_back(ModelFormatUtils::GetFormatInfo(format));
    }
    return info;
}

bool UnifiedModelLoader::IsFormatSupported(ModelFormat format) const {
    return HasLoader(format);
}

size_t UnifiedModelLoader::GetTotalLoads() const {
    return pImpl->total_loads_.load();
}

size_t UnifiedModelLoader::GetSuccessfulLoads() const {
    return pImpl->successful_loads_.load();
}

size_t UnifiedModelLoader::GetFailedLoads() const {
    return pImpl->failed_loads_.load();
}

double UnifiedModelLoader::GetAverageLoadTimeMs() const {
    size_t total = pImpl->total_loads_.load();
    if (total == 0) return 0.0;
    return static_cast<double>(pImpl->total_load_time_ms_.load()) / total;
}

void UnifiedModelLoader::ResetStatistics() {
    pImpl->total_loads_ = 0;
    pImpl->successful_loads_ = 0;
    pImpl->failed_loads_ = 0;
    pImpl->total_load_time_ms_ = 0;
}

// ModelCache::Impl
struct CacheEntry {
    std::shared_ptr<IModel> model;
    std::string key;
    std::chrono::steady_clock::time_point last_access;
    size_t memory_usage;
};

class ModelCache::Impl {
public:
    std::map<std::string, CacheEntry> entries_;
    mutable std::mutex mutex_;
    size_t max_size_ = 10;
    size_t max_memory_ = 0;  // 0 = unlimited
};

ModelCache::ModelCache() : pImpl(std::make_unique<Impl>()) {}
ModelCache::~ModelCache() = default;

void ModelCache::SetMaxSize(size_t max_models) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->max_size_ = max_models;
}

void ModelCache::SetMaxMemory(size_t max_memory_bytes) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->max_memory_ = max_memory_bytes;
}

size_t ModelCache::GetMaxSize() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->max_size_;
}

size_t ModelCache::GetMaxMemory() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->max_memory_;
}

void ModelCache::Add(const std::string& key, std::shared_ptr<IModel> model) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    CacheEntry entry;
    entry.model = model;
    entry.key = key;
    entry.last_access = std::chrono::steady_clock::now();
    entry.memory_usage = model ? model->GetMemoryUsage() : 0;
    
    pImpl->entries_[key] = entry;
    
    // Trim if necessary
    Trim();
}

std::shared_ptr<IModel> ModelCache::Get(const std::string& key) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    auto it = pImpl->entries_.find(key);
    if (it == pImpl->entries_.end()) {
        return nullptr;
    }
    
    // Update LRU
    it->second.last_access = std::chrono::steady_clock::now();
    return it->second.model;
}

void ModelCache::Remove(const std::string& key) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->entries_.erase(key);
}

void ModelCache::Clear() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->entries_.clear();
}

bool ModelCache::Contains(const std::string& key) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->entries_.find(key) != pImpl->entries_.end();
}

size_t ModelCache::GetSize() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->entries_.size();
}

size_t ModelCache::GetMemoryUsage() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    size_t total = 0;
    for (const auto& [_, entry] : pImpl->entries_) {
        total += entry.memory_usage;
    }
    return total;
}

std::vector<std::string> ModelCache::GetKeys() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    std::vector<std::string> keys;
    for (const auto& [key, _] : pImpl->entries_) {
        keys.push_back(key);
    }
    return keys;
}

void ModelCache::Trim() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    // Check size limit
    while (pImpl->max_size_ > 0 && pImpl->entries_.size() > pImpl->max_size_) {
        // Find oldest entry
        auto oldest = pImpl->entries_.begin();
        for (auto it = pImpl->entries_.begin(); it != pImpl->entries_.end(); ++it) {
            if (it->second.last_access < oldest->second.last_access) {
                oldest = it;
            }
        }
        pImpl->entries_.erase(oldest);
    }
    
    // Check memory limit
    if (pImpl->max_memory_ > 0) {
        while (GetMemoryUsage() > pImpl->max_memory_ && !pImpl->entries_.empty()) {
            // Find oldest entry
            auto oldest = pImpl->entries_.begin();
            for (auto it = pImpl->entries_.begin(); it != pImpl->entries_.end(); ++it) {
                if (it->second.last_access < oldest->second.last_access) {
                    oldest = it;
                }
            }
            pImpl->entries_.erase(oldest);
        }
    }
}

void ModelCache::UpdateLRU(const std::string& key) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    auto it = pImpl->entries_.find(key);
    if (it != pImpl->entries_.end()) {
        it->second.last_access = std::chrono::steady_clock::now();
    }
}

// AsyncModelLoader::Impl
class AsyncModelLoader::Impl {
public:
    UnifiedModelLoader* loader_ = nullptr;
    std::map<std::string, std::future<void>> pending_;
    mutable std::mutex mutex_;
};

AsyncModelLoader::AsyncModelLoader(UnifiedModelLoader* loader) 
    : pImpl(std::make_unique<Impl>()) {
    pImpl->loader_ = loader;
}

AsyncModelLoader::~AsyncModelLoader() {
    WaitForAll();
}

void AsyncModelLoader::LoadAsync(const std::string& path, LoadCallback callback) {
    LoadAsync(path, LoadOptions(), callback);
}

void AsyncModelLoader::LoadAsync(const std::string& path, const LoadOptions& options, LoadCallback callback) {
    if (!pImpl->loader_) {
        callback(LoadResult::Failure("Loader not initialized"));
        return;
    }
    
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    
    // Check if already loading
    if (pImpl->pending_.find(path) != pImpl->pending_.end()) {
        return;
    }
    
    // Start async load
    auto future = std::async(std::launch::async, [this, path, options, callback]() {
        auto result = pImpl->loader_->Load(path, options);
        callback(result);
        
        // Remove from pending
        std::lock_guard<std::mutex> lock(pImpl->mutex_);
        pImpl->pending_.erase(path);
    });
    
    pImpl->pending_[path] = std::move(future);
}

void AsyncModelLoader::CancelAll() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    // Note: std::future doesn't support cancellation
    // Just clear the map
    pImpl->pending_.clear();
}

void AsyncModelLoader::Cancel(const std::string& path) {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    pImpl->pending_.erase(path);
}

bool AsyncModelLoader::IsLoading(const std::string& path) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->pending_.find(path) != pImpl->pending_.end();
}

std::vector<std::string> AsyncModelLoader::GetPendingLoads() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    std::vector<std::string> paths;
    for (const auto& [path, _] : pImpl->pending_) {
        paths.push_back(path);
    }
    return paths;
}

void AsyncModelLoader::WaitForAll() {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    for (auto& [_, future] : pImpl->pending_) {
        if (future.valid()) {
            future.wait();
        }
    }
    pImpl->pending_.clear();
}

bool AsyncModelLoader::WaitFor(const std::string& path, int timeout_ms) {
    std::future<void> future;
    {
        std::lock_guard<std::mutex> lock(pImpl->mutex_);
        auto it = pImpl->pending_.find(path);
        if (it == pImpl->pending_.end()) {
            return true;  // Not pending, consider it done
        }
        future = std::move(it->second);
    }
    
    if (future.valid()) {
        auto status = future.wait_for(std::chrono::milliseconds(timeout_ms));
        return status == std::future_status::ready;
    }
    return true;
}

// LoaderUtils implementation
namespace LoaderUtils {

std::string GetFileExtension(const std::string& path) {
    std::filesystem::path p(path);
    return p.extension().string();
}

std::string GetFileName(const std::string& path) {
    std::filesystem::path p(path);
    return p.filename().string();
}

std::string GetDirectory(const std::string& path) {
    std::filesystem::path p(path);
    return p.parent_path().string();
}

bool FileExists(const std::string& path) {
    return std::filesystem::exists(path);
}

size_t GetFileSize(const std::string& path) {
    if (!FileExists(path)) return 0;
    return std::filesystem::file_size(path);
}

std::vector<uint8_t> ReadFileHeader(const std::string& path, size_t bytes) {
    std::vector<uint8_t> header;
    if (!FileExists(path)) return header;
    
    std::ifstream file(path, std::ios::binary);
    if (!file) return header;
    
    header.resize(bytes);
    file.read(reinterpret_cast<char*>(header.data()), bytes);
    header.resize(file.gcount());
    
    return header;
}

std::vector<uint8_t> ReadFile(const std::string& path) {
    std::vector<uint8_t> data;
    if (!FileExists(path)) return data;
    
    size_t size = GetFileSize(path);
    data.resize(size);
    
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    
    file.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

std::string CalculateSHA256(const std::string& path) {
    // Placeholder - would use proper SHA256 implementation
    return "sha256_placeholder";
}

std::string CalculateSHA256(const std::vector<uint8_t>& data) {
    // Placeholder - would use proper SHA256 implementation
    return "sha256_placeholder";
}

size_t EstimateMemoryFromFile(const std::string& path, ModelFormat format) {
    // Rough estimation based on file size
    size_t file_size = GetFileSize(path);
    
    switch (format) {
        case ModelFormat::GGUF:
            // GGUF is already quantized, estimate ~1.5x file size
            return static_cast<size_t>(file_size * 1.5);
        case ModelFormat::ONNX:
            // ONNX can vary, estimate ~2x file size
            return static_cast<size_t>(file_size * 2.0);
        case ModelFormat::TENSORRT:
            // TensorRT is optimized, estimate ~1.2x file size
            return static_cast<size_t>(file_size * 1.2);
        default:
            return file_size * 2;  // Conservative estimate
    }
}

std::string AutoSelectDevice() {
    // Check for CUDA
    // if (IsDeviceAvailable("cuda")) return "cuda";
    // Check for Vulkan
    // if (IsDeviceAvailable("vulkan")) return "vulkan";
    return "cpu";
}

bool IsDeviceAvailable(const std::string& device) {
    // Placeholder - would check actual device availability
    if (device == "cpu") return true;
    return false;
}

std::vector<std::string> GetAvailableDevices() {
    std::vector<std::string> devices;
    devices.push_back("cpu");
    // if (IsDeviceAvailable("cuda")) devices.push_back("cuda");
    // if (IsDeviceAvailable("vulkan")) devices.push_back("vulkan");
    return devices;
}

} // namespace LoaderUtils

// Global loader instance
UnifiedModelLoader& GetGlobalLoader() {
    static UnifiedModelLoader instance;
    return instance;
}

// Convenience functions
std::shared_ptr<IModel> LoadModel(const std::string& path) {
    auto result = GetGlobalLoader().Load(path);
    return result.model;
}

std::shared_ptr<IModel> LoadModel(const std::string& path, const LoadOptions& options) {
    auto result = GetGlobalLoader().Load(path, options);
    return result.model;
}

ModelMetadata GetModelMetadata(const std::string& path) {
    return GetGlobalLoader().ExtractMetadata(path);
}

} // namespace ModelCompatibility
} // namespace RawrXD

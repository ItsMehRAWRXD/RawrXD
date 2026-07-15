// RawrXD Model Loader Registry Implementation
// Phase X.2: Custom model loader support

#include "ModelLoaderRegistry.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>

namespace RawrXD {
namespace Extensions {

// ============================================================================
// ModelLoaderRegistry Implementation
// ============================================================================

ModelLoaderRegistry::ModelLoaderRegistry() = default;

ModelLoaderRegistry::~ModelLoaderRegistry() {
    if (!loadedModels_.empty()) {
        shutdown();
    }
}

bool ModelLoaderRegistry::initialize() {
    // Register built-in loaders
    registerLoader(std::make_shared<GGMLModelLoader>());
    registerLoader(std::make_shared<ONNXModelLoader>());
    
    return true;
}

bool ModelLoaderRegistry::shutdown() {
    unloadAllModels();
    return true;
}

// ============================================================================
// Loader Registration
// ============================================================================

void ModelLoaderRegistry::registerLoader(std::shared_ptr<IModelLoader> loader) {
    std::lock_guard<std::mutex> lock(mutex_);
    loaders_[loader->getName()] = loader;
}

void ModelLoaderRegistry::unregisterLoader(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    loaders_.erase(name);
}

std::shared_ptr<IModelLoader> ModelLoaderRegistry::getLoader(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loaders_.find(name);
    if (it != loaders_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<IModelLoader> ModelLoaderRegistry::findLoaderForPath(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [name, loader] : loaders_) {
        if (loader->canLoad(path)) {
            return loader;
        }
    }
    return nullptr;
}

std::vector<std::string> ModelLoaderRegistry::listLoaders() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, loader] : loaders_) {
        result.push_back(name);
    }
    return result;
}

std::vector<std::string> ModelLoaderRegistry::listLoadersForFormat(ModelFormat format) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, loader] : loaders_) {
        auto formats = loader->getSupportedFormats();
        if (std::find(formats.begin(), formats.end(), format) != formats.end()) {
            result.push_back(name);
        }
    }
    return result;
}

// ============================================================================
// Model Loading
// ============================================================================

ModelLoadResult ModelLoaderRegistry::loadModel(const std::string& path, const ModelLoadOptions& options) {
    auto loader = findLoaderForPath(path);
    if (!loader) {
        ModelLoadResult result;
        result.success = false;
        result.errorMessage = "No suitable loader found for: " + path;
        failedLoads_++;
        return result;
    }
    
    auto start = std::chrono::steady_clock::now();
    auto loadResult = loader->load(path, options);
    auto end = std::chrono::steady_clock::now();
    
    loadResult.loadTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    if (loadResult.success) {
        std::lock_guard<std::mutex> lock(mutex_);
        loadedModels_[loadResult.modelId] = loadResult;
        successfulLoads_++;
        notifyEvent("loaded", loadResult.modelId);
    } else {
        failedLoads_++;
    }
    
    return loadResult;
}

bool ModelLoaderRegistry::unloadModel(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedModels_.find(modelId);
    if (it == loadedModels_.end()) {
        return false;
    }
    
    // Find the loader and unload
    for (const auto& [name, loader] : loaders_) {
        if (loader->isLoaded(modelId)) {
            loader->unload(modelId);
            break;
        }
    }
    
    loadedModels_.erase(it);
    notifyEvent("unloaded", modelId);
    return true;
}

bool ModelLoaderRegistry::unloadAllModels() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [modelId, result] : loadedModels_) {
        for (const auto& [name, loader] : loaders_) {
            if (loader->isLoaded(modelId)) {
                loader->unload(modelId);
                break;
            }
        }
    }
    
    loadedModels_.clear();
    return true;
}

// ============================================================================
// Model Inspection
// ============================================================================

ModelMetadata ModelLoaderRegistry::inspectModel(const std::string& path) {
    auto loader = findLoaderForPath(path);
    if (loader) {
        return loader->inspect(path);
    }
    return ModelMetadata{};
}

bool ModelLoaderRegistry::validateModel(const std::string& path) {
    auto loader = findLoaderForPath(path);
    if (loader) {
        return loader->validate(path);
    }
    return false;
}

ModelFormat ModelLoaderRegistry::detectFormat(const std::string& path) const {
    return ModelFormatUtils::detectFromExtension(path);
}

// ============================================================================
// Model Access
// ============================================================================

void* ModelLoaderRegistry::getModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedModels_.find(modelId);
    if (it != loadedModels_.end()) {
        return it->second.modelHandle;
    }
    return nullptr;
}

bool ModelLoaderRegistry::isModelLoaded(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return loadedModels_.find(modelId) != loadedModels_.end();
}

std::vector<std::string> ModelLoaderRegistry::listLoadedModels() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [modelId, info] : loadedModels_) {
        result.push_back(modelId);
    }
    return result;
}

// ============================================================================
// Model Metadata
// ============================================================================

ModelMetadata ModelLoaderRegistry::getModelMetadata(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedModels_.find(modelId);
    if (it != loadedModels_.end()) {
        return it->second.metadata;
    }
    return ModelMetadata{};
}

bool ModelLoaderRegistry::updateModelMetadata(const std::string& modelId, const ModelMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = loadedModels_.find(modelId);
    if (it != loadedModels_.end()) {
        it->second.metadata = metadata;
        return true;
    }
    return false;
}

// ============================================================================
// Format Conversion
// ============================================================================

bool ModelLoaderRegistry::canConvert(ModelFormat from, ModelFormat to) const {
    // Would check if conversion is supported
    return from != to;
}

bool ModelLoaderRegistry::convertModel(const std::string& inputPath, const std::string& outputPath,
                                       ModelFormat targetFormat, const std::map<std::string, std::string>& options) {
    // Would implement model conversion
    return false;
}

// ============================================================================
// Quantization
// ============================================================================

bool ModelLoaderRegistry::canQuantize(ModelFormat format) const {
    return format == ModelFormat::GGML || format == ModelFormat::GGUF;
}

bool ModelLoaderRegistry::quantizeModel(const std::string& inputPath, const std::string& outputPath,
                                        const std::string& quantizationType, int bits) {
    // Would implement quantization
    return false;
}

// ============================================================================
// Model Caching
// ============================================================================

void ModelLoaderRegistry::enableCaching(bool enabled) {
    cachingEnabled_ = enabled;
}

bool ModelLoaderRegistry::isCachingEnabled() const {
    return cachingEnabled_;
}

void ModelLoaderRegistry::setCacheDirectory(const std::string& path) {
    cacheDirectory_ = path;
}

void ModelLoaderRegistry::clearCache() {
    // Would clear cache directory
}

uint64_t ModelLoaderRegistry::getCacheSize() const {
    // Would calculate cache size
    return 0;
}

// ============================================================================
// Model Sources
// ============================================================================

void ModelLoaderRegistry::registerSource(const std::string& name, const std::string& basePath) {
    std::lock_guard<std::mutex> lock(mutex_);
    modelSources_[name] = basePath;
}

void ModelLoaderRegistry::unregisterSource(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex_);
    modelSources_.erase(name);
}

std::string ModelLoaderRegistry::resolvePath(const std::string& source, const std::string& modelPath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = modelSources_.find(source);
    if (it != modelSources_.end()) {
        return it->second + "/" + modelPath;
    }
    return modelPath;
}

std::vector<std::string> ModelLoaderRegistry::listSources() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    for (const auto& [name, path] : modelSources_) {
        result.push_back(name);
    }
    return result;
}

// ============================================================================
// Statistics
// ============================================================================

ModelLoaderRegistry::LoaderStats ModelLoaderRegistry::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    LoaderStats stats{};
    stats.registeredLoaders = static_cast<uint32_t>(loaders_.size());
    stats.loadedModels = static_cast<uint32_t>(loadedModels_.size());
    stats.successfulLoads = successfulLoads_;
    stats.failedLoads = failedLoads_;
    
    // Calculate total memory
    for (const auto& [modelId, result] : loadedModels_) {
        stats.totalMemoryUsed += result.memoryUsed;
    }
    
    stats.cacheSize = getCacheSize();
    
    return stats;
}

// ============================================================================
// Events
// ============================================================================

void ModelLoaderRegistry::onModelEvent(ModelEventCallback callback) {
    eventCallback_ = callback;
}

void ModelLoaderRegistry::notifyEvent(const std::string& event, const std::string& modelId) {
    if (eventCallback_) {
        eventCallback_(event, modelId);
    }
}

std::string ModelLoaderRegistry::generateModelId() const {
    static uint32_t counter = 0;
    return "model_" + std::to_string(++counter);
}

// ============================================================================
// GGMLModelLoader Implementation
// ============================================================================

GGMLModelLoader::GGMLModelLoader() = default;

std::vector<ModelFormat> GGMLModelLoader::getSupportedFormats() const {
    return {ModelFormat::GGML, ModelFormat::GGUF};
}

bool GGMLModelLoader::canLoad(const std::string& path) const {
    std::string ext = std::filesystem::path(path).extension().string();
    return ext == ".ggml" || ext == ".gguf" || ext == ".bin";
}

ModelMetadata GGMLModelLoader::inspect(const std::string& path) const {
    ModelMetadata metadata;
    metadata.modelId = std::filesystem::path(path).stem().string();
    metadata.format = ModelFormat::GGUF;
    metadata.fileSize = std::filesystem::file_size(path);
    // Would read actual GGUF metadata
    return metadata;
}

bool GGMLModelLoader::validate(const std::string& path) const {
    // Would validate GGUF file structure
    return std::filesystem::exists(path);
}

ModelLoadResult GGMLModelLoader::load(const std::string& path, const ModelLoadOptions& options) {
    ModelLoadResult result;
    result.success = true;
    result.modelId = std::filesystem::path(path).stem().string();
    result.metadata = inspect(path);
    
    // Would actually load the model using llama.cpp
    
    std::lock_guard<std::mutex> lock(mutex_);
    models_[result.modelId] = nullptr;  // Placeholder
    
    return result;
}

bool GGMLModelLoader::unload(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(mutex_);
    models_.erase(modelId);
    return true;
}

void* GGMLModelLoader::getModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(modelId);
    if (it != models_.end()) {
        return it->second;
    }
    return nullptr;
}

bool GGMLModelLoader::isLoaded(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return models_.find(modelId) != models_.end();
}

uint64_t GGMLModelLoader::getMemoryUsage(const std::string& modelId) const {
    // Would return actual memory usage
    return 0;
}

std::map<std::string, double> GGMLModelLoader::getStatistics(const std::string& modelId) const {
    // Would return model statistics
    return {};
}

// ============================================================================
// ONNXModelLoader Implementation
// ============================================================================

ONNXModelLoader::ONNXModelLoader() = default;

std::vector<ModelFormat> ONNXModelLoader::getSupportedFormats() const {
    return {ModelFormat::ONNX};
}

bool ONNXModelLoader::canLoad(const std::string& path) const {
    return std::filesystem::path(path).extension() == ".onnx";
}

ModelMetadata ONNXModelLoader::inspect(const std::string& path) const {
    ModelMetadata metadata;
    metadata.modelId = std::filesystem::path(path).stem().string();
    metadata.format = ModelFormat::ONNX;
    metadata.fileSize = std::filesystem::file_size(path);
    return metadata;
}

bool ONNXModelLoader::validate(const std::string& path) const {
    return std::filesystem::exists(path);
}

ModelLoadResult ONNXModelLoader::load(const std::string& path, const ModelLoadOptions& options) {
    ModelLoadResult result;
    result.success = true;
    result.modelId = std::filesystem::path(path).stem().string();
    result.metadata = inspect(path);
    
    std::lock_guard<std::mutex> lock(mutex_);
    models_[result.modelId] = nullptr;
    
    return result;
}

bool ONNXModelLoader::unload(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(mutex_);
    models_.erase(modelId);
    return true;
}

void* ONNXModelLoader::getModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = models_.find(modelId);
    if (it != models_.end()) {
        return it->second;
    }
    return nullptr;
}

bool ONNXModelLoader::isLoaded(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return models_.find(modelId) != models_.end();
}

uint64_t ONNXModelLoader::getMemoryUsage(const std::string& modelId) const {
    return 0;
}

std::map<std::string, double> ONNXModelLoader::getStatistics(const std::string& modelId) const {
    return {};
}

// ============================================================================
// ModelFormatUtils Implementation
// ============================================================================

std::string ModelFormatUtils::formatToString(ModelFormat format) {
    switch (format) {
        case ModelFormat::GGML: return "GGML";
        case ModelFormat::GGUF: return "GGUF";
        case ModelFormat::ONNX: return "ONNX";
        case ModelFormat::PYTORCH: return "PyTorch";
        case ModelFormat::TENSORFLOW: return "TensorFlow";
        case ModelFormat::SAFETENSORS: return "SafeTensors";
        case ModelFormat::CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

ModelFormat ModelFormatUtils::stringToFormat(const std::string& str) {
    if (str == "GGML") return ModelFormat::GGML;
    if (str == "GGUF") return ModelFormat::GGUF;
    if (str == "ONNX") return ModelFormat::ONNX;
    if (str == "PyTorch") return ModelFormat::PYTORCH;
    if (str == "TensorFlow") return ModelFormat::TENSORFLOW;
    if (str == "SafeTensors") return ModelFormat::SAFETENSORS;
    if (str == "Custom") return ModelFormat::CUSTOM;
    return ModelFormat::UNKNOWN;
}

std::vector<std::string> ModelFormatUtils::getFileExtensions(ModelFormat format) {
    switch (format) {
        case ModelFormat::GGML: return {".ggml", ".bin"};
        case ModelFormat::GGUF: return {".gguf"};
        case ModelFormat::ONNX: return {".onnx"};
        case ModelFormat::PYTORCH: return {".pt", ".pth"};
        case ModelFormat::TENSORFLOW: return {".pb", ".h5"};
        case ModelFormat::SAFETENSORS: return {".safetensors"};
        default: return {};
    }
}

ModelFormat ModelFormatUtils::detectFromExtension(const std::string& path) {
    std::string ext = std::filesystem::path(path).extension().string();
    
    if (ext == ".ggml" || ext == ".bin") return ModelFormat::GGML;
    if (ext == ".gguf") return ModelFormat::GGUF;
    if (ext == ".onnx") return ModelFormat::ONNX;
    if (ext == ".pt" || ext == ".pth") return ModelFormat::PYTORCH;
    if (ext == ".pb" || ext == ".h5") return ModelFormat::TENSORFLOW;
    if (ext == ".safetensors") return ModelFormat::SAFETENSORS;
    
    return ModelFormat::UNKNOWN;
}

bool ModelFormatUtils::isValidFormat(const std::string& str) {
    return stringToFormat(str) != ModelFormat::UNKNOWN;
}

} // namespace Extensions
} // namespace RawrXD

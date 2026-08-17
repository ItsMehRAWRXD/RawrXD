//==============================================================================
// ModelResolver.cpp
// Single authority for model discovery and resolution
// Phase 15B: Service Architecture
//==============================================================================

#include "ModelResolver.hpp"
#include <windows.h>
#include <fstream>
#include <nlohmann/json.hpp>

namespace RawrXD::Runtime {

//==============================================================================
// Singleton
//==============================================================================
ModelResolver& ModelResolver::Instance() {
    static ModelResolver instance;
    return instance;
}

//==============================================================================
// Lifecycle
//==============================================================================
void ModelResolver::Initialize() {
    if (initialized_) return;
    
    // Default search paths
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::filesystem::path exeDir = std::filesystem::path(exePath).parent_path();
    
    searchPaths_.push_back(exeDir / "models");
    searchPaths_.push_back(exeDir / ".." / "models");
    searchPaths_.push_back("D:\\models");
    searchPaths_.push_back("D:\\OllamaModels");
    searchPaths_.push_back("F:\\OllamaModels");
    searchPaths_.push_back("C:\\Users\\" + std::string(getenv("USERNAME") ? getenv("USERNAME") : "") + "\\.ollama\\models");
    
    // Default Ollama path
    ollamaModelsPath_ = "F:\\OllamaModels";
    
    // Default HF cache
    hfCachePath_ = std::filesystem::path(getenv("USERPROFILE") ? getenv("USERPROFILE") : "") / ".cache" / "huggingface" / "hub";
    
    RefreshCache();
    initialized_ = true;
    
    OutputDebugStringA("[ModelResolver] Initialized\n");
}

void ModelResolver::Shutdown() {
    cache_.clear();
    initialized_ = false;
}

//==============================================================================
// Configuration
//==============================================================================
void ModelResolver::AddSearchPath(const std::filesystem::path& path) {
    if (std::filesystem::exists(path)) {
        searchPaths_.push_back(path);
    }
}

void ModelResolver::SetOllamaModelsPath(const std::filesystem::path& path) {
    ollamaModelsPath_ = path;
}

void ModelResolver::SetHuggingFaceCache(const std::filesystem::path& path) {
    hfCachePath_ = path;
}

void ModelResolver::SetBlobStorePath(const std::filesystem::path& path) {
    blobStorePath_ = path;
}

//==============================================================================
// Resolution
//==============================================================================
std::optional<ModelInfo> ModelResolver::Resolve(const std::string& reference) {
    if (!initialized_) Initialize();
    
    // Check cache first
    auto it = cache_.find(reference);
    if (it != cache_.end()) {
        return it->second;
    }
    
    // Determine reference type
    if (std::filesystem::exists(reference)) {
        // Absolute or relative path
        ModelInfo info;
        info.path = reference;
        info.source = ModelSource::LocalPath;
        info.name = std::filesystem::path(reference).stem().string();
        info.sizeBytes = std::filesystem::file_size(reference);
        
        std::string ext = std::filesystem::path(reference).extension().string();
        if (ext == ".gguf") {
            info.format = "gguf";
            info = ProbeGGUF(info.path);
        } else if (ext == ".bin") {
            info.format = "bin";
        }
        
        cache_[reference] = info;
        return info;
    }
    
    // Try relative name resolution
    auto local = ResolveLocal(reference);
    if (local) return local;
    
    // Try blob reference
    if (reference.find("sha256-") == 0) {
        auto blob = ResolveBlob(reference);
        if (blob) return blob;
    }
    
    // Try HuggingFace format
    if (reference.find("/") != std::string::npos && reference.find(":") == std::string::npos) {
        auto hf = ResolveHuggingFace(reference);
        if (hf) return hf;
    }
    
    // Try Ollama API format
    if (reference.find("ollama:") == 0) {
        auto ollama = ResolveOllamaAPI(reference.substr(7));
        if (ollama) return ollama;
    }
    
    return std::nullopt;
}

std::optional<ModelInfo> ModelResolver::ResolveLocal(const std::string& name) {
    for (const auto& path : searchPaths_) {
        if (!std::filesystem::exists(path)) continue;
        
        // Search for files matching name
        for (const auto& entry : std::filesystem::directory_iterator(path)) {
            std::string filename = entry.path().filename().string();
            if (filename.find(name) != std::string::npos) {
                std::string ext = entry.path().extension().string();
                if (ext == ".gguf" || ext == ".bin" || ext == ".safetensors") {
                    ModelInfo info;
                    info.path = entry.path();
                    info.source = ModelSource::LocalPath;
                    info.name = entry.path().stem().string();
                    info.sizeBytes = entry.file_size();
                    info.format = ext.substr(1); // remove dot
                    
                    if (ext == ".gguf") {
                        info = ProbeGGUF(info.path);
                    }
                    
                    cache_[name] = info;
                    return info;
                }
            }
        }
    }
    return std::nullopt;
}

std::optional<ModelInfo> ModelResolver::ResolveBlob(const std::string& sha256) {
    if (!std::filesystem::exists(blobStorePath_)) return std::nullopt;
    
    std::filesystem::path blobPath = blobStorePath_ / sha256;
    if (std::filesystem::exists(blobPath)) {
        ModelInfo info;
        info.path = blobPath;
        info.source = ModelSource::OllamaBlob;
        info.name = sha256;
        info.sizeBytes = std::filesystem::file_size(blobPath);
        info.format = "blob";
        cache_[sha256] = info;
        return info;
    }
    return std::nullopt;
}

std::optional<ModelInfo> ModelResolver::ResolveHuggingFace(const std::string& repo) {
    if (!std::filesystem::exists(hfCachePath_)) return std::nullopt;
    
    // HF cache structure: models--TheBloke--Llama-2-7B-GGUF
    std::string cacheKey = "models--" + repo;
    std::replace(cacheKey.begin(), cacheKey.end(), '/', '-');
    
    std::filesystem::path modelDir = hfCachePath_ / cacheKey;
    if (std::filesystem::exists(modelDir)) {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(modelDir)) {
            if (entry.path().extension() == ".gguf") {
                ModelInfo info;
                info.path = entry.path();
                info.source = ModelSource::HuggingFace;
                info.name = repo;
                info.sizeBytes = entry.file_size();
                info.format = "gguf";
                info = ProbeGGUF(info.path);
                cache_[repo] = info;
                return info;
            }
        }
    }
    return std::nullopt;
}

std::optional<ModelInfo> ModelResolver::ResolveOllamaAPI(const std::string& modelName) {
    // Check Ollama models directory
    if (!std::filesystem::exists(ollamaModelsPath_)) return std::nullopt;
    
    std::filesystem::path modelDir = ollamaModelsPath_ / "models" / modelName;
    if (std::filesystem::exists(modelDir)) {
        for (const auto& entry : std::filesystem::directory_iterator(modelDir)) {
            if (entry.path().extension() == ".gguf") {
                ModelInfo info;
                info.path = entry.path();
                info.source = ModelSource::OllamaAPI;
                info.name = modelName;
                info.sizeBytes = entry.file_size();
                info.format = "gguf";
                info = ProbeGGUF(info.path);
                cache_["ollama:" + modelName] = info;
                return info;
            }
        }
    }
    return std::nullopt;
}

//==============================================================================
// Discovery
//==============================================================================
std::vector<ModelInfo> ModelResolver::ListAvailableModels() {
    if (!initialized_) Initialize();
    
    std::vector<ModelInfo> result;
    for (const auto& [_, info] : cache_) {
        result.push_back(info);
    }
    return result;
}

std::vector<ModelInfo> ModelResolver::ListModelsByFormat(const std::string& format) {
    std::vector<ModelInfo> result;
    for (const auto& [_, info] : cache_) {
        if (info.format == format) {
            result.push_back(info);
        }
    }
    return result;
}

std::vector<ModelInfo> ModelResolver::ListModelsByQuantization(const std::string& quant) {
    std::vector<ModelInfo> result;
    for (const auto& [_, info] : cache_) {
        if (info.quantization == quant) {
            result.push_back(info);
        }
    }
    return result;
}

//==============================================================================
// Cache Management
//==============================================================================
void ModelResolver::RefreshCache() {
    cache_.clear();
    
    for (const auto& path : searchPaths_) {
        if (std::filesystem::exists(path)) {
            ScanDirectory(path);
        }
    }
    
    if (std::filesystem::exists(ollamaModelsPath_)) {
        ScanOllamaModels();
    }
    
    if (std::filesystem::exists(blobStorePath_)) {
        ScanBlobStore();
    }
    
    if (std::filesystem::exists(hfCachePath_)) {
        ScanHuggingFaceCache();
    }
}

void ModelResolver::ClearCache() {
    cache_.clear();
}

//==============================================================================
// Scanning
//==============================================================================
void ModelResolver::ScanDirectory(const std::filesystem::path& dir) {
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".gguf") {
                ModelInfo info = ProbeGGUF(entry.path());
                cache_[info.name] = info;
            } else if (ext == ".bin") {
                ModelInfo info = ProbeBin(entry.path());
                cache_[info.name] = info;
            }
        }
    }
}

void ModelResolver::ScanOllamaModels() {
    std::filesystem::path modelsDir = ollamaModelsPath_ / "models";
    if (!std::filesystem::exists(modelsDir)) return;
    
    for (const auto& entry : std::filesystem::directory_iterator(modelsDir)) {
        if (entry.is_directory()) {
            for (const auto& file : std::filesystem::directory_iterator(entry.path())) {
                if (file.path().extension() == ".gguf") {
                    ModelInfo info = ProbeGGUF(file.path());
                    info.source = ModelSource::OllamaAPI;
                    cache_["ollama:" + entry.path().filename().string()] = info;
                }
            }
        }
    }
}

void ModelResolver::ScanBlobStore() {
    if (!std::filesystem::exists(blobStorePath_)) return;
    
    for (const auto& entry : std::filesystem::directory_iterator(blobStorePath_)) {
        if (entry.is_regular_file() && entry.path().filename().string().find("sha256-") == 0) {
            ModelInfo info;
            info.path = entry.path();
            info.source = ModelSource::OllamaBlob;
            info.name = entry.path().filename().string();
            info.sizeBytes = entry.file_size();
            info.format = "blob";
            cache_[info.name] = info;
        }
    }
}

void ModelResolver::ScanHuggingFaceCache() {
    if (!std::filesystem::exists(hfCachePath_)) return;
    
    for (const auto& entry : std::filesystem::directory_iterator(hfCachePath_)) {
        if (entry.is_directory() && entry.path().filename().string().find("models--") == 0) {
            std::string repo = entry.path().filename().string().substr(8); // remove "models--"
            std::replace(repo.begin(), repo.end(), '-', '/');
            
            for (const auto& file : std::filesystem::recursive_directory_iterator(entry.path())) {
                if (file.path().extension() == ".gguf") {
                    ModelInfo info = ProbeGGUF(file.path());
                    info.source = ModelSource::HuggingFace;
                    info.name = repo;
                    cache_[repo] = info;
                    break; // one per repo
                }
            }
        }
    }
}

//==============================================================================
// Probing
//==============================================================================
ModelInfo ModelResolver::ProbeGGUF(const std::filesystem::path& path) {
    ModelInfo info;
    info.path = path;
    info.source = ModelSource::LocalPath;
    info.name = path.stem().string();
    info.sizeBytes = std::filesystem::file_size(path);
    info.format = "gguf";
    
    // Extract quantization from filename
    info.quantization = ExtractQuantizationFromFilename(path.filename().string());
    
    // Try to read GGUF header for parameter count
    std::ifstream file(path, std::ios::binary);
    if (file) {
        char magic[4];
        file.read(magic, 4);
        if (magic[0] == 'G' && magic[1] == 'G' && magic[2] == 'U' && magic[3] == 'F') {
            // GGUF v3 header
            uint32_t version;
            file.read(reinterpret_cast<char*>(&version), 4);
            
            uint64_t tensorCount;
            file.read(reinterpret_cast<char*>(&tensorCount), 8);
            
            uint64_t metadataCount;
            file.read(reinterpret_cast<char*>(&metadataCount), 8);
            
            // Parameter count is typically in metadata
            // For now, estimate from file size
            info.parameterCount = info.sizeBytes / 2; // rough estimate for Q4
        }
    }
    
    return info;
}

ModelInfo ModelResolver::ProbeBin(const std::filesystem::path& path) {
    ModelInfo info;
    info.path = path;
    info.source = ModelSource::LocalPath;
    info.name = path.stem().string();
    info.sizeBytes = std::filesystem::file_size(path);
    info.format = "bin";
    return info;
}

std::string ModelResolver::ExtractQuantizationFromFilename(const std::string& filename) {
    // Common patterns: Q4_K_M, Q5_K_S, Q8_0, IQ2_XXS, etc.
    const char* patterns[] = {"Q4_K_M", "Q4_K_S", "Q5_K_M", "Q5_K_S", "Q8_0", 
                              "Q2_K", "Q3_K_M", "Q3_K_S", "Q6_K", "IQ2_XXS",
                              "IQ2_XS", "IQ3_XXS", "IQ4_XS"};
    
    for (const auto* pattern : patterns) {
        if (filename.find(pattern) != std::string::npos) {
            return pattern;
        }
    }
    return "unknown";
}

} // namespace RawrXD::Runtime

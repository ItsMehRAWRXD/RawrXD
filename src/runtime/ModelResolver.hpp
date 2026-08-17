//==============================================================================
// ModelResolver.hpp / ModelResolver.cpp
// Single authority for model discovery and resolution
// Phase 15B: Service Architecture
//
// All model references route through here. No subsystem owns model discovery.
// Supports: local paths, GGUF registry, Ollama blobs, HuggingFace cache
//==============================================================================

#pragma once

#include <filesystem>
#include <string>
#include <vector>
#include <optional>
#include <map>

namespace RawrXD::Runtime {

//==============================================================================
// Model Reference Types
//==============================================================================
enum class ModelSource {
    LocalPath,      // D:\models\model.gguf
    GGUFRegistry,   // Registered GGUF files
    OllamaBlob,     // sha256-xxx blob reference
    HuggingFace,    // TheBloke/Llama-2-7B-GGUF
    OllamaAPI,      // ollama:llama3.1
    RelativeName,   // "phi3-mini" → search all sources
};

struct ModelInfo {
    std::filesystem::path path;
    ModelSource source;
    std::string name;
    std::string format;     // "gguf", "bin", "safetensors"
    size_t sizeBytes = 0;
    size_t parameterCount = 0;
    std::string quantization; // "Q4_K_M", "Q5_K_S", etc.
    bool verified = false;   // SHA256 checksum verified
};

//==============================================================================
// Model Resolver
// Singleton. Thread-safe. Caches results.
//==============================================================================
class ModelResolver {
public:
    static ModelResolver& Instance();
    
    // Configuration
    void AddSearchPath(const std::filesystem::path& path);
    void SetOllamaModelsPath(const std::filesystem::path& path);
    void SetHuggingFaceCache(const std::filesystem::path& path);
    void SetBlobStorePath(const std::filesystem::path& path);
    
    // Resolution
    std::optional<ModelInfo> Resolve(const std::string& reference);
    std::optional<ModelInfo> ResolveLocal(const std::string& name);
    std::optional<ModelInfo> ResolveBlob(const std::string& sha256);
    std::optional<ModelInfo> ResolveHuggingFace(const std::string& repo);
    std::optional<ModelInfo> ResolveOllamaAPI(const std::string& modelName);
    
    // Discovery
    std::vector<ModelInfo> ListAvailableModels();
    std::vector<ModelInfo> ListModelsByFormat(const std::string& format);
    std::vector<ModelInfo> ListModelsByQuantization(const std::string& quant);
    
    // Validation
    bool VerifyModel(const std::filesystem::path& path);
    bool IsModelLoaded(const std::string& reference) const;
    
    // Cache management
    void RefreshCache();
    void ClearCache();
    
    // Lifecycle
    void Initialize();
    void Shutdown();

private:
    ModelResolver() = default;
    ~ModelResolver() = default;
    
    ModelResolver(const ModelResolver&) = delete;
    ModelResolver& operator=(const ModelResolver&) = delete;
    
    std::vector<std::filesystem::path> searchPaths_;
    std::filesystem::path ollamaModelsPath_;
    std::filesystem::path hfCachePath_;
    std::filesystem::path blobStorePath_;
    
    std::map<std::string, ModelInfo> cache_;
    bool initialized_ = false;
    
    void ScanDirectory(const std::filesystem::path& dir);
    void ScanOllamaModels();
    void ScanBlobStore();
    void ScanHuggingFaceCache();
    
    ModelInfo ProbeGGUF(const std::filesystem::path& path);
    ModelInfo ProbeBin(const std::filesystem::path& path);
    
    std::string ExtractQuantizationFromFilename(const std::string& filename);
};

} // namespace RawrXD::Runtime

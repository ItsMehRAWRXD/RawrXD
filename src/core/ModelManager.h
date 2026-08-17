#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <optional>

namespace RawrXD {

// Forward declarations
class AIProvider;

// Quantization format metadata
enum class QuantizationFormat {
    Q2_K,
    Q3_K,
    Q4_0,
    Q4_K_M,
    Q4_K_S,
    Q5_K,
    Q6_K,
    Q8_0,
    FP16,
    FP32,
    Unknown
};

// Model architecture type
enum class ModelArchitecture {
    Llama,
    Mistral,
    Mixtral,
    Qwen2,
    Phi3,
    Gemma,
    CodeLlama,
    DeepSeek,
    Unknown
};

// Model capabilities
struct ModelCapabilities {
    bool supportsChat = false;
    bool supportsCompletion = false;
    bool supportsFIM = false;           // Fill-in-the-middle
    bool supportsVision = false;
    bool supportsTools = false;
    bool supportsFunctionCalling = false;
    uint32_t maxContextLength = 4096;
    uint32_t embeddingSize = 4096;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    uint32_t vocabSize = 32000;
};

// Model metadata extracted from GGUF
struct ModelMetadata {
    std::string name;
    std::string filePath;
    std::string description;
    ModelArchitecture architecture = ModelArchitecture::Unknown;
    QuantizationFormat quantization = QuantizationFormat::Unknown;
    
    // Size info
    uint64_t fileSizeBytes = 0;
    uint64_t parameterCount = 0;
    uint64_t tensorMemoryRequired = 0;
    uint64_t kvCacheMemoryRequired = 0;
    uint64_t totalMemoryRequired = 0;
    
    // Capabilities
    ModelCapabilities capabilities;
    
    // Version info
    std::string version;
    std::string baseModel;  // e.g., "Llama-3-70B"
    std::vector<std::string> tags;
    
    // Extraction timestamp
    uint64_t indexedAt = 0;
};

// VRAM calculation result
struct VRAMRequirements {
    uint64_t modelWeightsBytes = 0;
    uint64_t kvCacheBytes = 0;
    uint64_t overheadBytes = 512 * 1024 * 1024;  // 512MB overhead
    uint64_t totalBytes = 0;
    uint64_t recommendedBytes = 0;  // With safety margin
    
    float utilizationPercent = 0.0f;  // Of available VRAM
    bool fitsInVRAM = false;
    bool fitsWithSwap = false;
};

// Model selection criteria
struct ModelSelectionCriteria {
    uint64_t availableVRAM = 0;
    uint32_t desiredContextLength = 8192;
    bool preferQuality = true;        // Higher quant vs more context
    bool requireChat = false;
    bool requireFIM = false;
    bool requireVision = false;
    std::string preferredArchitecture;  // "llama", "mistral", etc.
    uint32_t minContextLength = 4096;
    uint32_t maxContextLength = 131072;
};

// Model match score
struct ModelMatch {
    std::shared_ptr<ModelMetadata> metadata;
    float score = 0.0f;  // 0.0 - 1.0
    VRAMRequirements vram;
    std::string reason;
};

// Model load result
struct ModelLoadResult {
    bool success = false;
    std::string errorMessage;
    std::string loadedModelName;
    uint64_t loadTimeMs = 0;
    uint64_t actualVRAMUsed = 0;
    AIProvider* provider = nullptr;
};

// Model manager configuration
struct ModelManagerConfig {
    std::vector<std::string> modelPaths;  // Directories to scan
    std::string defaultModel;
    uint64_t minFreeVRAM = 1024 * 1024 * 1024;  // 1GB minimum free
    float vramSafetyMargin = 0.9f;  // Use 90% of available VRAM max
    bool autoUnloadOnSwitch = true;
    bool keepLastModelCached = true;
    uint32_t maxCachedModels = 2;
};

// Callback types
using ModelLoadCallback = std::function<void(const ModelLoadResult& result)>;
using ModelProgressCallback = std::function<void(const std::string& stage, float progress)>;

// ============================================================================
// Model Manager - Production Model Lifecycle Management
// ============================================================================

class ModelManager {
public:
    ModelManager();
    ~ModelManager();

    // Initialization
    bool Initialize(const ModelManagerConfig& config);
    void Shutdown();
    bool IsInitialized() const;

    // Model Discovery
    void ScanForModels();
    void ScanDirectory(const std::string& path);
    void AddModelPath(const std::string& path);
    void RemoveModelPath(const std::string& path);
    
    // Model Metadata
    std::vector<std::shared_ptr<ModelMetadata>> GetAvailableModels() const;
    std::shared_ptr<ModelMetadata> GetModelMetadata(const std::string& modelName) const;
    std::shared_ptr<ModelMetadata> GetModelByPath(const std::string& filePath) const;
    bool HasModel(const std::string& modelName) const;
    
    // VRAM Planning
    VRAMRequirements CalculateVRAMRequirements(
        const ModelMetadata& metadata,
        uint32_t contextLength
    ) const;
    
    uint64_t GetAvailableVRAM() const;
    uint64_t GetTotalVRAM() const;
    
    // Model Selection
    std::vector<ModelMatch> FindBestModels(
        const ModelSelectionCriteria& criteria,
        size_t maxResults = 5
    ) const;
    
    std::optional<ModelMatch> SelectBestModel(
        const ModelSelectionCriteria& criteria
    ) const;
    
    // Model Loading
    ModelLoadResult LoadModel(
        const std::string& modelName,
        uint32_t contextLength = 0,  // 0 = use model default
        AIProvider* provider = nullptr
    );
    
    ModelLoadResult LoadModelAsync(
        const std::string& modelName,
        ModelLoadCallback callback,
        uint32_t contextLength = 0
    );
    
    void UnloadModel(const std::string& modelName);
    void UnloadAllModels();
    
    // Current Model
    bool IsModelLoaded(const std::string& modelName) const;
    std::string GetCurrentModel() const;
    std::shared_ptr<ModelMetadata> GetCurrentModelMetadata() const;
    
    // Model Switching
    ModelLoadResult SwitchToModel(
        const std::string& modelName,
        uint32_t contextLength = 0
    );
    
    // Smart Selection (auto-pick based on VRAM/task)
    ModelLoadResult AutoSelectModel(
        const std::string& task,  // "chat", "completion", "fim", "vision"
        uint32_t contextLength = 0
    );
    
    // Quantization Recommendations
    QuantizationFormat RecommendQuantization(
        uint64_t availableVRAM,
        uint64_t modelParameterCount,
        uint32_t desiredContextLength
    ) const;
    
    std::vector<QuantizationFormat> GetSupportedQuants() const;
    uint64_t EstimateQuantSize(
        uint64_t parameterCount,
        QuantizationFormat quant
    ) const;
    
    // Persistence
    bool SaveModelIndex(const std::string& path) const;
    bool LoadModelIndex(const std::string& path);
    void RefreshModelIndex();
    
    // Events
    void SetProgressCallback(ModelProgressCallback callback);
    
    // Statistics
    struct Statistics {
        uint32_t modelsDiscovered = 0;
        uint32_t modelsLoaded = 0;
        uint32_t loadOperations = 0;
        uint32_t unloadOperations = 0;
        uint64_t totalLoadTimeMs = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
    };
    Statistics GetStatistics() const;
    void ResetStatistics();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Helper Functions
// ============================================================================

// Parse quantization from filename (e.g., "model-Q4_K_M.gguf")
QuantizationFormat ParseQuantizationFromFilename(const std::string& filename);

// Get human-readable quant name
std::string QuantizationToString(QuantizationFormat quant);

// Get bits per weight for quant
float GetBitsPerWeight(QuantizationFormat quant);

// Parse architecture from GGUF metadata
ModelArchitecture ParseArchitecture(const std::string& archString);

// Get VRAM requirement estimate for context length
uint64_t EstimateKVCacheSize(
    uint32_t contextLength,
    uint32_t numLayers,
    uint32_t embeddingSize,
    uint32_t numKVHeads
);

} // namespace RawrXD

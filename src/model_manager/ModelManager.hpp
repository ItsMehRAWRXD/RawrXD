// ============================================================================
// ModelManager.hpp - Intelligent Model Routing and Lifecycle
// Manages local GGUF models, VRAM allocation, and model selection
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>

namespace RawrXD {
namespace Models {

// Forward declarations
class GGUFLoader;
class InferenceEngine;

// ============================================================================
// Model Types
// ============================================================================
enum class ModelType {
    Unknown,
    Completion,      // Small fast model for ghost text
    Chat,            // Medium model for conversation
    Code,            // Code-specialized model
    Reasoning,       // Large model for architecture/design
    Embedding,       // Embedding model for RAG
    Multimodal       // Vision + text
};

// ============================================================================
// Model Capabilities
// ============================================================================
struct ModelCapabilities {
    bool supportsFIM = false;           // Fill-in-the-middle
    bool supportsTools = false;        // Tool calling
    bool supportsVision = false;       // Image input
    bool supportsStreaming = true;     // Token streaming
    bool supportsFunctionCalling = false;
    uint32_t maxContextLength = 4096;
    uint32_t vocabSize = 32000;
    std::vector<std::string> supportedLanguages;
};

// ============================================================================
// Model Info
// ============================================================================
struct ModelInfo {
    std::string id;                    // Unique identifier
    std::string name;                  // Display name
    std::string path;                  // Path to GGUF file
    ModelType type = ModelType::Unknown;
    ModelCapabilities capabilities;
    
    // Specifications
    std::string architecture;          // llama, qwen2, etc.
    uint32_t parameterCount = 0;       // In billions (e.g., 7 for 7B)
    std::string quantization;          // Q4_K_M, Q5_K_S, etc.
    uint64_t fileSize = 0;             // Bytes
    
    // VRAM requirements
    uint64_t vramRequired = 0;         // Estimated VRAM in bytes
    uint64_t vramWorking = 0;          // Working set size
    
    // Performance metrics
    float tokensPerSecond = 0.0f;
    float timeToFirstToken = 0.0f;
    float avgLatencyMs = 0.0f;
    
    // Status
    bool isDownloaded = false;
    bool isLoaded = false;
    bool isAvailable = false;
    std::chrono::system_clock::time_point lastUsed;
    uint32_t useCount = 0;
};

// ============================================================================
// VRAM Budget
// ============================================================================
struct VRAMBudget {
    uint64_t total = 0;
    uint64_t reserved = 0;
    uint64_t used = 0;
    uint64_t available = 0;
    
    uint64_t Available() const { return total - reserved - used; }
    bool CanFit(uint64_t size) const { return size <= Available(); }
    float Utilization() const { return total > 0 ? static_cast<float>(used) / total : 0.0f; }
};

// ============================================================================
// Task Requirements
// ============================================================================
struct TaskRequirements {
    ModelType preferredType = ModelType::Chat;
    uint32_t minContextLength = 4096;
    uint32_t expectedOutputTokens = 512;
    bool requiresFIM = false;
    bool requiresTools = false;
    bool requiresVision = false;
    float maxLatencyMs = 1000.0f;      // Target latency
    float minQuality = 0.8f;           // Minimum quality score
};

// ============================================================================
// Model Selection Result
// ============================================================================
struct ModelSelection {
    std::string modelId;
    std::string reason;
    float estimatedLatency = 0.0f;
    float estimatedQuality = 0.0f;
    uint64_t estimatedVRAM = 0;
    bool needsLoad = false;
    bool needsUnload = false;
};

// ============================================================================
// Model Manager
// Routes requests to appropriate models and manages VRAM
// ============================================================================
class ModelManager {
public:
    ModelManager();
    ~ModelManager();
    
    // Initialize with hardware detection
    bool Initialize();
    
    // Model registration
    bool RegisterModel(const ModelInfo& info);
    bool UnregisterModel(const std::string& modelId);
    void ScanForModels(const std::string& directory);
    
    // Model lifecycle
    bool LoadModel(const std::string& modelId);
    bool UnloadModel(const std::string& modelId);
    bool IsModelLoaded(const std::string& modelId) const;
    
    // Smart model selection
    ModelSelection SelectModelForTask(const TaskRequirements& requirements);
    ModelSelection SelectModelForCompletion();
    ModelSelection SelectModelForChat();
    ModelSelection SelectModelForCode();
    ModelSelection SelectModelForReasoning();
    
    // Get model info
    std::optional<ModelInfo> GetModelInfo(const std::string& modelId) const;
    std::vector<ModelInfo> GetAvailableModels() const;
    std::vector<ModelInfo> GetLoadedModels() const;
    std::vector<ModelInfo> GetModelsByType(ModelType type) const;
    
    // VRAM management
    VRAMBudget GetVRAMBudget() const;
    bool CanLoadModel(const std::string& modelId) const;
    std::vector<std::string> GetModelsToUnloadFor(uint64_t requiredVRAM);
    
    // Performance optimization
    void SetLatencyTarget(float targetMs);
    void SetQualityTarget(float target);
    void EnableAutoUnload(bool enable);
    void SetMaxLoadedModels(uint32_t max);
    
    // Preloading
    void PreloadModel(const std::string& modelId);
    void PreloadModelsForTask(const TaskRequirements& requirements);
    
    // Statistics
    struct Stats {
        uint64_t totalRequests = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t modelLoads = 0;
        uint64_t modelUnloads = 0;
        double avgLoadTimeMs = 0.0;
        double avgSelectionTimeMs = 0.0;
        VRAMBudget vram;
    };
    Stats GetStats() const;
    
    // Events
    using ModelLoadedCallback = std::function<void(const std::string&)>;
    using ModelUnloadedCallback = std::function<void(const std::string&)>;
    using VRAMPressureCallback = std::function<void(float)>;
    
    void OnModelLoaded(ModelLoadedCallback callback);
    void OnModelUnloaded(ModelUnloadedCallback callback);
    void OnVRAMPressure(VRAMPressureCallback callback);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Model Router
// High-level routing for different request types
// ============================================================================
class ModelRouter {
public:
    explicit ModelRouter(ModelManager* manager);
    ~ModelRouter();
    
    // Route completion request
    std::string RouteCompletion(
        const std::string& prefix,
        const std::string& suffix,
        const std::string& language
    );
    
    // Route chat request
    std::string RouteChat(
        const std::vector<std::pair<std::string, std::string>>& history,
        const std::string& message
    );
    
    // Route agent task
    std::string RouteAgentTask(
        const std::string& task,
        const std::vector<std::string>& tools
    );
    
    // Route embedding request
    std::string RouteEmbedding(const std::string& text);

private:
    ModelManager* manager_;
};

// ============================================================================
// Hardware Detection
// ============================================================================
struct HardwareInfo {
    std::string deviceName;
    uint64_t totalVRAM = 0;
    uint64_t freeVRAM = 0;
    uint32_t computeCapability = 0;
    bool supportsCUDA = false;
    bool supportsVulkan = false;
    bool supportsROCm = false;
    bool supportsMetal = false;
};

class HardwareDetector {
public:
    static HardwareInfo DetectGPU();
    static uint64_t GetAvailableVRAM();
    static std::vector<HardwareInfo> DetectAllGPUs();
};

// ============================================================================
// Model Downloader
// ============================================================================
class ModelDownloader {
public:
    using ProgressCallback = std::function<void(float percent, uint64_t downloaded, uint64_t total)>;
    
    bool DownloadModel(
        const std::string& url,
        const std::string& destination,
        ProgressCallback callback
    );
    
    bool VerifyChecksum(const std::string& path, const std::string& expectedHash);
    void CancelDownload();
    
    bool IsDownloading() const;
    float GetDownloadProgress() const;
};

} // namespace Models
} // namespace RawrXD

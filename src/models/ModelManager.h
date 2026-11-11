#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace RawrXD {

// ============================================================================
// Model Manager — Intelligent Model Selection and VRAM Planning
// Phase 15 — Product Layer
// ============================================================================
// Automatically selects optimal models based on:
// - Available VRAM
// - Task type (completion, chat, agent)
// - Performance requirements
// ============================================================================

// ============================================================================
// Hardware Detection
// ============================================================================
struct GPUInfo {
    std::string name;
    size_t vramBytes = 0;
    size_t freeVramBytes = 0;
    uint32_t computeCapability = 0;
    bool supportsFP16 = false;
    bool supportsBF16 = false;
    bool supportsINT8 = false;
    bool supportsINT4 = false;
};

struct HardwareInfo {
    std::vector<GPUInfo> gpus;
    size_t systemRamBytes = 0;
    uint32_t cpuCores = 0;
    bool hasAVX2 = false;
    bool hasAVX512 = false;
};

// ============================================================================
// Model Configuration
// ============================================================================
enum class Quantization {
    Q2_K,   // 2-bit
    Q3_K,   // 3-bit
    Q4_K,   // 4-bit (K-quant)
    Q4_0,   // 4-bit (legacy)
    Q5_K,   // 5-bit
    Q6_K,   // 6-bit
    Q8_0,   // 8-bit
    FP16,   // 16-bit float
    FP32    // 32-bit float
};

enum class TaskType {
    Completion,     // Ghost text (fast, low latency)
    Chat,           // Conversational (balanced)
    Agent,          // Autonomous agent (reasoning quality)
    Analysis,       // Code analysis (large context)
    Embedding       // Semantic search
};

struct ModelConfig {
    std::string name;
    std::string filePath;
    size_t parameterCount = 0;      // e.g., 7B, 13B, 34B
    size_t contextLength = 4096;
    Quantization quant = Quantization::Q4_K;
    
    // Performance characteristics
    double tokensPerSecond = 0.0;   // Measured decode speed
    double prefillSpeed = 0.0;      // Measured prefill speed
    double qualityScore = 0.0;      // Benchmark score (0-1)
    
    // VRAM requirements by quantization
    std::map<Quantization, size_t> vramRequirements;
};

// ============================================================================
// VRAM Planner
// ============================================================================
class VRAMPlanner {
public:
    struct Allocation {
        std::string modelName;
        size_t vramBytes;
        bool fits;
    };
    
    // Plan model loading for available VRAM
    static Allocation PlanModelLoad(
        const ModelConfig& model,
        const GPUInfo& gpu,
        size_t reservedVram = 512 * 1024 * 1024  // 512MB reserved
    );
    
    // Check if multiple models can coexist
    static bool CanCoexist(
        const std::vector<ModelConfig>& models,
        const GPUInfo& gpu
    );
    
    // Calculate KV cache size for context
    static size_t CalculateKVCacheSize(
        size_t contextLength,
        size_t hiddenSize,
        size_t numLayers,
        Quantization quant
    );
    
    // Estimate VRAM for model + KV cache
    static size_t EstimateTotalVRAM(
        const ModelConfig& model,
        size_t contextLength
    );
};

// ============================================================================
// Model Selector
// ============================================================================
class ModelSelector {
public:
    struct Selection {
        ModelConfig model;
        Quantization recommendedQuant;
        size_t estimatedVramBytes;
        std::string reasoning;
    };
    
    // Select best model for task
    static Selection SelectForTask(
        TaskType task,
        const HardwareInfo& hardware,
        const std::vector<ModelConfig>& availableModels
    );
    
    // Select by name with fallback
    static Selection SelectByName(
        const std::string& modelName,
        const HardwareInfo& hardware,
        const std::vector<ModelConfig>& availableModels
    );
    
    // Rank models by suitability
    static std::vector<Selection> RankModels(
        TaskType task,
        const HardwareInfo& hardware,
        const std::vector<ModelConfig>& availableModels
    );

private:
    static float ScoreModel(
        const ModelConfig& model,
        TaskType task,
        const HardwareInfo& hardware
    );
    
    static Quantization SelectQuantization(
        const ModelConfig& model,
        size_t availableVram
    );
};

// ============================================================================
// Model Loader
// ============================================================================
class ModelLoader {
public:
    struct LoadResult {
        bool success = false;
        std::string error;
        size_t vramUsed = 0;
        size_t loadTimeMs = 0;
    };
    
    // Load model with progress callback
    static LoadResult Load(
        const ModelConfig& model,
        std::function<void(float progress)> onProgress = nullptr
    );
    
    // Unload model
    static bool Unload(const std::string& modelName);
    
    // Check if model is loaded
    static bool IsLoaded(const std::string& modelName);
    
    // Get loaded model info
    static std::vector<std::string> GetLoadedModels();
};

// ============================================================================
// Model Registry
// ============================================================================
class ModelRegistry {
public:
    // Register available models
    void RegisterModel(const ModelConfig& config);
    void RegisterFromDirectory(const std::string& dirPath);
    
    // Query
    std::vector<ModelConfig> GetAllModels() const;
    std::vector<ModelConfig> GetModelsBySize(size_t minParams, size_t maxParams) const;
    bool FindModel(const std::string& name, ModelConfig& out) const;
    
    // Default models
    ModelConfig GetDefaultModel() const;
    void SetDefaultModel(const std::string& name);
    
private:
    std::map<std::string, ModelConfig> models_;
    std::string defaultModel_;
};

// ============================================================================
// Model Manager — Main Facade
// ============================================================================
class ModelManager {
public:
    ModelManager();
    ~ModelManager();
    
    // Initialize with hardware detection
    bool Initialize();
    
    // Scan for available models
    void ScanModels(const std::vector<std::string>& searchPaths);
    
    // Select and load model for task
    bool LoadModelForTask(TaskType task);
    
    // Load specific model
    bool LoadModel(const std::string& modelName);
    
    // Get current model info
    std::string GetCurrentModel() const;
    ModelConfig GetCurrentModelConfig() const;
    
    // Switch quantization (unload + reload)
    bool ChangeQuantization(Quantization quant);
    
    // Status
    bool IsReady() const;
    std::string GetStatus() const;
    HardwareInfo GetHardwareInfo() const;
    
    // VRAM info
    size_t GetAvailableVRAM() const;
    size_t GetUsedVRAM() const;
    
    // Recommendations
    std::string GetRecommendation(TaskType task) const;
    
private:
    std::unique_ptr<ModelRegistry> registry_;
    HardwareInfo hardware_;
    ModelConfig currentModel_;
    bool initialized_ = false;
    bool modelLoaded_ = false;
    
    void DetectHardware();
    void DetectGPUs();
    void DetectCPU();
};

} // namespace RawrXD

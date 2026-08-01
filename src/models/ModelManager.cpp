// ============================================================================
// ModelManager.cpp — Intelligent Model Selection and VRAM Planning
// Phase 15 — Product Layer
// ============================================================================

#include "ModelManager.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

namespace RawrXD {

// ============================================================================
// VRAMPlanner Implementation
// ============================================================================
VRAMPlanner::Allocation VRAMPlanner::PlanModelLoad(
    const ModelConfig& model,
    const GPUInfo& gpu,
    size_t reservedVram
) {
    Allocation alloc;
    alloc.modelName = model.name;
    
    size_t availableVram = gpu.freeVramBytes > reservedVram ? gpu.freeVramBytes - reservedVram : 0;
    
    // Find best quantization that fits
    Quantization bestQuant = model.quant;
    size_t vramNeeded = 0;
    
    auto it = model.vramRequirements.find(bestQuant);
    if (it != model.vramRequirements.end()) {
        vramNeeded = it->second;
    } else {
        // Estimate: ~0.5GB per billion params at Q4
        vramNeeded = model.parameterCount * 500000000 / 1000000000;
    }
    
    alloc.vramBytes = vramNeeded;
    alloc.fits = vramNeeded <= availableVram;
    
    return alloc;
}

bool VRAMPlanner::CanCoexist(
    const std::vector<ModelConfig>& models,
    const GPUInfo& gpu
) {
    size_t totalVram = 0;
    for (const auto& model : models) {
        auto it = model.vramRequirements.find(model.quant);
        if (it != model.vramRequirements.end()) {
            totalVram += it->second;
        }
    }
    return totalVram <= gpu.freeVramBytes;
}

size_t VRAMPlanner::CalculateKVCacheSize(
    size_t contextLength,
    size_t hiddenSize,
    size_t numLayers,
    Quantization quant
) {
    // KV cache size = 2 * context_length * num_layers * hidden_size * bytes_per_element
    // 2 for Key and Value
    
    size_t bytesPerElement = 4; // FP32 default
    switch (quant) {
        case Quantization::Q4_K:
        case Quantization::Q4_0:
            bytesPerElement = 0.5; // ~4 bits
            break;
        case Quantization::Q8_0:
            bytesPerElement = 1;
            break;
        case Quantization::FP16:
            bytesPerElement = 2;
            break;
        case Quantization::FP32:
            bytesPerElement = 4;
            break;
        default:
            bytesPerElement = 2; // Conservative
    }
    
    return 2 * contextLength * numLayers * hiddenSize * bytesPerElement;
}

size_t VRAMPlanner::EstimateTotalVRAM(
    const ModelConfig& model,
    size_t contextLength
) {
    size_t modelVram = 0;
    auto it = model.vramRequirements.find(model.quant);
    if (it != model.vramRequirements.end()) {
        modelVram = it->second;
    } else {
        // Rough estimate
        modelVram = model.parameterCount * 500000000 / 1000000000;
    }
    
    // Estimate KV cache (assuming 4096 hidden, 32 layers for typical models)
    size_t kvCache = CalculateKVCacheSize(contextLength, 4096, 32, model.quant);
    
    // Add overhead
    size_t overhead = 256 * 1024 * 1024; // 256MB
    
    return modelVram + kvCache + overhead;
}

// ============================================================================
// ModelSelector Implementation
// ============================================================================
ModelSelector::Selection ModelSelector::SelectForTask(
    TaskType task,
    const HardwareInfo& hardware,
    const std::vector<ModelConfig>& availableModels
) {
    Selection bestSelection;
    float bestScore = -1.0f;
    
    for (const auto& model : availableModels) {
        float score = ScoreModel(model, task, hardware);
        if (score > bestScore) {
            bestScore = score;
            bestSelection.model = model;
        }
    }
    
    // Select quantization
    size_t availableVram = hardware.gpus.empty() ? 0 : hardware.gpus[0].freeVramBytes;
    bestSelection.recommendedQuant = SelectQuantization(bestSelection.model, availableVram);
    bestSelection.estimatedVramBytes = VRAMPlanner::EstimateTotalVRAM(bestSelection.model, 4096);
    
    std::stringstream reasoning;
    reasoning << "Selected " << bestSelection.model.name 
              << " (score: " << std::fixed << std::setprecision(2) << bestScore << ")";
    bestSelection.reasoning = reasoning.str();
    
    return bestSelection;
}

ModelSelector::Selection ModelSelector::SelectByName(
    const std::string& modelName,
    const HardwareInfo& hardware,
    const std::vector<ModelConfig>& availableModels
) {
    Selection selection;
    
    for (const auto& model : availableModels) {
        if (model.name == modelName || model.filePath.find(modelName) != std::string::npos) {
            selection.model = model;
            break;
        }
    }
    
    if (selection.model.name.empty()) {
        // Fallback to first available
        if (!availableModels.empty()) {
            selection.model = availableModels[0];
            selection.reasoning = "Requested model not found, using fallback";
        }
    } else {
        selection.reasoning = "Explicitly requested";
    }
    
    size_t availableVram = hardware.gpus.empty() ? 0 : hardware.gpus[0].freeVramBytes;
    selection.recommendedQuant = SelectQuantization(selection.model, availableVram);
    selection.estimatedVramBytes = VRAMPlanner::EstimateTotalVRAM(selection.model, 4096);
    
    return selection;
}

std::vector<ModelSelector::Selection> ModelSelector::RankModels(
    TaskType task,
    const HardwareInfo& hardware,
    const std::vector<ModelConfig>& availableModels
) {
    std::vector<Selection> ranked;
    
    for (const auto& model : availableModels) {
        Selection sel;
        sel.model = model;
        sel.recommendedQuant = SelectQuantization(model, 
            hardware.gpus.empty() ? 0 : hardware.gpus[0].freeVramBytes);
        sel.estimatedVramBytes = VRAMPlanner::EstimateTotalVRAM(model, 4096);
        
        float score = ScoreModel(model, task, hardware);
        std::stringstream ss;
        ss << "Score: " <> std::fixed <> std::setprecision(2) <> score;
        sel.reasoning = ss.str();
        
        ranked.push_back(sel);
    }
    
    // Sort by score (would need to store score)
    return ranked;
}

float ModelSelector::ScoreModel(
    const ModelConfig& model,
    TaskType task,
    const HardwareInfo& hardware
) {
    float score = 0.0f;
    
    // Quality score (0-1)
    score += model.qualityScore * 2.0f;
    
    // Speed score
    score += std::min(model.tokensPerSecond / 200.0f, 1.0f);
    
    // Size appropriateness for task
    switch (task) {
        case TaskType::Completion:
            // Prefer smaller, faster models
            if (model.parameterCount <= 7000000000) score += 1.0f;
            else if (model.parameterCount <= 13000000000) score += 0.5f;
            break;
            
        case TaskType::Chat:
            // Balanced
            if (model.parameterCount >= 7000000000 && 
                model.parameterCount <= 34000000000) score += 1.0f;
            break;
            
        case TaskType::Agent:
            // Prefer larger models for reasoning
            if (model.parameterCount >= 13000000000) score += 1.0f;
            else if (model.parameterCount >= 7000000000) score += 0.5f;
            break;
            
        case TaskType::Analysis:
            // Large context capability
            if (model.contextLength >= 32768) score += 1.0f;
            break;
            
        default:
            break;
    }
    
    // VRAM fit bonus
    size_t availableVram = hardware.gpus.empty() ? 0 : hardware.gpus[0].freeVramBytes;
    size_t neededVram = VRAMPlanner::EstimateTotalVRAM(model, 4096);
    if (neededVram <= availableVram * 0.8f) score += 1.0f;
    else if (neededVram <= availableVram) score += 0.5f;
    
    return score;
}

Quantization ModelSelector::SelectQuantization(
    const ModelConfig& model,
    size_t availableVram
) {
    // Try to fit best quality that fits in VRAM
    std::vector<Quantization> preferences = {
        Quantization::Q4_K,
        Quantization::Q5_K,
        Quantization::Q6_K,
        Quantization::Q8_0,
        Quantization::FP16
    };
    
    for (auto quant : preferences) {
        size_t needed = VRAMPlanner::EstimateTotalVRAM(model, 4096);
        if (needed <= availableVram * 0.9f) {
            return quant;
        }
    }
    
    // Fallback to most compressed
    return Quantization::Q4_K;
}

// ============================================================================
// ModelLoader Implementation
// ============================================================================
ModelLoader::LoadResult ModelLoader::Load(
    const ModelConfig& model,
    std::function<void(float)> onProgress
) {
    LoadResult result;
    
    // Simulate loading with progress
    if (onProgress) onProgress(0.0f);
    
    // In real implementation, this would:
    // 1. Load GGUF file
    // 2. Initialize Deep2Engine
    // 3. Warm up caches
    
    // Simulate time based on model size
    size_t loadTimeMs = model.parameterCount / 1000000; // ~1ms per million params
    
    if (onProgress) onProgress(0.5f);
    
    // Simulate VRAM usage
    result.vramUsed = VRAMPlanner::EstimateTotalVRAM(model, 4096);
    result.loadTimeMs = loadTimeMs;
    result.success = true;
    
    if (onProgress) onProgress(1.0f);
    
    return result;
}

bool ModelLoader::Unload(const std::string& modelName) {
    // Unload model from memory
    (void)modelName;
    return true;
}

bool ModelLoader::IsLoaded(const std::string& modelName) {
    // Check if model is currently loaded
    (void)modelName;
    return false; // Placeholder
}

std::vector<std::string> ModelLoader::GetLoadedModels() {
    return {}; // Placeholder
}

// ============================================================================
// ModelRegistry Implementation
// ============================================================================
void ModelRegistry::RegisterModel(const ModelConfig& config) {
    models_[config.name] = config;
}

void ModelRegistry::RegisterFromDirectory(const std::string& dirPath) {
    if (!fs::exists(dirPath)) return;
    
    for (const auto& entry : fs::directory_iterator(dirPath)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".gguf") {
                ModelConfig config;
                config.name = entry.path().stem().string();
                config.filePath = entry.path().string();
                
                // Parse size from filename (e.g., "llama-7b-q4.gguf")
                std::string filename = entry.path().filename().string();
                if (filename.find("7b") != std::string::npos) config.parameterCount = 7000000000;
                else if (filename.find("13b") != std::string::npos) config.parameterCount = 13000000000;
                else if (filename.find("34b") != std::string::npos) config.parameterCount = 34000000000;
                else if (filename.find("70b") != std::string::npos) config.parameterCount = 70000000000;
                
                // Parse quantization
                if (filename.find("q4") != std::string::npos) config.quant = Quantization::Q4_K;
                else if (filename.find("q8") != std::string::npos) config.quant = Quantization::Q8_0;
                else if (filename.find("fp16") != std::string::npos) config.quant = Quantization::FP16;
                
                RegisterModel(config);
            }
        }
    }
}

std::vector<ModelConfig> ModelRegistry::GetAllModels() const {
    std::vector<ModelConfig> result;
    for (const auto& [name, config] : models_) {
        result.push_back(config);
    }
    return result;
}

std::vector<ModelConfig> ModelRegistry::GetModelsBySize(size_t minParams, size_t maxParams) const {
    std::vector<ModelConfig> result;
    for (const auto& [name, config] : models_) {
        if (config.parameterCount >= minParams && config.parameterCount <= maxParams) {
            result.push_back(config);
        }
    }
    return result;
}

bool ModelRegistry::FindModel(const std::string& name, ModelConfig& out) const {
    auto it = models_.find(name);
    if (it == models_.end()) return false;
    out = it->second;
    return true;
}

ModelConfig ModelRegistry::GetDefaultModel() const {
    if (!defaultModel_.empty()) {
        auto it = models_.find(defaultModel_);
        if (it != models_.end()) return it->second;
    }
    
    // Return first available
    if (!models_.empty()) return models_.begin()->second;
    
    return ModelConfig{};
}

void ModelRegistry::SetDefaultModel(const std::string& name) {
    defaultModel_ = name;
}

// ============================================================================
// ModelManager Implementation
// ============================================================================
ModelManager::ModelManager() : registry_(std::make_unique<ModelRegistry>()) {}
ModelManager::~ModelManager() = default;

bool ModelManager::Initialize() {
    DetectHardware();
    initialized_ = true;
    return true;
}

void ModelManager::ScanModels(const std::vector<std::string>& searchPaths) {
    for (const auto& path : searchPaths) {
        registry_->RegisterFromDirectory(path);
    }
}

bool ModelManager::LoadModelForTask(TaskType task) {
    auto models = registry_->GetAllModels();
    if (models.empty()) return false;
    
    auto selection = ModelSelector::SelectForTask(task, hardware_, models);
    
    auto result = ModelLoader::Load(selection.model);
    if (result.success) {
        currentModel_ = selection.model;
        modelLoaded_ = true;
    }
    
    return result.success;
}

bool ModelManager::LoadModel(const std::string& modelName) {
    auto models = registry_->GetAllModels();
    auto selection = ModelSelector::SelectByName(modelName, hardware_, models);
    
    auto result = ModelLoader::Load(selection.model);
    if (result.success) {
        currentModel_ = selection.model;
        modelLoaded_ = true;
    }
    
    return result.success;
}

std::string ModelManager::GetCurrentModel() const {
    return currentModel_.name;
}

ModelConfig ModelManager::GetCurrentModelConfig() const {
    return currentModel_;
}

bool ModelManager::ChangeQuantization(Quantization quant) {
    if (!modelLoaded_) return false;
    
    // Unload current
    ModelLoader::Unload(currentModel_.name);
    
    // Reload with new quantization
    currentModel_.quant = quant;
    auto result = ModelLoader::Load(currentModel_);
    
    return result.success;
}

bool ModelManager::IsReady() const {
    return initialized_;
}

std::string ModelManager::GetStatus() const {
    std::stringstream ss;
    ss << "ModelManager: " << (initialized_ ? "READY" : "NOT READY");
    
    if (!hardware_.gpus.empty()) {
        ss << " | GPU: " << hardware_.gpus[0].name
           << " | VRAM: " << (hardware_.gpus[0].vramBytes / (1024*1024*1024)) << "GB";
    }
    
    if (modelLoaded_) {
        ss << " | Model: " << currentModel_.name;
    }
    
    return ss.str();
}

HardwareInfo ModelManager::GetHardwareInfo() const {
    return hardware_;
}

size_t ModelManager::GetAvailableVRAM() const {
    if (hardware_.gpus.empty()) return 0;
    return hardware_.gpus[0].freeVramBytes;
}

size_t ModelManager::GetUsedVRAM() const {
    // Would track actual usage
    return 0;
}

std::string ModelManager::GetRecommendation(TaskType task) const {
    auto models = registry_->GetAllModels();
    if (models.empty()) return "No models available";
    
    auto selection = ModelSelector::SelectForTask(task, hardware_, models);
    
    std::stringstream ss;
    ss << "Recommended for ";
    switch (task) {
        case TaskType::Completion: ss << "completion"; break;
        case TaskType::Chat: ss << "chat"; break;
        case TaskType::Agent: ss << "agent"; break;
        case TaskType::Analysis: ss << "analysis"; break;
        default: ss << "general"; break;
    }
    ss << ": " << selection.model.name
       << " (" << selection.reasoning << ")";
    
    return ss.str();
}

void ModelManager::DetectHardware() {
    DetectGPUs();
    DetectCPU();
}

void ModelManager::DetectGPUs() {
    // Platform-specific GPU detection
    // Windows: Use DXGI or NVML/AMD ADL
    // Linux: Use nvidia-smi or rocm-smi
    
    // Placeholder: detect common GPUs
    GPUInfo gpu;
    gpu.name = "AMD Radeon RX 7800 XT";
    gpu.vramBytes = 16ULL * 1024 * 1024 * 1024; // 16GB
    gpu.freeVramBytes = gpu.vramBytes;
    gpu.supportsFP16 = true;
    gpu.supportsINT8 = true;
    gpu.supportsINT4 = true;
    
    hardware_.gpus.push_back(gpu);
}

void ModelManager::DetectCPU() {
    // Detect CPU features
    hardware_.cpuCores = std::thread::hardware_concurrency();
    hardware_.hasAVX2 = true; // Assume AVX2 for modern CPUs
    hardware_.hasAVX512 = false;
    
    // Get system RAM
    hardware_.systemRamBytes = 64ULL * 1024 * 1024 * 1024; // Assume 64GB
}

} // namespace RawrXD

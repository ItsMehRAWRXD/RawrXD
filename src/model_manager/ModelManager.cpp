// ============================================================================
// ModelManager.cpp - Model Routing and Lifecycle Implementation
// ============================================================================

#include "ModelManager.hpp"
#include <iostream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace Models {

// ============================================================================
// Implementation
// ============================================================================
class ModelManager::Impl {
public:
    std::map<std::string, ModelInfo> models_;
    std::set<std::string> loadedModels_;
    VRAMBudget vramBudget_;
    
    // Configuration
    float latencyTarget_ = 500.0f;
    float qualityTarget_ = 0.8f;
    bool autoUnload_ = true;
    uint32_t maxLoadedModels_ = 3;
    
    // Statistics
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    // Callbacks
    ModelLoadedCallback onModelLoaded_;
    ModelUnloadedCallback onModelUnloaded_;
    VRAMPressureCallback onVRAMPressure_;
    
    // Hardware info
    HardwareInfo hardware_;
    
    Impl() {
        hardware_ = HardwareDetector::DetectGPU();
        vramBudget_.total = hardware_.totalVRAM;
        vramBudget_.available = hardware_.totalVRAM;
    }
    
    float ScoreModelForTask(const ModelInfo& model, const TaskRequirements& req) {
        float score = 0.0f;
        
        // Type match
        if (model.type == req.preferredType) {
            score += 0.3f;
        } else if (req.preferredType == ModelType::Completion && model.type == ModelType::Code) {
            score += 0.2f;  // Code models are good for completion
        }
        
        // Capability match
        if (req.requiresFIM && model.capabilities.supportsFIM) {
            score += 0.2f;
        }
        if (req.requiresTools && model.capabilities.supportsTools) {
            score += 0.2f;
        }
        
        // Context length
        if (model.capabilities.maxContextLength >= req.minContextLength) {
            score += 0.1f;
        }
        
        // Latency (lower is better)
        if (model.avgLatencyMs > 0 && model.avgLatencyMs <= req.maxLatencyMs) {
            score += 0.1f * (1.0f - model.avgLatencyMs / req.maxLatencyMs);
        }
        
        // Quality (based on parameter count as proxy)
        float quality = std::min(model.parameterCount / 70.0f, 1.0f);  // 70B = max
        if (quality >= req.minQuality) {
            score += 0.1f * quality;
        }
        
        // Prefer loaded models (no load latency)
        if (model.isLoaded) {
            score += 0.15f;
        }
        
        // Penalize if VRAM insufficient
        if (!vramBudget_.CanFit(model.vramRequired)) {
            score -= 0.5f;
        }
        
        return score;
    }
    
    bool UnloadModelToFreeVRAM(uint64_t requiredBytes) {
        // Find least recently used model
        std::string lruModel;
        std::chrono::system_clock::time_point oldestTime = std::chrono::system_clock::now();
        
        for (const auto& modelId : loadedModels_) {
            auto it = models_.find(modelId);
            if (it != models_.end()) {
                if (it->second.lastUsed < oldestTime) {
                    oldestTime = it->second.lastUsed;
                    lruModel = modelId;
                }
            }
        }
        
        if (!lruModel.empty()) {
            // Unload the model
            auto it = models_.find(lruModel);
            if (it != models_.end()) {
                it->second.isLoaded = false;
                vramBudget_.used -= it->second.vramWorking;
                loadedModels_.erase(lruModel);
                
                if (onModelUnloaded_) {
                    onModelUnloaded_(lruModel);
                }
                
                stats_.modelUnloads++;
                
                return vramBudget_.CanFit(requiredBytes);
            }
        }
        
        return false;
    }
};

// ============================================================================
// ModelManager Public Interface
// ============================================================================
ModelManager::ModelManager() : pImpl(std::make_unique<Impl>()) {}
ModelManager::~ModelManager() = default;

bool ModelManager::Initialize() {
    std::cout << "[ModelManager] Initializing...\n";
    std::cout << "  GPU: " << pImpl->hardware_.deviceName << "\n";
    std::cout << "  VRAM: " << (pImpl->hardware_.totalVRAM / 1024 / 1024) << " MB\n";
    
    // Scan for existing models
    // This would scan a models directory
    
    return true;
}

bool ModelManager::RegisterModel(const ModelInfo& info) {
    if (info.id.empty()) {
        std::cerr << "[ModelManager] Cannot register model with empty ID\n";
        return false;
    }
    
    pImpl->models_[info.id] = info;
    
    std::cout << "[ModelManager] Registered model: " << info.name 
              << " (" <> info.parameterCount << "B " << info.quantization << ")\n";
    
    return true;
}

bool ModelManager::UnregisterModel(const std::string& modelId) {
    auto it = pImpl->models_.find(modelId);
    if (it == pImpl->models_.end()) {
        return false;
    }
    
    // Unload if loaded
    if (it->second.isLoaded) {
        UnloadModel(modelId);
    }
    
    pImpl->models_.erase(it);
    return true;
}

void ModelManager::ScanForModels(const std::string& directory) {
    std::cout << "[ModelManager] Scanning for models in: " << directory << "\n";
    
    // This would scan for .gguf files and register them
    // For now, register some default models
    
    ModelInfo completionModel;
    completionModel.id = "qwen2.5-coder-7b-q4";
    completionModel.name = "Qwen2.5 Coder 7B Q4";
    completionModel.path = directory + "/qwen2.5-coder-7b-instruct-q4_k_m.gguf";
    completionModel.type = ModelType::Completion;
    completionModel.architecture = "qwen2";
    completionModel.parameterCount = 7;
    completionModel.quantization = "Q4_K_M";
    completionModel.vramRequired = 5ULL * 1024 * 1024 * 1024;  // ~5GB
    completionModel.capabilities.supportsFIM = true;
    completionModel.capabilities.maxContextLength = 32768;
    RegisterModel(completionModel);
    
    ModelInfo chatModel;
    chatModel.id = "qwen2.5-14b-q4";
    chatModel.name = "Qwen2.5 14B Q4";
    chatModel.path = directory + "/qwen2.5-14b-instruct-q4_k_m.gguf";
    chatModel.type = ModelType::Chat;
    chatModel.architecture = "qwen2";
    chatModel.parameterCount = 14;
    chatModel.quantization = "Q4_K_M";
    chatModel.vramRequired = 10ULL * 1024 * 1024 * 1024;  // ~10GB
    chatModel.capabilities.supportsTools = true;
    chatModel.capabilities.maxContextLength = 32768;
    RegisterModel(chatModel);
    
    ModelInfo reasoningModel;
    reasoningModel.id = "deepseek-r1-32b-q4";
    reasoningModel.name = "DeepSeek R1 32B Q4";
    reasoningModel.path = directory + "/deepseek-r1-distill-qwen-32b-q4_k_m.gguf";
    reasoningModel.type = ModelType::Reasoning;
    reasoningModel.architecture = "qwen2";
    reasoningModel.parameterCount = 32;
    reasoningModel.quantization = "Q4_K_M";
    reasoningModel.vramRequired = 20ULL * 1024 * 1024 * 1024;  // ~20GB
    reasoningModel.capabilities.supportsTools = true;
    reasoningModel.capabilities.maxContextLength = 131072;
    RegisterModel(reasoningModel);
}

bool ModelManager::LoadModel(const std::string& modelId) {
    auto it = pImpl->models_.find(modelId);
    if (it == pImpl->models_.end()) {
        std::cerr << "[ModelManager] Model not found: " << modelId << "\n";
        return false;
    }
    
    ModelInfo& model = it->second;
    
    if (model.isLoaded) {
        model.lastUsed = std::chrono::system_clock::now();
        return true;
    }
    
    // Check VRAM
    if (!pImpl->vramBudget_.CanFit(model.vramRequired)) {
        // Try to free VRAM
        if (pImpl->autoUnload_) {
            if (!pImpl->UnloadModelToFreeVRAM(model.vramRequired)) {
                std::cerr << "[ModelManager] Insufficient VRAM to load: " << modelId << "\n";
                return false;
            }
        } else {
            std::cerr << "[ModelManager] Insufficient VRAM to load: " << modelId << "\n";
            return false;
        }
    }
    
    // Load the model
    std::cout << "[ModelManager] Loading model: " << model.name << "\n";
    
    // Simulate load time
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // In real implementation, this would load the GGUF file
    model.isLoaded = true;
    model.isAvailable = true;
    model.lastUsed = std::chrono::system_clock::now();
    
    pImpl->vramBudget_.used += model.vramWorking;
    pImpl->loadedModels_.insert(modelId);
    
    auto endTime = std::chrono::high_resolution_clock::now();
    double loadTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    // Update stats
    {
        std::lock_guard<std::mutex> lock(pImpl->statsMutex_);
        pImpl->stats_.modelLoads++;
        pImpl->stats_.avgLoadTimeMs = (pImpl->stats_.avgLoadTimeMs * (pImpl->stats_.modelLoads - 1) + loadTimeMs)
                                        / pImpl->stats_.modelLoads;
    }
    
    if (pImpl->onModelLoaded_) {
        pImpl->onModelLoaded_(modelId);
    }
    
    std::cout << "[ModelManager] Loaded: " << model.name << "\n";
    return true;
}

bool ModelManager::UnloadModel(const std::string& modelId) {
    auto it = pImpl->models_.find(modelId);
    if (it == pImpl->models_.end()) {
        return false;
    }
    
    ModelInfo& model = it->second;
    
    if (!model.isLoaded) {
        return true;
    }
    
    std::cout << "[ModelManager] Unloading model: " << model.name << "\n";
    
    model.isLoaded = false;
    pImpl->vramBudget_.used -= model.vramWorking;
    pImpl->loadedModels_.erase(modelId);
    
    // Update stats
    pImpl->stats_.modelUnloads++;
    
    if (pImpl->onModelUnloaded_) {
        pImpl->onModelUnloaded_(modelId);
    }
    
    return true;
}

bool ModelManager::IsModelLoaded(const std::string& modelId) const {
    auto it = pImpl->models_.find(modelId);
    if (it == pImpl->models_.end()) {
        return false;
    }
    return it->second.isLoaded;
}

ModelSelection ModelManager::SelectModelForTask(const TaskRequirements& requirements) {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    ModelSelection selection;
    float bestScore = -1.0f;
    
    for (auto& [id, model] : pImpl->models_) {
        float score = pImpl->ScoreModelForTask(model, requirements);
        
        if (score > bestScore) {
            bestScore = score;
            selection.modelId = id;
            selection.estimatedLatency = model.avgLatencyMs;
            selection.estimatedQuality = std::min(model.parameterCount / 70.0f, 1.0f);
            selection.estimatedVRAM = model.vramRequired;
            selection.needsLoad = !model.isLoaded;
        }
    }
    
    if (selection.modelId.empty()) {
        selection.reason = "No suitable model found";
        return selection;
    }
    
    // Build reason string
    auto it = pImpl->models_.find(selection.modelId);
    if (it != pImpl->models_.end()) {
        selection.reason = "Selected " + it->second.name + " (score: " + std::to_string(bestScore) + ")";
    }
    
    // Check if we need to unload other models
    if (selection.needsLoad && !pImpl->vramBudget_.CanFit(selection.estimatedVRAM)) {
        selection.needsUnload = true;
    }
    
    // Update stats
    auto endTime = std::chrono::high_resolution_clock::now();
    double selectionTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    {
        std::lock_guard<std::mutex> lock(pImpl->statsMutex_);
        pImpl->stats_.totalRequests++;
        pImpl->stats_.avgSelectionTimeMs = (pImpl->stats_.avgSelectionTimeMs * (pImpl->stats_.totalRequests - 1) + selectionTimeMs)
                                              / pImpl->stats_.totalRequests;
    }
    
    return selection;
}

ModelSelection ModelManager::SelectModelForCompletion() {
    TaskRequirements req;
    req.preferredType = ModelType::Completion;
    req.requiresFIM = true;
    req.maxLatencyMs = 100.0f;  // Fast completion
    req.expectedOutputTokens = 50;
    return SelectModelForTask(req);
}

ModelSelection ModelManager::SelectModelForChat() {
    TaskRequirements req;
    req.preferredType = ModelType::Chat;
    req.maxLatencyMs = 500.0f;
    req.expectedOutputTokens = 512;
    return SelectModelForTask(req);
}

ModelSelection ModelManager::SelectModelForCode() {
    TaskRequirements req;
    req.preferredType = ModelType::Code;
    req.requiresFIM = true;
    req.maxLatencyMs = 200.0f;
    req.expectedOutputTokens = 256;
    return SelectModelForTask(req);
}

ModelSelection ModelManager::SelectModelForReasoning() {
    TaskRequirements req;
    req.preferredType = ModelType::Reasoning;
    req.requiresTools = true;
    req.maxLatencyMs = 2000.0f;  // Slower but smarter
    req.expectedOutputTokens = 2048;
    req.minQuality = 0.9f;
    return SelectModelForTask(req);
}

std::optional<ModelInfo> ModelManager::GetModelInfo(const std::string& modelId) const {
    auto it = pImpl->models_.find(modelId);
    if (it != pImpl->models_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ModelInfo> ModelManager::GetAvailableModels() const {
    std::vector<ModelInfo> result;
    for (const auto& [id, model] : pImpl->models_) {
        if (model.isAvailable || model.isDownloaded) {
            result.push_back(model);
        }
    }
    return result;
}

std::vector<ModelInfo> ModelManager::GetLoadedModels() const {
    std::vector<ModelInfo> result;
    for (const auto& modelId : pImpl->loadedModels_) {
        auto it = pImpl->models_.find(modelId);
        if (it != pImpl->models_.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

std::vector<ModelInfo> ModelManager::GetModelsByType(ModelType type) const {
    std::vector<ModelInfo> result;
    for (const auto& [id, model] : pImpl->models_) {
        if (model.type == type) {
            result.push_back(model);
        }
    }
    return result;
}

VRAMBudget ModelManager::GetVRAMBudget() const {
    return pImpl->vramBudget_;
}

bool ModelManager::CanLoadModel(const std::string& modelId) const {
    auto it = pImpl->models_.find(modelId);
    if (it == pImpl->models_.end()) {
        return false;
    }
    return pImpl->vramBudget_.CanFit(it->second.vramRequired);
}

std::vector<std::string> ModelManager::GetModelsToUnloadFor(uint64_t requiredVRAM) {
    std::vector<std::string> toUnload;
    uint64_t freedVRAM = 0;
    
    // Sort by last used time
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> sortedModels;
    for (const auto& modelId : pImpl->loadedModels_) {
        auto it = pImpl->models_.find(modelId);
        if (it != pImpl->models_.end()) {
            sortedModels.push_back({modelId, it->second.lastUsed});
        }
    }
    
    std::sort(sortedModels.begin(), sortedModels.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    for (const auto& [modelId, _] : sortedModels) {
        auto it = pImpl->models_.find(modelId);
        if (it != pImpl->models_.end()) {
            toUnload.push_back(modelId);
            freedVRAM += it->second.vramWorking;
            
            if (freedVRAM >= requiredVRAM) {
                break;
            }
        }
    }
    
    return toUnload;
}

void ModelManager::SetLatencyTarget(float targetMs) {
    pImpl->latencyTarget_ = targetMs;
}

void ModelManager::SetQualityTarget(float target) {
    pImpl->qualityTarget_ = target;
}

void ModelManager::EnableAutoUnload(bool enable) {
    pImpl->autoUnload_ = enable;
}

void ModelManager::SetMaxLoadedModels(uint32_t max) {
    pImpl->maxLoadedModels_ = max;
}

void ModelManager::PreloadModel(const std::string& modelId) {
    LoadModel(modelId);
}

void ModelManager::PreloadModelsForTask(const TaskRequirements& requirements) {
    auto selection = SelectModelForTask(requirements);
    if (!selection.modelId.empty() && selection.needsLoad) {
        LoadModel(selection.modelId);
    }
}

ModelManager::Stats ModelManager::GetStats() const {
    std::lock_guard<std::mutex> lock(pImpl->statsMutex_);
    Stats stats = pImpl->stats_;
    stats.vram = pImpl->vramBudget_;
    return stats;
}

void ModelManager::OnModelLoaded(ModelLoadedCallback callback) {
    pImpl->onModelLoaded_ = callback;
}

void ModelManager::OnModelUnloaded(ModelUnloadedCallback callback) {
    pImpl->onModelUnloaded_ = callback;
}

void ModelManager::OnVRAMPressure(VRAMPressureCallback callback) {
    pImpl->onVRAMPressure_ = callback;
}

// ============================================================================
// ModelRouter Implementation
// ============================================================================
ModelRouter::ModelRouter(ModelManager* manager) : manager_(manager) {}
ModelRouter::~ModelRouter() = default;

std::string ModelRouter::RouteCompletion(
    const std::string& prefix,
    const std::string& suffix,
    const std::string& language
) {
    auto selection = manager_->SelectModelForCompletion();
    
    if (selection.modelId.empty()) {
        return "";
    }
    
    if (selection.needsLoad) {
        manager_->LoadModel(selection.modelId);
    }
    
    return selection.modelId;
}

std::string ModelRouter::RouteChat(
    const std::vector<std::pair<std::string, std::string>>& history,
    const std::string& message
) {
    auto selection = manager_->SelectModelForChat();
    
    if (selection.modelId.empty()) {
        return "";
    }
    
    if (selection.needsLoad) {
        manager_->LoadModel(selection.modelId);
    }
    
    return selection.modelId;
}

std::string ModelRouter::RouteAgentTask(
    const std::string& task,
    const std::vector<std::string>& tools
) {
    auto selection = manager_->SelectModelForReasoning();
    
    if (selection.modelId.empty()) {
        return "";
    }
    
    if (selection.needsLoad) {
        manager_->LoadModel(selection.modelId);
    }
    
    return selection.modelId;
}

std::string ModelRouter::RouteEmbedding(const std::string& text) {
    // Return embedding model ID
    return "";
}

// ============================================================================
// HardwareDetector Implementation
// ============================================================================
HardwareInfo HardwareDetector::DetectGPU() {
    HardwareInfo info;
    
    // This would use platform-specific APIs to detect GPU
    // For now, return a reasonable default for RX 7800 XT
    
    info.deviceName = "AMD Radeon RX 7800 XT";
    info.totalVRAM = 16ULL * 1024 * 1024 * 1024;  // 16GB
    info.freeVRAM = 16ULL * 1024 * 1024 * 1024;
    info.supportsVulkan = true;
    info.supportsROCm = true;
    
    return info;
}

uint64_t HardwareDetector::GetAvailableVRAM() {
    return DetectGPU().freeVRAM;
}

std::vector<HardwareInfo> HardwareDetector::DetectAllGPUs() {
    std::vector<HardwareInfo> gpus;
    gpus.push_back(DetectGPU());
    return gpus;
}

} // namespace Models
} // namespace RawrXD

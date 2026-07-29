// ============================================================================
// GGUFModelRegistry.cpp - Phase 3: Production Model Management
// Central registry implementation with metadata extraction
// ============================================================================

#include "GGUFModelRegistry.h"
#include "../GGUFLoader.hpp"
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <json/json.hpp>

namespace Deep2 {
namespace ModelRegistry {

// ============================================================================
// Singleton
// ============================================================================
ModelRegistry& ModelRegistry::Instance() {
    static ModelRegistry instance;
    return instance;
}

// ============================================================================
// Initialization
// ============================================================================
bool ModelRegistry::Initialize(const std::string& registryPath) {
    if (initialized_) {
        return true;
    }

    printf("[ModelRegistry] Initializing...\n");

    registryPath_ = registryPath.empty() 
        ? "./models/registry.json" 
        : registryPath;

    // Create default profiles
    InferenceProfile defaultProfile;
    defaultProfile.profileId = "default";
    defaultProfile.name = "Default";
    defaultProfile.description = "Balanced performance and quality";
    profiles_["default"] = defaultProfile;

    InferenceProfile fastProfile;
    fastProfile.profileId = "fast";
    fastProfile.name = "Fast";
    fastProfile.description = "Optimized for speed";
    fastProfile.maxContextLength = 2048;
    fastProfile.temperature = 0.6f;
    profiles_["fast"] = fastProfile;

    InferenceProfile qualityProfile;
    qualityProfile.profileId = "quality";
    qualityProfile.name = "Quality";
    qualityProfile.description = "Optimized for output quality";
    qualityProfile.maxContextLength = 8192;
    qualityProfile.temperature = 0.7f;
    profiles_["quality"] = qualityProfile;

    // Load existing registry
    LoadRegistry();

    initialized_ = true;
    printf("[ModelRegistry] Initialized with %zu profiles\n", profiles_.size());
    return true;
}

void ModelRegistry::Shutdown() {
    printf("[ModelRegistry] Shutting down...\n");

    // Unload all models
    auto loaded = GetAllLoadedModels();
    for (const auto& model : loaded) {
        UnloadModel(model.modelId);
    }

    // Save registry
    SaveRegistry();

    initialized_ = false;
}

// ============================================================================
// Discovery
// ============================================================================
size_t ModelRegistry::ScanDirectory(const std::string& directory, bool recursive) {
    printf("[ModelRegistry] Scanning %s for GGUF models...\n", directory.c_str());

    size_t found = 0;

    try {
        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
                if (entry.is_regular_file() && entry.path().extension() == ".gguf") {
                    if (RegisterModel(entry.path().string())) {
                        found++;
                    }
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(directory)) {
                if (entry.is_regular_file() && entry.path().extension() == ".gguf") {
                    if (RegisterModel(entry.path().string())) {
                        found++;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        printf("[ModelRegistry] Scan error: %s\n", e.what());
    }

    printf("[ModelRegistry] Found %zu models\n", found);
    return found;
}

bool ModelRegistry::RegisterModel(const std::string& filePath) {
    if (!std::filesystem::exists(filePath)) {
        return false;
    }

    // Extract manifest
    ModelManifest manifest = ExtractManifest(filePath);
    if (manifest.modelId.empty()) {
        manifest.modelId = std::filesystem::path(filePath).stem().string();
    }

    // Check if already registered
    {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        if (models_.find(manifest.modelId) != models_.end()) {
            // Update existing
            models_[manifest.modelId] = manifest;
            printf("[ModelRegistry] Updated model: %s\n", manifest.modelId.c_str());
        } else {
            models_[manifest.modelId] = manifest;
            printf("[ModelRegistry] Registered model: %s (%.2f GB, %s)\n",
                   manifest.modelId.c_str(),
                   manifest.fileSizeBytes / (1024.0 * 1024.0 * 1024.0),
                   manifest.quantizationType.c_str());
        }
    }

    if (onModelRegistered_) {
        onModelRegistered_(manifest.modelId);
    }

    return true;
}

bool ModelRegistry::UnregisterModel(const std::string& modelId) {
    std::lock_guard<std::mutex> lock(modelsMutex_);

    // Unload if loaded
    if (loadedModels_.find(modelId) != loadedModels_.end()) {
        UnloadModel(modelId);
    }

    auto it = models_.find(modelId);
    if (it != models_.end()) {
        models_.erase(it);
        printf("[ModelRegistry] Unregistered model: %s\n", modelId.c_str());
        return true;
    }

    return false;
}

// ============================================================================
// Query
// ============================================================================
std::vector<ModelManifest> ModelRegistry::ListModels() const {
    std::lock_guard<std::mutex> lock(modelsMutex_);

    std::vector<ModelManifest> result;
    for (const auto& [id, manifest] : models_) {
        result.push_back(manifest);
    }

    return result;
}

std::vector<ModelManifest> ModelRegistry::FindModelsByCapability(const std::string& capability) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);

    std::vector<ModelManifest> result;
    for (const auto& [id, manifest] : models_) {
        if (std::find(manifest.capabilities.begin(), manifest.capabilities.end(), capability) 
            != manifest.capabilities.end()) {
            result.push_back(manifest);
        }
    }

    return result;
}

std::vector<ModelManifest> ModelRegistry::FindModelsByVRAM(uint64_t maxVRAMBytes) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);

    std::vector<ModelManifest> result;
    for (const auto& [id, manifest] : models_) {
        if (manifest.minVRAMBytes <= maxVRAMBytes) {
            result.push_back(manifest);
        }
    }

    return result;
}

std::optional<ModelManifest> ModelRegistry::GetModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);

    auto it = models_.find(modelId);
    if (it != models_.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool ModelRegistry::HasModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(modelsMutex_);
    return models_.find(modelId) != models_.end();
}

// ============================================================================
// Lifecycle
// ============================================================================
bool ModelRegistry::LoadModel(const std::string& modelId, const InferenceProfile& profile) {
    auto manifest = GetModel(modelId);
    if (!manifest) {
        printf("[ModelRegistry] Model not found: %s\n", modelId.c_str());
        return false;
    }

    printf("[ModelRegistry] Loading model: %s\n", modelId.c_str());

    // Check if already loaded
    {
        std::lock_guard<std::mutex> lock(loadedMutex_);
        if (loadedModels_.find(modelId) != loadedModels_.end()) {
            printf("[ModelRegistry] Model already loaded: %s\n", modelId.c_str());
            return true;
        }
    }

    // TODO: Actually load the model into Deep2Engine
    // For now, simulate loading

    LoadedModel loaded;
    loaded.modelId = modelId;
    loaded.state = ModelState::LOADED;
    loaded.loadTime = std::chrono::steady_clock::now();
    loaded.lastUsedTime = loaded.loadTime;
    loaded.vramUsedBytes = EstimateVRAM(*manifest);

    // Determine GPU placement based on profile
    if (profile.preferredDevice >= 0) {
        loaded.primaryDevice = profile.preferredDevice;
    } else {
        // Auto-select based on execution mode
        if (profile.executionMode == "hybrid") {
            loaded.primaryDevice = 0;   // R9700
            loaded.secondaryDevice = 1; // 7800XT
        } else {
            loaded.primaryDevice = 0;
            loaded.secondaryDevice = -1;
        }
    }

    {
        std::lock_guard<std::mutex> lock(loadedMutex_);
        loadedModels_[modelId] = loaded;
    }

    // Update manifest
    {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        auto it = models_.find(modelId);
        if (it != models_.end()) {
            it->second.isLoaded = true;
            it->second.loadStatus = "loaded";
        }
    }

    printf("[ModelRegistry] Model loaded: %s (%.2f GB VRAM, device %d)\n",
           modelId.c_str(),
           loaded.vramUsedBytes / (1024.0 * 1024.0 * 1024.0),
           loaded.primaryDevice);

    if (onModelLoaded_) {
        onModelLoaded_(modelId);
    }

    return true;
}

bool ModelRegistry::UnloadModel(const std::string& modelId) {
    printf("[ModelRegistry] Unloading model: %s\n", modelId.c_str());

    {
        std::lock_guard<std::mutex> lock(loadedMutex_);
        auto it = loadedModels_.find(modelId);
        if (it == loadedModels_.end()) {
            return false;
        }
        loadedModels_.erase(it);
    }

    // Update manifest
    {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        auto it = models_.find(modelId);
        if (it != models_.end()) {
            it->second.isLoaded = false;
            it->second.loadStatus = "unloaded";
        }
    }

    printf("[ModelRegistry] Model unloaded: %s\n", modelId.c_str());

    if (onModelUnloaded_) {
        onModelUnloaded_(modelId);
    }

    return true;
}

bool ModelRegistry::IsModelLoaded(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(loadedMutex_);
    return loadedModels_.find(modelId) != loadedModels_.end();
}

LoadedModel ModelRegistry::GetLoadedModel(const std::string& modelId) const {
    std::lock_guard<std::mutex> lock(loadedMutex_);
    auto it = loadedModels_.find(modelId);
    if (it != loadedModels_.end()) {
        return it->second;
    }
    return LoadedModel{};
}

std::vector<LoadedModel> ModelRegistry::GetAllLoadedModels() const {
    std::lock_guard<std::mutex> lock(loadedMutex_);

    std::vector<LoadedModel> result;
    for (const auto& [id, model] : loadedModels_) {
        result.push_back(model);
    }

    return result;
}

// ============================================================================
// Hot Swap
// ============================================================================
bool ModelRegistry::HotSwapModel(const std::string& unloadId, const std::string& loadId) {
    printf("[ModelRegistry] Hot swapping: %s -> %s\n", unloadId.c_str(), loadId.c_str());

    // Load new model first
    if (!LoadModel(loadId)) {
        return false;
    }

    // Then unload old
    UnloadModel(unloadId);

    return true;
}

bool ModelRegistry::EvictLRUModel() {
    std::lock_guard<std::mutex> lock(loadedMutex_);

    if (loadedModels_.empty()) {
        return false;
    }

    // Find least recently used
    std::string lruId;
    auto lruTime = std::chrono::steady_clock::now();

    for (const auto& [id, model] : loadedModels_) {
        if (model.lastUsedTime < lruTime) {
            lruTime = model.lastUsedTime;
            lruId = id;
        }
    }

    if (!lruId.empty()) {
        // Need to unlock before calling UnloadModel
        lock.~lock_guard();
        return UnloadModel(lruId);
    }

    return false;
}

// ============================================================================
// Profiles
// ============================================================================
void ModelRegistry::AddProfile(const InferenceProfile& profile) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    profiles_[profile.profileId] = profile;
}

void ModelRegistry::RemoveProfile(const std::string& profileId) {
    std::lock_guard<std::mutex> lock(profilesMutex_);
    profiles_.erase(profileId);
}

std::vector<InferenceProfile> ModelRegistry::ListProfiles() const {
    std::lock_guard<std::mutex> lock(profilesMutex_);

    std::vector<InferenceProfile> result;
    for (const auto& [id, profile] : profiles_) {
        result.push_back(profile);
    }

    return result;
}

std::optional<InferenceProfile> ModelRegistry::GetProfile(const std::string& profileId) const {
    std::lock_guard<std::mutex> lock(profilesMutex_);

    auto it = profiles_.find(profileId);
    if (it != profiles_.end()) {
        return it->second;
    }

    return std::nullopt;
}

InferenceProfile ModelRegistry::GetDefaultProfile() const {
    std::lock_guard<std::mutex> lock(profilesMutex_);

    auto it = profiles_.find("default");
    if (it != profiles_.end()) {
        return it->second;
    }

    return InferenceProfile{};
}

// ============================================================================
// Auto-Scheduling
// ============================================================================
std::string ModelRegistry::SelectBestModel(const std::string& taskType, uint64_t availableVRAM) const {
    auto candidates = FindModelsByVRAM(availableVRAM);

    if (candidates.empty()) {
        return "";
    }

    // Sort by capability match and size
    std::sort(candidates.begin(), candidates.end(),
        [&taskType](const ModelManifest& a, const ModelManifest& b) {
            bool aHasCap = std::find(a.capabilities.begin(), a.capabilities.end(), taskType) 
                           != a.capabilities.end();
            bool bHasCap = std::find(b.capabilities.begin(), b.capabilities.end(), taskType) 
                           != b.capabilities.end();
            
            if (aHasCap != bHasCap) {
                return aHasCap > bHasCap;  // Capability match first
            }
            
            // Then by parameter count (larger is better)
            return a.parameterCount > b.parameterCount;
        });

    return candidates[0].modelId;
}

InferenceProfile ModelRegistry::SelectBestProfile(const std::string& modelId, 
                                                     const std::string& taskType) const {
    auto manifest = GetModel(modelId);
    if (!manifest) {
        return GetDefaultProfile();
    }

    // Select based on task type
    if (taskType == "fast" || taskType == "completion") {
        auto profile = GetProfile("fast");
        if (profile) return *profile;
    } else if (taskType == "quality" || taskType == "analysis") {
        auto profile = GetProfile("quality");
        if (profile) return *profile;
    }

    return GetDefaultProfile();
}

// ============================================================================
// Verification
// ============================================================================
bool ModelRegistry::VerifyModel(const std::string& modelId) {
    auto manifest = GetModel(modelId);
    if (!manifest) {
        return false;
    }

    printf("[ModelRegistry] Verifying model: %s\n", modelId.c_str());

    // Check file exists
    if (!std::filesystem::exists(manifest->filePath)) {
        printf("[ModelRegistry] Model file not found: %s\n", manifest->filePath.c_str());
        return false;
    }

    // Verify checksum
    if (!manifest->checksum.empty()) {
        std::string currentChecksum = ComputeChecksum(manifest->filePath);
        if (currentChecksum != manifest->checksum) {
            printf("[ModelRegistry] Checksum mismatch for %s\n", modelId.c_str());
            return false;
        }
    }

    // Update manifest
    {
        std::lock_guard<std::mutex> lock(modelsMutex_);
        auto it = models_.find(modelId);
        if (it != models_.end()) {
            it->second.isVerified = true;
        }
    }

    printf("[ModelRegistry] Model verified: %s\n", modelId.c_str());
    return true;
}

bool ModelRegistry::ValidateChecksum(const std::string& modelId) {
    return VerifyModel(modelId);
}

// ============================================================================
// Persistence
// ============================================================================
bool ModelRegistry::SaveRegistry() {
    try {
        nlohmann::json j;

        // Save models
        j["models"] = nlohmann::json::array();
        {
            std::lock_guard<std::mutex> lock(modelsMutex_);
            for (const auto& [id, manifest] : models_) {
                nlohmann::json m;
                m["modelId"] = manifest.modelId;
                m["name"] = manifest.name;
                m["filePath"] = manifest.filePath;
                m["checksum"] = manifest.checksum;
                m["fileSizeBytes"] = manifest.fileSizeBytes;
                m["architecture"] = manifest.architecture;
                m["parameterCount"] = manifest.parameterCount;
                m["quantizationType"] = manifest.quantizationType;
                m["minVRAMBytes"] = manifest.minVRAMBytes;
                j["models"].push_back(m);
            }
        }

        // Save profiles
        j["profiles"] = nlohmann::json::array();
        {
            std::lock_guard<std::mutex> lock(profilesMutex_);
            for (const auto& [id, profile] : profiles_) {
                nlohmann::json p;
                p["profileId"] = profile.profileId;
                p["name"] = profile.name;
                p["maxContextLength"] = profile.maxContextLength;
                p["temperature"] = profile.temperature;
                j["profiles"].push_back(p);
            }
        }

        std::ofstream file(registryPath_);
        file << j.dump(2);

        printf("[ModelRegistry] Registry saved to %s\n", registryPath_.c_str());
        return true;
    } catch (const std::exception& e) {
        printf("[ModelRegistry] Save error: %s\n", e.what());
        return false;
    }
}

bool ModelRegistry::LoadRegistry() {
    try {
        if (!std::filesystem::exists(registryPath_)) {
            printf("[ModelRegistry] No existing registry found\n");
            return true;
        }

        std::ifstream file(registryPath_);
        nlohmann::json j;
        file >> j;

        // Load models
        if (j.contains("models")) {
            std::lock_guard<std::mutex> lock(modelsMutex_);
            for (const auto& m : j["models"]) {
                ModelManifest manifest;
                manifest.modelId = m.value("modelId", "");
                manifest.name = m.value("name", "");
                manifest.filePath = m.value("filePath", "");
                manifest.checksum = m.value("checksum", "");
                manifest.fileSizeBytes = m.value("fileSizeBytes", 0);
                manifest.architecture = m.value("architecture", "");
                manifest.parameterCount = m.value("parameterCount", 0);
                manifest.quantizationType = m.value("quantizationType", "");
                manifest.minVRAMBytes = m.value("minVRAMBytes", 0);
                manifest.registeredTime = std::chrono::system_clock::now();
                
                if (!manifest.modelId.empty()) {
                    models_[manifest.modelId] = manifest;
                }
            }
        }

        printf("[ModelRegistry] Registry loaded: %zu models\n", models_.size());
        return true;
    } catch (const std::exception& e) {
        printf("[ModelRegistry] Load error: %s\n", e.what());
        return false;
    }
}

// ============================================================================
// Internal Helpers
// ============================================================================
ModelManifest ModelRegistry::ExtractManifest(const std::string& filePath) {
    ModelManifest manifest;
    manifest.filePath = filePath;
    manifest.registeredTime = std::chrono::system_clock::now();

    // Get file info
    try {
        auto fileSize = std::filesystem::file_size(filePath);
        manifest.fileSizeBytes = fileSize;
        
        auto modified = std::filesystem::last_write_time(filePath);
        // Convert to system_clock time (platform-specific)
    } catch (...) {}

    // Parse GGUF metadata
    ParseGGUFMetadata(filePath, manifest);

    // Compute checksum
    manifest.checksum = ComputeChecksum(filePath);

    // Estimate VRAM requirements
    manifest.minVRAMBytes = EstimateVRAM(manifest);
    manifest.recommendedVRAMBytes = manifest.minVRAMBytes * 12 / 10;  // +20%

    return manifest;
}

std::string ModelRegistry::ComputeChecksum(const std::string& filePath) {
    // Simplified checksum - in production would use SHA256
    // For now, use file size + modification time as proxy
    try {
        auto size = std::filesystem::file_size(filePath);
        auto time = std::filesystem::last_write_time(filePath);
        
        // Simple hash
        uint64_t hash = size ^ (size >> 32);
        hash ^= std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        char buf[32];
        snprintf(buf, sizeof(buf), "%016llx", hash);
        return buf;
    } catch (...) {
        return "";
    }
}

bool ModelRegistry::ParseGGUFMetadata(const std::string& filePath, ModelManifest& manifest) {
    // Use GGUFLoader to extract metadata
    GGUFLoadOptions options;
    options.loadTensors = false;  // Only metadata
    options.verbose = false;
    options.mmap = true;

    GGUFLoadResult result = GGUFLoader::LoadHardened(filePath.c_str(), options);
    if (!result.success) {
        printf("[ModelRegistry] Failed to parse GGUF: %s\n", result.error);
        return false;
    }

    const auto& meta = result.metadata;
    
    manifest.architecture = meta.architecture;
    manifest.hiddenSize = meta.hiddenSize;
    manifest.numLayers = meta.numLayers;
    manifest.numAttentionHeads = meta.numHeads;
    manifest.numKeyValueHeads = meta.numKeyValueHeads;
    manifest.contextLength = meta.contextLength > 0 ? meta.contextLength : meta.maxPositionEmbeddings;
    manifest.vocabSize = meta.vocabSize;

    // Detect quantization from file name
    std::string filename = std::filesystem::path(filePath).filename().string();
    if (filename.find("Q4_K_M") != std::string::npos) {
        manifest.quantizationType = "Q4_K_M";
        manifest.bitsPerWeight = 4;
    } else if (filename.find("Q5_K_M") != std::string::npos) {
        manifest.quantizationType = "Q5_K_M";
        manifest.bitsPerWeight = 5;
    } else if (filename.find("Q8_0") != std::string::npos) {
        manifest.quantizationType = "Q8_0";
        manifest.bitsPerWeight = 8;
    } else if (filename.find("FP16") != std::string::npos) {
        manifest.quantizationType = "FP16";
        manifest.bitsPerWeight = 16;
    } else {
        manifest.quantizationType = "unknown";
    }

    // Estimate parameter count
    if (meta.parameterCount > 0) {
        manifest.parameterCount = meta.parameterCount;
    } else {
        // Rough estimate from architecture
        manifest.parameterCount = manifest.fileSizeBytes * 8 / manifest.bitsPerWeight;
    }

    // Calculate compression ratio
    if (manifest.bitsPerWeight > 0) {
        manifest.compressionRatio = 16.0f / manifest.bitsPerWeight;  // vs FP16
    }

    // Detect capabilities from metadata
    if (!meta.chatTemplate.empty()) {
        manifest.capabilities.push_back("chat");
    }
    if (meta.architecture.find("code") != std::string::npos ||
        filename.find("code") != std::string::npos) {
        manifest.capabilities.push_back("code");
    }
    if (manifest.capabilities.empty()) {
        manifest.capabilities.push_back("instruct");
    }

    return true;
}

uint64_t ModelRegistry::EstimateVRAM(const ModelManifest& manifest) const {
    // Rough estimation: model size + KV cache + overhead
    uint64_t modelSize = manifest.fileSizeBytes;
    uint64_t kvCacheSize = manifest.contextLength * manifest.numLayers * 
                           manifest.hiddenSize * 2 * sizeof(float);  // K + V
    uint64_t overhead = 512 * 1024 * 1024;  // 512MB overhead
    
    return modelSize + kvCacheSize + overhead;
}

// ============================================================================
// Event Callbacks
// ============================================================================
void ModelRegistry::SetModelLoadedCallback(ModelEventCallback cb) {
    onModelLoaded_ = cb;
}

void ModelRegistry::SetModelUnloadedCallback(ModelEventCallback cb) {
    onModelUnloaded_ = cb;
}

void ModelRegistry::SetModelRegisteredCallback(ModelEventCallback cb) {
    onModelRegistered_ = cb;
}

} // namespace ModelRegistry
} // namespace Deep2

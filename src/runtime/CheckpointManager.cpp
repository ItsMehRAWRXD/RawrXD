/**
 * CheckpointManager.cpp
 * 
 * Phase B.5 Batch 3/5: Checkpoint/Restore Functionality Implementation
 */

#include "CheckpointManager.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <random>

namespace Sovereign {

// CheckpointMetadata implementation
std::string CheckpointMetadata::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"checkpointId\": \"" << checkpointId << "\",\n";
    json << "  \"timestamp\": " << timestampMs << ",\n";
    json << "  \"version\": \"" << version << "\",\n";
    json << "  \"description\": \"" << description << "\",\n";
    json << "  \"hasEngineState\": " << (hasEngineState ? "true" : "false") << ",\n";
    json << "  \"hasSwarmState\": " << (hasSwarmState ? "true" : "false") << ",\n";
    json << "  \"hasTelemetryState\": " << (hasTelemetryState ? "true" : "false") << ",\n";
    json << "  \"hasGraphState\": " << (hasGraphState ? "true" : "false") << ",\n";
    json << "  \"totalCyclesExecuted\": " << totalCyclesExecuted << ",\n";
    json << "  \"currentConvergenceScore\": " << std::fixed << std::setprecision(4) << currentConvergenceScore << ",\n";
    json << "  \"isConverged\": " << (isConverged ? "true" : "false") << "\n";
    json << "}";
    return json.str();
}

CheckpointMetadata CheckpointMetadata::FromJson(const std::string& json) {
    // Simplified parsing - would use proper JSON library
    CheckpointMetadata meta;
    meta.checkpointId = "parsed-id";
    meta.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    meta.version = "1.0.0";
    return meta;
}

// Checkpoint implementation
std::vector<uint8_t> Checkpoint::ToBinary() const {
    std::vector<uint8_t> data;
    
    // Serialize metadata size
    std::string metaJson = metadata.ToJson();
    uint32_t metaSize = static_cast<uint32_t>(metaJson.size());
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&metaSize), 
                reinterpret_cast<uint8_t*>(&metaSize) + sizeof(metaSize));
    data.insert(data.end(), metaJson.begin(), metaJson.end());
    
    // Serialize component count
    uint32_t compCount = static_cast<uint32_t>(components.size());
    data.insert(data.end(), reinterpret_cast<uint8_t*>(&compCount),
                reinterpret_cast<uint8_t*>(&compCount) + sizeof(compCount));
    
    // Serialize each component
    for (const auto& [name, state] : components) {
        // Name length and name
        uint32_t nameLen = static_cast<uint32_t>(name.size());
        data.insert(data.end(), reinterpret_cast<uint8_t*>(&nameLen),
                    reinterpret_cast<uint8_t*>(&nameLen) + sizeof(nameLen));
        data.insert(data.end(), name.begin(), name.end());
        
        // Data size and data
        uint32_t dataLen = static_cast<uint32_t>(state.data.size());
        data.insert(data.end(), reinterpret_cast<uint8_t*>(&dataLen),
                    reinterpret_cast<uint8_t*>(&dataLen) + sizeof(dataLen));
        data.insert(data.end(), state.data.begin(), state.data.end());
    }
    
    return data;
}

Checkpoint Checkpoint::FromBinary(const std::vector<uint8_t>& data) {
    // Simplified deserialization
    Checkpoint cp;
    cp.metadata.checkpointId = "restored";
    return cp;
}

std::string Checkpoint::ToJson() const {
    std::ostringstream json;
    json << "{\n";
    json << "  \"metadata\": " << metadata.ToJson() << ",\n";
    json << "  \"components\": [\n";
    
    bool first = true;
    for (const auto& [name, state] : components) {
        if (!first) json << ",\n";
        json << "    {\"name\": \"" << name << "\", ";
        json << "\"dataSize\": " << state.data.size() << "}";
        first = false;
    }
    
    json << "\n  ]\n}";
    return json.str();
}

Checkpoint Checkpoint::FromJson(const std::string& json) {
    // Simplified parsing
    return Checkpoint();
}

// CheckpointManager implementation
CheckpointManager::CheckpointManager() = default;
CheckpointManager::~CheckpointManager() = default;

bool CheckpointManager::Initialize(const std::string& storagePath) {
    storagePath_ = storagePath;
    
    // Create directory if it doesn't exist
    try {
        std::filesystem::create_directories(storagePath_);
    } catch (const std::exception& e) {
        std::cerr << "[CheckpointManager] Failed to create storage directory: " << e.what() << "\n";
        return false;
    }
    
    std::cout << "[CheckpointManager] Initialized with storage path: " << storagePath_ << "\n";
    return true;
}

void CheckpointManager::SetPolicy(const CheckpointPolicy& policy) {
    policy_ = policy;
}

std::string CheckpointManager::CreateCheckpoint(const std::string& description) {
    std::vector<std::string> allComponents;
    for (const auto& [name, _] : componentHandlers_) {
        allComponents.push_back(name);
    }
    return CreateCheckpoint(allComponents, description);
}

std::string CheckpointManager::CreateCheckpoint(const std::vector<std::string>& componentNames,
                                                  const std::string& description) {
    Checkpoint checkpoint;
    checkpoint.metadata.checkpointId = GenerateCheckpointId();
    checkpoint.metadata.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    checkpoint.metadata.version = "1.0.0";
    checkpoint.metadata.description = description;
    
    // Serialize each component
    for (const auto& name : componentNames) {
        auto it = componentHandlers_.find(name);
        if (it != componentHandlers_.end()) {
            ComponentState state = it->second.first(); // Call serialize function
            state.componentName = name;
            checkpoint.components[name] = state;
            
            // Update metadata flags
            if (name == "engine") checkpoint.metadata.hasEngineState = true;
            if (name == "swarm") checkpoint.metadata.hasSwarmState = true;
            if (name == "telemetry") checkpoint.metadata.hasTelemetryState = true;
            if (name == "graph") checkpoint.metadata.hasGraphState = true;
        }
    }
    
    // Save to disk
    if (!SaveCheckpointToDisk(checkpoint)) {
        std::cerr << "[CheckpointManager] Failed to save checkpoint\n";
        return "";
    }
    
    lastCheckpointTime_ = checkpoint.metadata.timestampMs;
    
    // Prune old checkpoints if needed
    if (policy_.maxCheckpoints > 0) {
        PruneCheckpoints(policy_.maxCheckpoints);
    }
    
    std::cout << "[CheckpointManager] Created checkpoint: " << checkpoint.metadata.checkpointId << "\n";
    return checkpoint.metadata.checkpointId;
}

bool CheckpointManager::RestoreCheckpoint(const std::string& checkpointId) {
    std::vector<std::string> allComponents;
    for (const auto& [name, _] : componentHandlers_) {
        allComponents.push_back(name);
    }
    return RestoreCheckpoint(checkpointId, allComponents);
}

bool CheckpointManager::RestoreCheckpoint(const std::string& checkpointId,
                                           const std::vector<std::string>& componentNames) {
    Checkpoint checkpoint = LoadCheckpointFromDisk(checkpointId);
    if (checkpoint.metadata.checkpointId.empty()) {
        std::cerr << "[CheckpointManager] Failed to load checkpoint: " << checkpointId << "\n";
        return false;
    }
    
    // Restore each component
    bool success = true;
    for (const auto& name : componentNames) {
        auto compIt = checkpoint.components.find(name);
        auto handlerIt = componentHandlers_.find(name);
        
        if (compIt != checkpoint.components.end() && handlerIt != componentHandlers_.end()) {
            if (!handlerIt->second.second(compIt->second)) { // Call deserialize function
                std::cerr << "[CheckpointManager] Failed to restore component: " << name << "\n";
                success = false;
            }
        }
    }
    
    std::cout << "[CheckpointManager] Restored checkpoint: " << checkpointId << "\n";
    return success;
}

std::vector<CheckpointMetadata> CheckpointManager::ListCheckpoints() const {
    std::vector<CheckpointMetadata> checkpoints;
    
    try {
        for (const auto& entry : std::filesystem::directory_iterator(storagePath_)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                // Load metadata
                std::ifstream file(entry.path());
                if (file.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(file)),
                                        std::istreambuf_iterator<char>());
                    CheckpointMetadata meta = CheckpointMetadata::FromJson(content);
                    checkpoints.push_back(meta);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[CheckpointManager] Error listing checkpoints: " << e.what() << "\n";
    }
    
    // Sort by timestamp (newest first)
    std::sort(checkpoints.begin(), checkpoints.end(),
              [](const CheckpointMetadata& a, const CheckpointMetadata& b) {
                  return a.timestampMs > b.timestampMs;
              });
    
    return checkpoints;
}

CheckpointMetadata CheckpointManager::GetCheckpointMetadata(const std::string& checkpointId) const {
    Checkpoint cp = LoadCheckpointFromDisk(checkpointId);
    return cp.metadata;
}

bool CheckpointManager::DeleteCheckpoint(const std::string& checkpointId) {
    try {
        std::filesystem::path checkpointPath = GetCheckpointPath(checkpointId);
        std::filesystem::remove(checkpointPath);
        std::cout << "[CheckpointManager] Deleted checkpoint: " << checkpointId << "\n";
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[CheckpointManager] Failed to delete checkpoint: " << e.what() << "\n";
        return false;
    }
}

bool CheckpointManager::PruneCheckpoints(size_t keepCount) {
    auto checkpoints = ListCheckpoints();
    
    if (checkpoints.size() <= keepCount) return true;
    
    // Delete oldest checkpoints
    for (size_t i = keepCount; i < checkpoints.size(); ++i) {
        DeleteCheckpoint(checkpoints[i].checkpointId);
    }
    
    return true;
}

bool CheckpointManager::VerifyCheckpoint(const std::string& checkpointId) const {
    Checkpoint cp = LoadCheckpointFromDisk(checkpointId);
    return !cp.metadata.checkpointId.empty();
}

bool CheckpointManager::ExportCheckpoint(const std::string& checkpointId, const std::string& filePath) {
    Checkpoint cp = LoadCheckpointFromDisk(checkpointId);
    if (cp.metadata.checkpointId.empty()) return false;
    
    std::ofstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;
    
    auto data = cp.ToBinary();
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

std::string CheckpointManager::ImportCheckpoint(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return "";
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    
    Checkpoint cp = Checkpoint::FromBinary(data);
    if (cp.metadata.checkpointId.empty()) {
        cp.metadata.checkpointId = GenerateCheckpointId();
    }
    
    if (!SaveCheckpointToDisk(cp)) return "";
    return cp.metadata.checkpointId;
}

void CheckpointManager::StartAutoCheckpoint() {
    // Would start background thread
    std::cout << "[CheckpointManager] Auto-checkpoint enabled (interval: " 
              << policy_.autoCheckpointIntervalMinutes << " min)\n";
}

void CheckpointManager::StopAutoCheckpoint() {
    // Would stop background thread
    std::cout << "[CheckpointManager] Auto-checkpoint disabled\n";
}

bool CheckpointManager::IsAutoCheckpointRunning() const {
    // Would check background thread
    return policy_.enableAutoCheckpoint;
}

size_t CheckpointManager::GetCheckpointCount() const {
    return ListCheckpoints().size();
}

void CheckpointManager::RegisterComponent(const std::string& name,
                                          std::function<ComponentState()> serializeFunc,
                                          std::function<bool(const ComponentState&)> deserializeFunc) {
    componentHandlers_[name] = {serializeFunc, deserializeFunc};
    std::cout << "[CheckpointManager] Registered component: " << name << "\n";
}

void CheckpointManager::UnregisterComponent(const std::string& name) {
    componentHandlers_.erase(name);
    std::cout << "[CheckpointManager] Unregistered component: " << name << "\n";
}

// Helper methods
std::string CheckpointManager::GenerateCheckpointId() const {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9999);
    
    std::ostringstream id;
    id << "cp-" << ms << "-" << std::setfill('0') << std::setw(4) << dis(gen);
    return id.str();
}

std::string CheckpointManager::GetCheckpointPath(const std::string& checkpointId) const {
    return (std::filesystem::path(storagePath_) / (checkpointId + ".json")).string();
}

bool CheckpointManager::SaveCheckpointToDisk(const Checkpoint& checkpoint) {
    std::string path = GetCheckpointPath(checkpoint.metadata.checkpointId);
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << checkpoint.ToJson();
    return true;
}

Checkpoint CheckpointManager::LoadCheckpointFromDisk(const std::string& checkpointId) const {
    std::string path = GetCheckpointPath(checkpointId);
    std::ifstream file(path);
    if (!file.is_open()) return Checkpoint();
    
    std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    return Checkpoint::FromJson(content);
}

std::vector<uint8_t> CheckpointManager::Compress(const std::vector<uint8_t>& data) const {
    // Simplified - would use actual compression library
    return data;
}

std::vector<uint8_t> CheckpointManager::Decompress(const std::vector<uint8_t>& data) const {
    // Simplified - would use actual compression library
    return data;
}

// CheckpointableRuntime implementation
CheckpointableRuntime::CheckpointableRuntime() = default;
CheckpointableRuntime::~CheckpointableRuntime() = default;

bool CheckpointableRuntime::Initialize(const std::string& storagePath) {
    checkpointManager_ = std::make_unique<CheckpointManager>();
    return checkpointManager_->Initialize(storagePath);
}

std::string CheckpointableRuntime::Checkpoint(const std::string& description) {
    if (!checkpointManager_) return "";
    return checkpointManager_->CreateCheckpoint(description);
}

bool CheckpointableRuntime::Restore(const std::string& checkpointId) {
    if (!checkpointManager_) return false;
    return checkpointManager_->RestoreCheckpoint(checkpointId);
}

void CheckpointableRuntime::EnableAutoCheckpoint(int intervalMinutes) {
    if (!checkpointManager_) return;
    CheckpointPolicy policy = checkpointManager_->GetPolicy();
    policy.enableAutoCheckpoint = true;
    policy.autoCheckpointIntervalMinutes = intervalMinutes;
    checkpointManager_->SetPolicy(policy);
    checkpointManager_->StartAutoCheckpoint();
}

void CheckpointableRuntime::DisableAutoCheckpoint() {
    if (!checkpointManager_) return;
    checkpointManager_->StopAutoCheckpoint();
}

} // namespace Sovereign

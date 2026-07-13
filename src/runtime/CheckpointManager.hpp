#pragma once

/**
 * CheckpointManager.hpp
 * 
 * Phase B.5 Batch 3/5: Checkpoint/Restore Functionality
 * 
 * Provides state persistence and recovery for the Sovereign Runtime
 */

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <fstream>

namespace Sovereign {

/**
 * Checkpoint metadata
 */
struct CheckpointMetadata {
    std::string checkpointId;
    int64_t timestampMs;
    std::string version;
    std::string description;
    std::map<std::string, std::string> tags;
    
    // Component states
    bool hasEngineState = false;
    bool hasSwarmState = false;
    bool hasTelemetryState = false;
    bool hasGraphState = false;
    
    // Statistics
    int64_t totalCyclesExecuted = 0;
    double currentConvergenceScore = 0.0;
    bool isConverged = false;
    
    std::string ToJson() const;
    static CheckpointMetadata FromJson(const std::string& json);
};

/**
 * Serialized component state
 */
struct ComponentState {
    std::string componentName;
    std::vector<uint8_t> data;
    std::map<std::string, std::string> metadata;
    
    template<typename T>
    void Serialize(const T& obj) {
        // Simplified serialization - would use proper binary serialization
        data.resize(sizeof(T));
        std::memcpy(data.data(), &obj, sizeof(T));
    }
    
    template<typename T>
    bool Deserialize(T& obj) const {
        if (data.size() != sizeof(T)) return false;
        std::memcpy(&obj, data.data(), sizeof(T));
        return true;
    }
};

/**
 * Complete checkpoint
 */
struct Checkpoint {
    CheckpointMetadata metadata;
    std::map<std::string, ComponentState> components;
    
    // Serialize to binary format
    std::vector<uint8_t> ToBinary() const;
    
    // Deserialize from binary
    static Checkpoint FromBinary(const std::vector<uint8_t>& data);
    
    // Serialize to JSON (for human-readable storage)
    std::string ToJson() const;
    
    // Deserialize from JSON
    static Checkpoint FromJson(const std::string& json);
};

/**
 * Checkpoint policy
 */
struct CheckpointPolicy {
    // Auto-checkpoint settings
    bool enableAutoCheckpoint = false;
    int autoCheckpointIntervalMinutes = 30;
    int maxCheckpoints = 10;
    
    // Checkpoint triggers
    bool checkpointOnConvergence = true;
    bool checkpointOnShutdown = true;
    bool checkpointOnError = false;
    
    // Compression
    bool compressCheckpoints = true;
    int compressionLevel = 6; // 0-9
    
    // Encryption (optional)
    bool encryptCheckpoints = false;
    std::string encryptionKey;
};

/**
 * Checkpoint manager
 */
class CheckpointManager {
public:
    CheckpointManager();
    ~CheckpointManager();
    
    // Initialize with storage path
    bool Initialize(const std::string& storagePath);
    
    // Set checkpoint policy
    void SetPolicy(const CheckpointPolicy& policy);
    const CheckpointPolicy& GetPolicy() const { return policy_; }
    
    // Create checkpoint
    std::string CreateCheckpoint(const std::string& description = "");
    
    // Create checkpoint with specific components
    std::string CreateCheckpoint(const std::vector<std::string>& componentNames,
                                  const std::string& description = "");
    
    // Restore from checkpoint
    bool RestoreCheckpoint(const std::string& checkpointId);
    
    // Restore specific components
    bool RestoreCheckpoint(const std::string& checkpointId,
                           const std::vector<std::string>& componentNames);
    
    // List all checkpoints
    std::vector<CheckpointMetadata> ListCheckpoints() const;
    
    // Get checkpoint metadata
    CheckpointMetadata GetCheckpointMetadata(const std::string& checkpointId) const;
    
    // Delete checkpoint
    bool DeleteCheckpoint(const std::string& checkpointId);
    
    // Delete old checkpoints (keep only N most recent)
    bool PruneCheckpoints(size_t keepCount);
    
    // Verify checkpoint integrity
    bool VerifyCheckpoint(const std::string& checkpointId) const;
    
    // Export checkpoint to file
    bool ExportCheckpoint(const std::string& checkpointId, const std::string& filePath);
    
    // Import checkpoint from file
    std::string ImportCheckpoint(const std::string& filePath);
    
    // Auto-checkpoint management
    void StartAutoCheckpoint();
    void StopAutoCheckpoint();
    bool IsAutoCheckpointRunning() const;
    
    // Get last checkpoint time
    int64_t GetLastCheckpointTime() const { return lastCheckpointTime_; }
    
    // Get checkpoint count
    size_t GetCheckpointCount() const;
    
    // Register component for checkpointing
    void RegisterComponent(const std::string& name,
                           std::function<ComponentState()> serializeFunc,
                           std::function<bool(const ComponentState&)> deserializeFunc);
    
    // Unregister component
    void UnregisterComponent(const std::string& name);
    
private:
    std::string storagePath_;
    CheckpointPolicy policy_;
    int64_t lastCheckpointTime_ = 0;
    
    std::map<std::string, std::pair<
        std::function<ComponentState()>,
        std::function<bool(const ComponentState&)>
    >> componentHandlers_;
    
    // Helper methods
    std::string GenerateCheckpointId() const;
    std::string GetCheckpointPath(const std::string& checkpointId) const;
    bool SaveCheckpointToDisk(const Checkpoint& checkpoint);
    Checkpoint LoadCheckpointFromDisk(const std::string& checkpointId) const;
    
    // Compression
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data) const;
};

/**
 * Checkpoint-aware runtime wrapper
 */
class CheckpointableRuntime {
public:
    CheckpointableRuntime();
    ~CheckpointableRuntime();
    
    // Initialize with checkpoint support
    bool Initialize(const std::string& storagePath);
    
    // Create checkpoint
    std::string Checkpoint(const std::string& description = "");
    
    // Restore from checkpoint
    bool Restore(const std::string& checkpointId);
    
    // Auto-checkpoint control
    void EnableAutoCheckpoint(int intervalMinutes = 30);
    void DisableAutoCheckpoint();
    
    // Get checkpoint manager
    CheckpointManager& GetCheckpointManager() { return *checkpointManager_; }
    const CheckpointManager& GetCheckpointManager() const { return *checkpointManager_; }
    
private:
    std::unique_ptr<CheckpointManager> checkpointManager_;
};

} // namespace Sovereign

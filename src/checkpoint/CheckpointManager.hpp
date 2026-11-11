// ============================================================================
// CheckpointManager.hpp — Task Checkpoint and Rollback System
// Enables safe undo/redo of agent operations with full state recovery
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>
#include <filesystem>

namespace RawrXD {
namespace Checkpoint {

using json = nlohmann::json;

// ============================================================================
// File Snapshot — captures file state at a point in time
// ============================================================================
struct FileSnapshot {
    std::string path;
    std::string content;
    std::string hash;           // SHA256 or content hash
    std::chrono::system_clock::time_point timestamp;
    uint64_t size = 0;
};

// ============================================================================
// Checkpoint — a point-in-time capture of project state
// ============================================================================
struct Checkpoint {
    std::string id;
    std::string name;
    std::string description;
    std::string agentName;
    std::vector<FileSnapshot> files;
    json agentState;            // Agent memory, task queue, etc.
    json metadata;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point restored;
    bool isAutoCheckpoint = false;
    uint64_t totalSize = 0;
};

// ============================================================================
// Diff Entry — represents a single file change
// ============================================================================
struct DiffEntry {
    std::string filePath;
    std::string originalContent;
    std::string newContent;
    std::string diff;           // Unified diff text
    int additions = 0;
    int deletions = 0;
    bool isBinary = false;
    bool approved = false;
    std::string reviewComment;
};

// ============================================================================
// Checkpoint Manager
// ============================================================================
class CheckpointManager {
public:
    CheckpointManager();
    ~CheckpointManager();

    // Initialization
    bool Initialize(const std::string& storagePath);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Checkpoint Operations
    std::string CreateCheckpoint(const std::string& name, 
                                  const std::string& description = "",
                                  bool isAuto = false);
    bool RestoreCheckpoint(const std::string& id);
    bool DeleteCheckpoint(const std::string& id);
    Checkpoint GetCheckpoint(const std::string& id) const;
    std::vector<Checkpoint> ListCheckpoints(int maxResults = 50) const;
    std::vector<Checkpoint> FindCheckpoints(const std::string& query) const;

    // Auto-checkpointing
    void EnableAutoCheckpoint(int intervalSec = 300);
    void DisableAutoCheckpoint();
    void TriggerAutoCheckpoint();

    // File Snapshots
    bool SnapshotFile(const std::string& filePath, const std::string& checkpointId);
    bool RestoreFile(const std::string& filePath, const std::string& checkpointId);
    bool HasSnapshot(const std::string& filePath, const std::string& checkpointId) const;

    // Diff Operations
    std::vector<DiffEntry> ComputeDiff(const std::string& checkpointId);
    std::vector<DiffEntry> ComputeDiff(const std::string& fromId, const std::string& toId);
    bool ApproveDiff(const std::string& filePath, const std::string& checkpointId);
    bool RejectDiff(const std::string& filePath, const std::string& checkpointId, 
                    const std::string& reason);

    // Rollback
    bool RollbackToLastCheckpoint();
    bool RollbackToCheckpoint(const std::string& id);
    bool RollbackFile(const std::string& filePath);

    // Statistics
    json GetStats() const;
    uint64_t GetCheckpointCount() const { return m_checkpoints.size(); }
    uint64_t GetTotalSize() const;

    // Persistence
    bool SaveState();
    bool LoadState();

    // Callbacks
    using CheckpointCallback = std::function<void(const Checkpoint&)>;
    using RollbackCallback = std::function<void(const std::string& checkpointId, bool success)>;
    
    void SetCheckpointCallback(CheckpointCallback cb) { m_checkpointCb = cb; }
    void SetRollbackCallback(RollbackCallback cb) { m_rollbackCb = cb; }

private:
    std::string GenerateId();
    bool SnapshotFiles(const std::vector<std::string>& paths, Checkpoint& cp);
    bool RestoreFiles(const Checkpoint& cp);
    std::string ComputeFileHash(const std::string& path);
    std::string ComputeDiff(const std::string& original, const std::string& modified);
    void AutoCheckpointLoop();

private:
    std::string m_storagePath;
    std::vector<Checkpoint> m_checkpoints;
    mutable std::mutex m_mutex;
    bool m_initialized = false;
    bool m_autoCheckpointEnabled = false;
    int m_autoCheckpointIntervalSec = 300;
    std::thread m_autoCheckpointThread;
    
    CheckpointCallback m_checkpointCb;
    RollbackCallback m_rollbackCb;
};

} // namespace Checkpoint
} // namespace RawrXD

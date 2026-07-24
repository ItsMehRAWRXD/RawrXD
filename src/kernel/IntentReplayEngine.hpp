// Intent Replay Engine - Deterministic Replay of Autonomous Actions
// 
// Every autonomous action becomes reproducible:
//   intent.json + context hash + patch + validation = replay
//
// This enables:
//   - Debugging failed intents
//   - Regression testing
//   - Audit trails
//   - Distributed replay across nodes

#pragma once

#include "AgentKernel.hpp"
#include "../intent/intent_abi.hpp"
#include "../hotpatch/patch_transaction.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>

namespace RawrXD {
namespace Kernel {

// Forward declarations
class ReplaySession;
class ReplayJournal;

// ============================================================================
// Snapshot Types - Capture system state at point in time
// ============================================================================

struct FileSystemSnapshot {
    uint64_t snapshotId;
    std::string rootPath;
    std::unordered_map<std::string, std::string> fileHashes;  // path -> hash
    std::unordered_map<std::string, uint64_t> fileTimestamps;
    
    std::string ComputeAggregateHash() const;
    bool HasFileChanged(const std::string& path, const std::string& hash) const;
};

struct MemorySnapshot {
    uint64_t snapshotId;
    std::unordered_map<std::string, uintptr_t> symbolAddresses;
    std::unordered_map<std::string, std::vector<uint8_t>> memoryRegions;
    
    std::string ComputeAggregateHash() const;
};

struct BuildSnapshot {
    uint64_t snapshotId;
    std::string buildConfig;  // Debug/Release/etc
    std::string cmakeCacheHash;
    std::vector<std::string> objectFiles;
    std::string executableHash;
    
    bool IsValid() const;
    std::string ComputeAggregateHash() const;
};

struct ContextSnapshot {
    uint64_t snapshotId;
    uint64_t timestamp;
    
    FileSystemSnapshot fs;
    MemorySnapshot memory;
    BuildSnapshot build;
    
    // Agent state
    AgentId agentId;
    std::string agentType;
    std::vector<uint64_t> agentIntentHistory;
    
    // Kernel state
    std::vector<std::shared_ptr<ResourceLease>> activeLeases;
    BeaconEvent lastBeacon;
    
    std::string ComputeContextHash() const;
};

// ============================================================================
// Replay Record - Complete record of an intent execution
// ============================================================================

struct ReplayRecord {
    uint64_t recordId;
    uint64_t timestamp;
    
    // Intent
    IntentRequest intent;
    Intent::IntentRequest abiIntent;
    
    // Snapshots
    ContextSnapshot preSnapshot;
    ContextSnapshot postSnapshot;
    
    // Execution
    std::vector<BeaconEvent> events;
    std::vector<std::shared_ptr<ResourceLease>> leases;
    std::unique_ptr<Hotpatch::PatchTransaction> transaction;
    
    // Results
    bool succeeded;
    std::string errorMessage;
    uint64_t executionTimeMs;
    
    // Patch data
    std::vector<uint8_t> patchData;
    std::string patchHash;
    
    // Serialization
    std::string ToJson() const;
    static std::optional<ReplayRecord> FromJson(const std::string& json);
    
    // Compute deterministic hash
    std::string ComputeReplayHash() const;
};

// ============================================================================
// Replay Journal - Persistent storage of replay records
// ============================================================================

class ReplayJournal {
public:
    static ReplayJournal& Instance();
    
    // Lifecycle
    void Initialize(const std::string& journalPath = ".rawrxd/replay_journal");
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Recording
    uint64_t StartRecording(const IntentRequest& intent);
    void RecordSnapshot(uint64_t recordId, const ContextSnapshot& snapshot, bool isPre);
    void RecordEvent(uint64_t recordId, const BeaconEvent& event);
    void RecordLease(uint64_t recordId, std::shared_ptr<ResourceLease> lease);
    void RecordTransaction(uint64_t recordId, Hotpatch::PatchTransaction&& tx);
    void RecordResult(uint64_t recordId, bool success, const std::string& error, uint64_t timeMs);
    void FinalizeRecord(uint64_t recordId);
    
    // Retrieval
    std::optional<ReplayRecord> GetRecord(uint64_t recordId) const;
    std::vector<ReplayRecord> GetRecordsForIntent(const std::string& intentType, size_t max = 100) const;
    std::vector<ReplayRecord> GetRecordsForAgent(AgentId agent, size_t max = 100) const;
    std::vector<ReplayRecord> GetFailedRecords(size_t max = 100) const;
    std::vector<ReplayRecord> GetRecentRecords(size_t max = 100) const;
    
    // Query
    std::optional<ReplayRecord> FindSimilarRecord(const IntentRequest& intent, 
                                                   const ContextSnapshot& context) const;
    
    // Management
    void PruneOldRecords(std::chrono::days maxAge);
    void ExportRecords(const std::string& exportPath) const;
    void ImportRecords(const std::string& importPath);
    
    // Statistics
    struct JournalStats {
        uint64_t totalRecords;
        uint64_t successfulRecords;
        uint64_t failedRecords;
        uint64_t totalSizeBytes;
        std::chrono::system_clock::time_point oldestRecord;
        std::chrono::system_clock::time_point newestRecord;
    };
    JournalStats GetStats() const;
    
private:
    ReplayJournal() = default;
    
    std::string journalPath_;
    std::atomic<bool> initialized_{false};
    std::atomic<uint64_t> nextRecordId_{1};
    
    mutable std::mutex recordsMutex_;
    std::unordered_map<uint64_t, ReplayRecord> records_;
    
    // Index for fast queries
    std::unordered_map<std::string, std::vector<uint64_t>> intentTypeIndex_;
    std::unordered_map<AgentId, std::vector<uint64_t>> agentIndex_;
    std::vector<uint64_t> failedRecords_;
    std::vector<uint64_t> recentRecords_;  // Ordered by time
    
    void PersistRecord(const ReplayRecord& record);
    void LoadExistingRecords();
};

// ============================================================================
// Replay Session - Execute a replay
// ============================================================================

enum class ReplayMode {
    EXACT,          // Exact replay with same inputs
    ADAPTIVE,       // Adapt to current context
    DRY_RUN,        // Simulate without side effects
    DEBUG           // Step-through debugging
};

struct ReplayOptions {
    ReplayMode mode = ReplayMode::EXACT;
    bool stopOnMismatch = true;      // Stop if context differs
    bool captureNewSnapshot = true;  // Capture post-replay state
    bool validateResults = true;     // Compare results to original
    std::chrono::milliseconds timeout{30000};
};

struct ReplayResult {
    bool success;
    std::string errorMessage;
    
    // Comparison to original
    bool contextMatched;
    bool resultMatched;
    std::string contextDiff;
    std::string resultDiff;
    
    // Timing
    uint64_t originalTimeMs;
    uint64_t replayTimeMs;
    double timeDeltaPercent;
    
    // New record (if captured)
    std::optional<ReplayRecord> newRecord;
};

class ReplaySession {
public:
    ReplaySession(uint64_t recordId, const ReplayOptions& options);
    
    // Preparation
    bool Prepare();
    bool CheckContextMatch(std::string* diff = nullptr) const;
    bool RestorePreConditions();
    
    // Execution
    ReplayResult Execute();
    
    // Step-through (for DEBUG mode)
    bool StepNext();
    bool IsComplete() const;
    std::string GetCurrentStep() const;
    
    // Results
    ReplayRecord GetOriginalRecord() const;
    std::optional<ReplayRecord> GetNewRecord() const;
    
private:
    uint64_t recordId_;
    ReplayOptions options_;
    
    std::optional<ReplayRecord> originalRecord_;
    std::optional<ReplayRecord> newRecord_;
    
    // Execution state
    size_t currentStep_{0};
    std::vector<std::string> executionSteps_;
    
    bool PrepareExactReplay();
    bool PrepareAdaptiveReplay();
    ReplayResult ExecuteExact();
    ReplayResult ExecuteAdaptive();
    ReplayResult ExecuteDryRun();
};

// ============================================================================
// Snapshot Manager - Capture and restore system state
// ============================================================================

class SnapshotManager {
public:
    static SnapshotManager& Instance();
    
    // Capture
    ContextSnapshot CaptureFullSnapshot();
    FileSystemSnapshot CaptureFileSystem(const std::string& rootPath);
    MemorySnapshot CaptureMemory();
    BuildSnapshot CaptureBuild();
    
    // Restore
    bool RestoreFileSystem(const FileSystemSnapshot& snapshot);
    bool RestoreMemory(const MemorySnapshot& snapshot);
    bool RestoreBuild(const BuildSnapshot& snapshot);
    
    // Comparison
    struct DiffResult {
        bool identical;
        std::vector<std::string> differences;
    };
    DiffResult CompareSnapshots(const ContextSnapshot& a, const ContextSnapshot& b) const;
    DiffResult CompareFileSystems(const FileSystemSnapshot& a, const FileSystemSnapshot& b) const;
    
    // Persistence
    bool SaveSnapshot(const ContextSnapshot& snapshot, const std::string& path);
    std::optional<ContextSnapshot> LoadSnapshot(const std::string& path);
};

// ============================================================================
// Intent Replay Engine - Main API
// ============================================================================

class IntentReplayEngine {
public:
    static IntentReplayEngine& Instance();
    
    // Lifecycle
    bool Initialize(const std::string& journalPath = ".rawrxd/replay_journal");
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // Recording control
    void StartRecordingIntent(const IntentRequest& intent);
    void StopRecordingIntent(bool success, const std::string& error);
    bool IsRecording() const { return isRecording_.load(); }
    
    // Replay control
    ReplayResult ReplayIntent(uint64_t recordId, const ReplayOptions& options);
    ReplayResult ReplayLastIntent(const ReplayOptions& options);
    
    // Batch replay
    std::vector<ReplayResult> ReplayIntentType(const std::string& intentType, 
                                                const ReplayOptions& options);
    std::vector<ReplayResult> ReplayFailedIntents(const ReplayOptions& options);
    
    // Analysis
    std::string GenerateReplayReport(uint64_t recordId) const;
    std::string GenerateRegressionReport(const std::string& intentType) const;
    
    // Integration with execution pipeline
    void ConnectToPipeline();
    void DisconnectFromPipeline();
    
private:
    IntentReplayEngine() = default;
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> isRecording_{false};
    std::atomic<uint64_t> currentRecordId_{0};
    
    // Pipeline integration
    uint64_t pipelineSubscriptionId_{0};
    
    void OnPipelineEvent(const BeaconEvent& event);
};

// ============================================================================
// Convenience API
// ============================================================================

#define REPLAY_ENGINE RawrXD::Kernel::IntentReplayEngine::Instance()
#define REPLAY_JOURNAL RawrXD::Kernel::ReplayJournal::Instance()
#define SNAPSHOT_MANAGER RawrXD::Kernel::SnapshotManager::Instance()

// Quick replay helper
inline ReplayResult QuickReplay(uint64_t recordId) {
    ReplayOptions opts;
    opts.mode = ReplayMode::EXACT;
    return REPLAY_ENGINE.ReplayIntent(recordId, opts);
}

// Record current execution scope
class ScopedReplayRecording {
public:
    explicit ScopedReplayRecording(const IntentRequest& intent);
    ~ScopedReplayRecording();
    
    void MarkSuccess();
    void MarkFailed(const std::string& error);
    
private:
    uint64_t recordId_;
    bool finalized_{false};
};

} // namespace Kernel
} // namespace RawrXD

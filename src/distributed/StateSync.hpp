/**
 * StateSync.hpp
 *
 * Phase D.3 Batch 2/5: State Synchronization Protocol
 *
 * Distributed state synchronization with CRDT-based conflict resolution.
 * Ensures eventual consistency across all nodes.
 */

#pragma once

#include "CRDTTypes.hpp"
#include "NodeCommunication.hpp"
#include <functional>
#include <future>

namespace Distributed {

// ============================================================================
// Forward Declarations
// ============================================================================

class StateReplicator;
class DeltaSync;
class StateSnapshot;
class SyncScheduler;

// ============================================================================
// State Types
// ============================================================================

enum class StateType {
    AGENT_STATE,        // Agent runtime state
    MODEL_STATE,        // Model loading/execution state
    CONFIG_STATE,       // Configuration state
    METRICS_STATE,      // Performance metrics
    SESSION_STATE,      // User session state
    CUSTOM_STATE        // User-defined state
};

std::string StateTypeToString(StateType type);
StateType StateTypeFromString(const std::string& str);

// ============================================================================
// State Key
// ============================================================================

/**
 * Unique identifier for a state entry.
 */
struct StateKey {
    StateType type;
    std::string scope;      // e.g., "agent", "model", "global"
    std::string name;       // Specific state name
    
    std::string ToString() const;
    static StateKey FromString(const std::string& str);
    
    bool operator==(const StateKey& other) const;
    bool operator<(const StateKey& other) const;
};

// ============================================================================
// State Entry
// ============================================================================

/**
 * Single state entry with metadata.
 */
struct StateEntry {
    StateKey key;
    std::vector<uint8_t> data;
    VersionVector version;
    uint64_t timestamp;
    std::string nodeId;
    uint32_t checksum;
    
    // Calculate checksum
    uint32_t CalculateChecksum() const;
    bool VerifyChecksum() const;
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static StateEntry Deserialize(const std::vector<uint8_t>& data);
};

// ============================================================================
// State Change
// ============================================================================

/**
 * Represents a change to state.
 */
struct StateChange {
    enum class Type {
        SET,        // Set value
        DELETE,     // Delete key
        MERGE,      // Merge with existing
        CLEAR       // Clear all
    };
    
    Type type;
    StateKey key;
    std::vector<uint8_t> data;
    VersionVector version;
    uint64_t timestamp;
    std::string sourceNode;
};

// ============================================================================
// Sync Configuration
// ============================================================================

/**
 * Configuration for state synchronization.
 */
struct SyncConfig {
    // Timing
    uint64_t syncIntervalMs = 1000;           // Full sync interval
    uint64_t deltaSyncIntervalMs = 100;       // Delta sync interval
    uint64_t snapshotIntervalMs = 60000;      // Snapshot interval
    
    // Thresholds
    size_t maxDeltaSize = 1024 * 1024;        // Max delta size (1MB)
    size_t maxBatchSize = 100;                // Max changes per batch
    uint64_t maxSyncLagMs = 5000;             // Max acceptable lag
    
    // Conflict resolution
    bool enableCRDT = true;                   // Use CRDT merging
    bool enableTombstones = true;             // Track deletions
    uint64_t tombstoneRetentionMs = 86400000;   // Tombstone retention (24h)
    
    // Performance
    bool compressDeltas = true;               // Compress delta messages
    bool prioritizeActive = true;             // Prioritize active state
    size_t maxConcurrentSyncs = 5;            // Max parallel syncs
    
    // Validation
    bool verifyChecksums = true;              // Verify data integrity
    bool trackCausality = true;               // Track happens-before
};

// ============================================================================
// Sync Status
// ============================================================================

/**
 * Status of synchronization with a peer.
 */
struct SyncStatus {
    std::string peerNodeId;
    VersionVector localVersion;
    VersionVector peerVersion;
    uint64_t lastSyncTime;
    uint64_t lastSuccessTime;
    uint64_t lagMs;
    size_t pendingChanges;
    bool isSyncing;
    bool isHealthy;
    
    std::string ToJson() const;
};

// ============================================================================
// State Snapshot
// ============================================================================

/**
 * Point-in-time snapshot of state.
 */
class StateSnapshot {
public:
    StateSnapshot();
    explicit StateSnapshot(const VersionVector& version);
    
    // Add entry
    void AddEntry(const StateEntry& entry);
    void AddEntries(const std::vector<StateEntry>& entries);
    
    // Query
    std::optional<StateEntry> GetEntry(const StateKey& key) const;
    std::vector<StateEntry> GetEntriesByType(StateType type) const;
    std::vector<StateEntry> GetAllEntries() const;
    size_t Size() const;
    bool IsEmpty() const;
    
    // Version
    VersionVector GetVersion() const;
    void SetVersion(const VersionVector& version);
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static StateSnapshot Deserialize(const std::vector<uint8_t>& data);
    
    // Compression
    std::vector<uint8_t> Compress() const;
    static StateSnapshot Decompress(const std::vector<uint8_t>& data);
    
private:
    VersionVector version_;
    std::map<StateKey, StateEntry> entries_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Delta Sync
// ============================================================================

/**
 * Efficient delta-based synchronization.
 */
class DeltaSync {
public:
    explicit DeltaSync(const SyncConfig& config);
    ~DeltaSync();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Delta generation
    std::optional<Delta> GenerateDelta(
        const VersionVector& fromVersion,
        const VersionVector& toVersion
    );
    
    std::optional<Delta> GenerateDeltaForPeer(
        const std::string& peerNodeId,
        const VersionVector& peerVersion
    );
    
    // Delta application
    bool ApplyDelta(const Delta& delta);
    bool ApplyDeltas(const std::vector<Delta>& deltas);
    
    // Change tracking
    void TrackChange(const StateChange& change);
    void TrackChanges(const std::vector<StateChange>& changes);
    
    // Get changes since version
    std::vector<StateChange> GetChangesSince(
        const VersionVector& version,
        size_t maxChanges = 0
    );
    
    // Pruning
    void PruneOldChanges(uint64_t olderThanMs);
    void PruneTombstones();
    
    // Status
    size_t GetPendingChangeCount() const;
    size_t GetTombstoneCount() const;
    
private:
    SyncConfig config_;
    
    struct TrackedChange {
        StateChange change;
        uint64_t timestamp;
    };
    
    std::vector<TrackedChange> changes_;
    std::map<StateKey, StateChange> tombstones_;
    VersionVector currentVersion_;
    
    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    
    // Internal methods
    void CleanupOldChanges();
    std::vector<uint8_t> EncodeChanges(
        const std::vector<TrackedChange>& changes
    );
    std::vector<StateChange> DecodeChanges(const std::vector<uint8_t>& data);
};

// ============================================================================
// State Replicator
// ============================================================================

/**
 * Replicates state across cluster nodes.
 */
class StateReplicator {
public:
    using StateChangeCallback = std::function<void(const StateChange&)>;
    using SyncCompleteCallback = std::function<void(const std::string& peerNodeId, bool success)>;
    
    StateReplicator(
        std::shared_ptr<CommunicationManager> commManager,
        const SyncConfig& config
    );
    ~StateReplicator();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // State operations
    bool SetState(const StateKey& key, const std::vector<uint8_t>& data);
    bool SetState(const StateKey& key, const std::string& data);
    bool SetStateJson(const StateKey& key, const std::string& json);
    
    std::optional<std::vector<uint8_t>> GetState(const StateKey& key);
    std::optional<std::string> GetStateString(const StateKey& key);
    std::optional<std::string> GetStateJson(const StateKey& key);
    
    bool DeleteState(const StateKey& key);
    bool HasState(const StateKey& key);
    
    // Bulk operations
    bool SetMultiple(const std::map<StateKey, std::vector<uint8_t>>& states);
    std::map<StateKey, std::vector<uint8_t>> GetMultiple(
        const std::vector<StateKey>& keys
    );
    std::map<StateKey, std::vector<uint8_t>> GetAllByType(StateType type);
    
    // Synchronization
    bool RequestSync(const std::string& peerNodeId);
    bool RequestSyncAll();
    bool IsSyncing(const std::string& peerNodeId);
    
    // Snapshot
    StateSnapshot CreateSnapshot();
    bool RestoreSnapshot(const StateSnapshot& snapshot);
    bool RequestSnapshot(const std::string& peerNodeId);
    
    // Callbacks
    void OnStateChange(StateChangeCallback callback);
    void OnSyncComplete(SyncCompleteCallback callback);
    
    // Status
    SyncStatus GetSyncStatus(const std::string& peerNodeId);
    std::vector<SyncStatus> GetAllSyncStatus();
    bool IsFullySynced();
    uint64_t GetMaxLagMs();
    
    // CRDT access
    CRDTManager* GetCRDTManager();
    
    // Conflict resolution
    StateEntry ResolveConflict(
        const StateEntry& local,
        const StateEntry& remote
    );
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    SyncConfig config_;
    
    std::unique_ptr<DeltaSync> deltaSync_;
    std::unique_ptr<CRDTManager> crdtManager_;
    
    std::map<StateKey, StateEntry> localState_;
    std::map<std::string, SyncStatus> peerStatus_;
    
    StateChangeCallback changeCallback_;
    SyncCompleteCallback syncCompleteCallback_;
    
    mutable std::mutex stateMutex_;
    mutable std::mutex callbackMutex_;
    std::atomic<bool> running_{false};
    
    // Background threads
    std::thread syncThread_;
    std::thread snapshotThread_;
    
    // Message handlers
    void HandleDeltaMessage(const Message& message);
    void HandleSyncRequest(const Message& message);
    void HandleSyncResponse(const Message& message);
    void HandleSnapshotRequest(const Message& message);
    void HandleSnapshotResponse(const Message& message);
    
    // Background loops
    void SyncLoop();
    void SnapshotLoop();
    
    // Internal methods
    void NotifyStateChange(const StateChange& change);
    void NotifySyncComplete(const std::string& peerNodeId, bool success);
    void UpdatePeerVersion(const std::string& peerNodeId, const VersionVector& version);
    std::vector<uint8_t> EncodeStateValue(const std::string& value);
    std::string DecodeStateValue(const std::vector<uint8_t>& data);
};

// ============================================================================
// Sync Scheduler
// ============================================================================

/**
 * Schedules and prioritizes synchronization tasks.
 */
class SyncScheduler {
public:
    struct Task {
        enum class Priority {
            CRITICAL,   // Immediate sync required
            HIGH,       // Active state changes
            NORMAL,     // Regular sync
            LOW,        // Background sync
            SNAPSHOT    // Full snapshot
        };
        
        Priority priority;
        std::string peerNodeId;
        StateType type;
        uint64_t timestamp;
        VersionVector targetVersion;
        
        bool operator<(const Task& other) const;
    };
    
    explicit SyncScheduler(const SyncConfig& config);
    ~SyncScheduler();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Schedule tasks
    void ScheduleSync(const std::string& peerNodeId, Task::Priority priority);
    void ScheduleDeltaSync(const std::string& peerNodeId, const VersionVector& from);
    void ScheduleSnapshot(const std::string& peerNodeId);
    void ScheduleFullSync();
    
    // Get next task
    std::optional<Task> GetNextTask();
    
    // Cancel tasks
    void CancelTasksForPeer(const std::string& peerNodeId);
    void CancelAllTasks();
    
    // Status
    size_t GetPendingTaskCount() const;
    size_t GetTaskCountByPriority(Task::Priority priority) const;
    
private:
    SyncConfig config_;
    
    std::priority_queue<Task> tasks_;
    std::set<std::string> activeSyncs_;
    
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> running_{false};
};

// ============================================================================
// State Synchronizer (High-level API)
// ============================================================================

/**
 * High-level state synchronization facade.
 */
class StateSynchronizer {
public:
    StateSynchronizer(
        std::shared_ptr<CommunicationManager> commManager,
        const SyncConfig& config = SyncConfig{}
    );
    ~StateSynchronizer();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Simple API
    bool Set(const std::string& key, const std::string& value);
    bool SetJson(const std::string& key, const std::string& json);
    std::optional<std::string> Get(const std::string& key);
    std::optional<std::string> GetJson(const std::string& key);
    bool Delete(const std::string& key);
    bool Exists(const std::string& key);
    
    // Typed API
    template<typename T>
    bool SetTyped(const std::string& key, const T& value);
    
    template<typename T>
    std::optional<T> GetTyped(const std::string& key);
    
    // Sync control
    bool SyncNow(const std::string& peerNodeId);
    bool SyncAllNow();
    bool IsSyncComplete();
    void WaitForSync();
    
    // Status
    bool IsHealthy();
    std::string GetStatusJson();
    
    // Advanced access
    StateReplicator* GetReplicator();
    
private:
    std::unique_ptr<StateReplicator> replicator_;
    std::unique_ptr<SyncScheduler> scheduler_;
};

} // namespace Distributed

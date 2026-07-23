#pragma once
#include "IntentABI.hpp"
#include <deque>
#include <map>
#include <chrono>

// =============================================================================
// HotpatchJournal - Every mutation logged for rollback
// All features toggleable at compile-time and runtime
// =============================================================================

namespace RawrXD {
namespace Sovereign {
namespace Guardrails {

// =============================================================================
// Journal Entry - Single patch record
// =============================================================================

struct JournalEntry {
    std::string transactionId;
    uint64_t timestamp;
    uint64_t sessionId;
    
    // State hashes
    std::string beforeStateHash;   // SHA256 of filesystem before
    std::string afterStateHash;    // SHA256 of filesystem after
    std::string memoryStateHash;   // Runtime memory snapshot
    
    // Patch details
    IntentRequest intent;
    std::string patchDiff;
    std::string compiledBinary;    // If applicable
    
    // Validation results
    IntentResponse validation;
    bool testsPassed{false};
    bool securityScanPassed{false};
    
    // Rollback info
    std::string rollbackSnapshotPath;
    bool canRollback{true};
    
    // Toggle: Mark as non-rollbackable (e.g., destructive ops)
    bool permanent{false};
    std::string permanentJustification;
};

// =============================================================================
// Rollback Point - Restorable state
// =============================================================================

struct RollbackPoint {
    std::string pointId;
    uint64_t timestamp;
    std::string journalEntryId;
    
    // Snapshot paths
    std::string filesystemSnapshot;
    std::string memorySnapshot;
    std::string registrySnapshot;
    
    // Verification
    std::string stateHash;
    bool verified{false};
};

// =============================================================================
// HotpatchJournal - Transaction log and rollback system
// =============================================================================

class HotpatchJournal {
public:
    static HotpatchJournal& Instance();
    
    // Master toggle
    void SetEnabled(bool enabled) { enabled_ = enabled; }
    bool IsEnabled() const { return enabled_; }
    
    // Toggle: Journal recording
    void SetRecordingEnabled(bool enabled) { recordingEnabled_ = enabled; }
    bool IsRecordingEnabled() const { return recordingEnabled_; }
    
    // Toggle: Rollback capability
    void SetRollbackEnabled(bool enabled) { rollbackEnabled_ = enabled; }
    bool IsRollbackEnabled() const { return rollbackEnabled_; }
    
    // Toggle: Compression
    void SetCompressionEnabled(bool enabled) { compressionEnabled_ = enabled; }
    bool IsCompressionEnabled() const { return compressionEnabled_; }
    
    // Journal operations
    std::string BeginTransaction(const IntentRequest& intent);
    bool CommitTransaction(const std::string& transactionId, const IntentResponse& result);
    bool AbortTransaction(const std::string& transactionId);
    
    // Rollback operations
    bool CanRollback(const std::string& transactionId) const;
    bool RollbackTo(const std::string& transactionId);
    bool RollbackToPrevious();
    bool RollbackN(size_t n);
    
    // Snapshot management
    std::string CreateSnapshot(const std::string& name);
    bool RestoreSnapshot(const std::string& snapshotId);
    bool DeleteSnapshot(const std::string& snapshotId);
    std::vector<std::string> ListSnapshots() const;
    
    // Query
    std::vector<JournalEntry> GetRecentEntries(size_t count) const;
    std::optional<JournalEntry> GetEntry(const std::string& transactionId) const;
    size_t GetEntryCount() const;
    
    // Configuration
    void SetMaxJournalSize(size_t entries) { maxJournalSize_ = entries; }
    size_t GetMaxJournalSize() const { return maxJournalSize_; }
    
    void SetMaxSnapshotSize(size_t bytes) { maxSnapshotSize_ = bytes; }
    size_t GetMaxSnapshotSize() const { return maxSnapshotSize_; }
    
    void SetJournalPath(const std::string& path) { journalPath_ = path; }
    std::string GetJournalPath() const { return journalPath_; }
    
    // Persistence
    bool SaveJournal();
    bool LoadJournal();
    bool ClearJournal();
    
    // Emergency: Disable all rollback (destructive)
    void EmergencyClear(const std::string& justification);

private:
    HotpatchJournal() = default;
    
    std::string GenerateTransactionId();
    bool PruneOldEntries();
    bool VerifySnapshotIntegrity(const std::string& snapshotId);
    
    // State
    std::atomic<bool> enabled_{true};
    std::atomic<bool> recordingEnabled_{true};
    std::atomic<bool> rollbackEnabled_{true};
    std::atomic<bool> compressionEnabled_{true};
    std::atomic<size_t> maxJournalSize_{1000};
    std::atomic<size_t> maxSnapshotSize_{1024 * 1024 * 1024};  // 1GB
    
    std::string journalPath_{"~/.rawrxd/journal"};
    std::deque<JournalEntry> entries_;
    std::map<std::string, RollbackPoint> snapshots_;
    mutable std::mutex journalMutex_;
};

// =============================================================================
// Compile-time toggles
// =============================================================================

#if RAWRXD_HOTPATCH_JOURNAL_ENABLED
    #define JOURNAL_ENABLED true
    #define JOURNAL_BEGIN(intent) HotpatchJournal::Instance().BeginTransaction(intent)
    #define JOURNAL_COMMIT(id, result) HotpatchJournal::Instance().CommitTransaction(id, result)
    #define JOURNAL_ROLLBACK(id) HotpatchJournal::Instance().RollbackTo(id)
#else
    #define JOURNAL_ENABLED false
    #define JOURNAL_BEGIN(intent) std::string("noop")
    #define JOURNAL_COMMIT(id, result) true
    #define JOURNAL_ROLLBACK(id) true
#endif

} // namespace Guardrails
} // namespace Sovereign
} // namespace RawrXD

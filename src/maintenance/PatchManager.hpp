// RawrXD Patch Manager
// Phase W.2: Patch management and differential updates
// Handles binary patching, delta updates, and version migration

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Maintenance {

// Patch type
enum class PatchType {
    BINARY_DIFF,    // Binary diff patch
    CONFIG_UPDATE,  // Configuration change
    HOTFIX,         // Critical hotfix
    SECURITY,       // Security patch
    FEATURE,        // Feature update
    ROLLBACK        // Rollback patch
};

// Patch status
enum class PatchStatus {
    PENDING,        // Waiting to be applied
    DOWNLOADING,    // Downloading patch
    VALIDATING,     // Validating patch integrity
    APPLYING,       // Applying patch
    APPLIED,        // Successfully applied
    FAILED,         // Failed to apply
    ROLLED_BACK     // Was rolled back
};

// Patch metadata
struct PatchMetadata {
    std::string patchId;
    std::string version;
    std::string previousVersion;
    PatchType type;
    std::string description;
    std::vector<std::string> changelog;
    std::chrono::system_clock::time_point releasedAt;
    std::chrono::system_clock::time_point appliedAt;
    uint64_t size;
    std::string checksum;
    std::string signature;
    std::vector<std::string> prerequisites;
    std::vector<std::string> affectedFiles;
    bool requiresRestart{false};
    bool isMandatory{false};
    std::map<std::string, std::string> metadata;
};

// Patch file
struct PatchFile {
    std::string path;
    std::string operation;  // "add", "modify", "delete"
    std::string oldHash;
    std::string newHash;
    uint64_t oldSize;
    uint64_t newSize;
    std::vector<uint8_t> diffData;
};

// Patch package
struct PatchPackage {
    PatchMetadata metadata;
    std::vector<PatchFile> files;
    std::vector<uint8_t> binaryData;
};

// Delta patch
struct DeltaPatch {
    std::string sourceVersion;
    std::string targetVersion;
    std::vector<uint8_t> deltaData;
    uint64_t sourceSize;
    uint64_t targetSize;
    double compressionRatio;
};

// Backup entry
struct BackupEntry {
    std::string backupId;
    std::string originalPath;
    std::string backupPath;
    std::chrono::system_clock::time_point createdAt;
    uint64_t size;
    std::string checksum;
};

// Patch result
struct PatchResult {
    bool success;
    std::string patchId;
    PatchStatus finalStatus;
    std::chrono::milliseconds duration;
    std::string errorMessage;
    std::vector<std::string> affectedFiles;
    std::vector<std::string> warnings;
};

// Patch manager
class PatchManager {
public:
    PatchManager();
    ~PatchManager();
    
    // Initialization
    bool initialize(const std::string& backupDirectory);
    bool shutdown();
    
    // Patch discovery
    std::vector<PatchMetadata> checkForPatches(const std::string& updateServer);
    bool downloadPatch(const std::string& patchId, const std::string& sourceUrl);
    bool validatePatch(const std::string& patchId);
    
    // Patch application
    PatchResult applyPatch(const std::string& patchId);
    PatchResult applyPatchAsync(const std::string& patchId);
    bool canApplyPatch(const std::string& patchId) const;
    std::vector<std::string> getMissingPrerequisites(const std::string& patchId) const;
    
    // Patch rollback
    bool rollbackPatch(const std::string& patchId);
    bool rollbackToVersion(const std::string& version);
    bool canRollback(const std::string& patchId) const;
    
    // Delta patching
    DeltaPatch createDelta(const std::string& oldFile, const std::string& newFile);
    bool applyDelta(const DeltaPatch& delta, const std::string& outputPath);
    std::vector<DeltaPatch> createDeltaChain(const std::string& fromVersion, 
                                             const std::string& toVersion);
    
    // Binary diff
    std::vector<uint8_t> createBinaryDiff(const std::vector<uint8_t>& oldData,
                                           const std::vector<uint8_t>& newData);
    std::vector<uint8_t> applyBinaryDiff(const std::vector<uint8_t>& oldData,
                                         const std::vector<uint8_t>& diff);
    
    // Backup management
    std::string createBackup(const std::string& path);
    bool restoreBackup(const std::string& backupId);
    bool deleteBackup(const std::string& backupId);
    std::vector<BackupEntry> listBackups() const;
    void cleanupOldBackups(std::chrono::hours maxAge);
    
    // Patch history
    std::vector<PatchMetadata> getPatchHistory() const;
    std::vector<PatchMetadata> getPatchHistoryForVersion(const std::string& version) const;
    PatchMetadata getPatchInfo(const std::string& patchId) const;
    
    // Current status
    PatchStatus getPatchStatus(const std::string& patchId) const;
    std::vector<std::string> getPendingPatches() const;
    std::vector<std::string> getAppliedPatches() const;
    std::vector<std::string> getFailedPatches() const;
    
    // Configuration migration
    bool migrateConfiguration(const std::string& fromVersion, 
                              const std::string& toVersion);
    std::map<std::string, std::string> getConfigurationChanges(
        const std::string& fromVersion,
        const std::string& toVersion) const;
    
    // Database migration
    bool migrateDatabase(const std::string& fromVersion,
                        const std::string& toVersion);
    bool validateDatabaseMigration(const std::string& fromVersion,
                                   const std::string& toVersion) const;
    
    // Statistics
    struct PatchStats {
        uint32_t totalPatches;
        uint32_t appliedPatches;
        uint32_t failedPatches;
        uint32_t rolledBackPatches;
        uint64_t totalBytesPatched;
        uint64_t totalBytesDownloaded;
        std::chrono::seconds totalPatchTime;
    };
    PatchStats getStats() const;
    
    // Callbacks
    using PatchCallback = std::function<void(const std::string& patchId, PatchStatus status)>;
    using ProgressCallback = std::function<void(const std::string& operation, 
                                                  uint64_t current, uint64_t total)>;
    void onPatchStatusChange(PatchCallback callback);
    void onProgress(ProgressCallback callback);

private:
    bool applyPatchInternal(const PatchPackage& package);
    bool createFileBackup(const std::string& path);
    bool restoreFileFromBackup(const std::string& path);
    std::string calculateChecksum(const std::string& path) const;
    void notifyStatusChange(const std::string& patchId, PatchStatus status);
    void notifyProgress(const std::string& operation, uint64_t current, uint64_t total);
    
    mutable std::mutex mutex_;
    std::string backupDirectory_;
    std::map<std::string, PatchPackage> patches_;
    std::map<std::string, PatchStatus> patchStatuses_;
    std::map<std::string, BackupEntry> backups_;
    std::vector<PatchMetadata> patchHistory_;
    
    PatchCallback statusCallback_;
    ProgressCallback progressCallback_;
    PatchStats stats_{};
};

// Version migrator
class VersionMigrator {
public:
    VersionMigrator();
    
    // Migration registration
    void registerMigration(const std::string& fromVersion, 
                          const std::string& toVersion,
                          std::function<bool()> migrationFunc);
    void registerConfigurationMigration(const std::string& fromVersion,
                                        const std::string& toVersion,
                                        std::function<bool()> migrationFunc);
    void registerDatabaseMigration(const std::string& fromVersion,
                                   const std::string& toVersion,
                                   std::function<bool()> migrationFunc);
    
    // Migration execution
    bool migrate(const std::string& fromVersion, const std::string& toVersion);
    bool canMigrate(const std::string& fromVersion, const std::string& toVersion) const;
    std::vector<std::string> getMigrationPath(const std::string& fromVersion,
                                              const std::string& toVersion) const;
    
    // Migration info
    struct MigrationInfo {
        std::string fromVersion;
        std::string toVersion;
        bool hasConfigurationMigration;
        bool hasDatabaseMigration;
        std::chrono::seconds estimatedDuration;
        bool requiresDowntime;
    };
    std::vector<MigrationInfo> listMigrations() const;
    MigrationInfo getMigrationInfo(const std::string& fromVersion,
                                   const std::string& toVersion) const;

private:
    struct MigrationEntry {
        std::function<bool()> migrationFunc;
        std::function<bool()> configMigration;
        std::function<bool()> dbMigration;
        std::chrono::seconds estimatedDuration;
        bool requiresDowntime;
    };
    
    std::map<std::pair<std::string, std::string>, MigrationEntry> migrations_;
};

// Update verifier
class UpdateVerifier {
public:
    UpdateVerifier();
    
    // Verification
    bool verifyPatchIntegrity(const PatchPackage& package);
    bool verifyPatchSignature(const PatchPackage& package, const std::string& publicKey);
    bool verifyFileChecksum(const std::string& path, const std::string& expectedChecksum);
    
    // Pre-flight checks
    struct PreflightResult {
        bool canProceed;
        std::vector<std::string> issues;
        std::vector<std::string> warnings;
        uint64_t requiredSpace;
        uint64_t availableSpace;
    };
    PreflightResult runPreflightChecks(const PatchPackage& package) const;
    
    // Compatibility check
    bool checkCompatibility(const std::string& currentVersion,
                           const std::string& targetVersion) const;
    std::vector<std::string> getIncompatibleComponents(
        const std::string& currentVersion,
        const std::string& targetVersion) const;
};

} // namespace Maintenance
} // namespace RawrXD

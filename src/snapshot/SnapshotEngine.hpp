// snapshot/SnapshotEngine.hpp
//
// RawrXD Snapshot Engine -- transactional autonomous experimentation.
//
// Provides incremental snapshots, agent checkpoints, hotpatch rollback,
// and performance experiment tracking. No full-tree scans on startup.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include <optional>
#include <chrono>
#include <filesystem>
#include "snapshot/SnapshotConfig.hpp"
#include "snapshot/SnapshotManifest.hpp"
#include "snapshot/FileSnapshot.hpp"
#include "snapshot/SnapshotStorage.hpp"
#include "snapshot/SnapshotJournal.hpp"

namespace kartgib {

struct SnapshotConfig;

class SnapshotEngine {
public:
    // RawrXD Snapshot Engine -- transactional autonomous experimentation.
    //
    // Provides incremental snapshots, agent checkpoints, hotpatch rollback,
    // and performance experiment tracking. No full-tree scans on startup.

    SnapshotConfig config_ = SnapshotConfig{};                                     // Engine configuration
    SnapshotStorage storage_ = SnapshotStorage{};                                  // Content-addressed storage
    SnapshotJournal journal_ = SnapshotJournal{};                                  // Write-ahead journal
    std::vector<SnapshotManifest> manifests_ = {};                                 // In-memory manifest index
    std::optional<SnapshotManifest> current_transaction_ = std::nullopt;           // Active agent transaction

    bool Initialize(const SnapshotConfig& config);                                 // Initialize the snapshot engine
    void Shutdown();                                                               // Flush and shutdown
    SnapshotManifest CreateSnapshot(const std::string& name, SnapshotMode mode, const std::string& agent_id, const std::string& task_id, const std::string& description = "");  // Create a new snapshot (Lightweight mode)
    bool BeginTransaction(const std::string& name, const std::string& agent_id, const std::string& task_id);  // Begin an agent transaction (AgentTransaction mode)
    bool CaptureFile(const std::filesystem::path& path, SnapshotManifest* targetManifest = nullptr);  // Capture a file before modification (must be called before write)
    bool CaptureFiles(const std::vector<std::filesystem::path>& paths, SnapshotManifest* targetManifest = nullptr);  // Capture multiple files before modification
    SnapshotManifest CommitTransaction();                                          // Commit the current agent transaction
    bool RollbackTransaction();                                                    // Rollback the current agent transaction
    bool RestoreSnapshot(const std::string& snapshot_id, ConflictPolicy policy = ConflictPolicy::Abort);  // Restore a snapshot to the working tree
    std::string DiffSnapshot(const std::string& snapshot_id);                      // Generate a unified diff for a snapshot
    std::vector<SnapshotManifest> ListSnapshots(const std::string& agent_id = "");  // List all snapshots, optionally filtered by agent
    std::optional<SnapshotManifest> GetSnapshot(const std::string& id);            // Get a snapshot by ID
    bool DeleteSnapshot(const std::string& id);                                    // Delete a snapshot and decrement refcounts
    SnapshotManifest RunPerformanceExperiment(const std::string& name, const std::string& agent_id, const std::string& task_id, const std::string& build_command, const std::string& test_command, const std::string& benchmark_command, double acceptance_threshold);  // Run a performance experiment: snapshot, build, test, benchmark, restore on regression
    std::string GetGitState();                                                     // Get current git commit, branch, and dirty state as JSON
    bool VerifyIntegrity(const std::string& snapshot_id);                          // Verify snapshot integrity via SHA-256

private:
    std::string GenerateUUID();
    std::string GetCurrentTimeISO();
    bool IsPathExcluded(const std::filesystem::path& path);
    bool CaptureGitState(SnapshotManifest& manifest);
    bool RunCommand(const std::string& command, std::string& output, int& exit_code);
    bool ParseBenchmarkOutput(const std::string& output, double& metric_value);
    void SaveManifest(const SnapshotManifest& manifest);
    void LoadManifest(const std::filesystem::path& path);
};

} // namespace kartgib
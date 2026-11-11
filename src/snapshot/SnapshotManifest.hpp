// snapshot/SnapshotManifest.hpp
//
// A complete snapshot manifest containing multiple file snapshots.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include <chrono>
#include "snapshot/SnapshotTypes.hpp"
#include "snapshot/FileSnapshot.hpp"

namespace kartgib {

struct SnapshotManifest {
    // A complete snapshot manifest containing multiple file snapshots.

    std::string id = "";                                                      // Unique snapshot ID (UUID)
    std::string name = "";                                                    // Human-readable name
    std::string description = "";                                             // Optional description
    SnapshotMode mode = SnapshotMode::Lightweight;                            // Snapshot mode
    SnapshotStatus status = SnapshotStatus::Pending;                          // Current status
    std::chrono::system_clock::time_point created_time = std::chrono::system_clock::now();  // When the snapshot was created
    std::chrono::system_clock::time_point committed_time = std::chrono::system_clock::time_point{};  // When the snapshot was committed
    std::string git_commit = "";                                              // Git commit hash at snapshot time
    std::string git_branch = "";                                              // Git branch at snapshot time
    bool git_dirty = false;                                                   // Whether the working tree was dirty
    std::string agent_id = "";                                                // Agent that created the snapshot
    std::string task_id = "";                                                 // Task/operation ID
    std::vector<FileSnapshot> files = {};                                     // Files captured in this snapshot
    std::string parent_snapshot_id = "";                                      // Parent snapshot for undo/redo chain
    std::string benchmark_data = "";                                          // JSON benchmark results for performance experiments
};

} // namespace kartgib
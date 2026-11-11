// snapshot/SnapshotTypes.hpp
//
// Core type definitions for the snapshot engine.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <cstdint>

namespace kartgib {

enum class SnapshotMode : uint32_t {
    Lightweight = 0,           // File-level before/after snapshots, no repository crawl
    AgentTransaction = 1,      // Groups multiple edits into one reversible operation
    PerformanceExperiment = 2, // Checkpoint source, apply optimization, rebuild, measure, restore on failure
};

enum class SnapshotStatus : uint32_t {
    Pending = 0,     // Snapshot created, not yet committed
    Committed = 1,   // Snapshot committed and verified
    RolledBack = 2,  // Snapshot was rolled back
    Failed = 3,      // Snapshot creation or verification failed
};

enum class ConflictPolicy : uint32_t {
    Abort = 0,  // Abort the operation on conflict
    Force = 1,  // Force overwrite, discarding concurrent changes
    Merge = 2,  // Attempt three-way merge
};

} // namespace kartgib
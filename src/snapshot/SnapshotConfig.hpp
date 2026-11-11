// snapshot/SnapshotConfig.hpp
//
// Configuration for the snapshot engine.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

namespace kartgib {

struct SnapshotConfig {
    // Configuration for the snapshot engine.

    std::filesystem::path repository_root = std::filesystem::path{};  // Root of the repository to snapshot
    std::filesystem::path storage_path = std::filesystem::path{};     // Where snapshots are stored (default: .rawrxd/snapshots)
    uint64_t max_storage_gb = 10;                                     // Maximum storage quota in gigabytes
    uint32_t max_snapshots = 1000;                                    // Maximum number of snapshots to retain
    uint32_t retention_days = 30;                                     // Days to retain snapshots before garbage collection
    std::vector<std::string> excluded_patterns = {"*.gguf", "*.bin", "*.safetensors", ".git/**", "build/**", "out/**", "*.obj", "*.exe", "*.dll", "*.pdb", "*.ilk"};  // Glob patterns to exclude from snapshots
    bool include_untracked = true;                                    // Preserve untracked source files
    bool verify_checksums = true;                                     // Verify SHA-256 on restore
    bool atomic_writes = true;                                        // Use atomic file replacement
    bool journal_enabled = true;                                      // Enable write-ahead journal for crash recovery
};

} // namespace kartgib
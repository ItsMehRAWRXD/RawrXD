// snapshot/FileSnapshot.hpp
//
// A single file's snapshot record.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <string>
#include <cstdint>
#include <array>
#include <chrono>
#include "snapshot/SnapshotTypes.hpp"

namespace kartgib {

struct FileSnapshot {
    // A single file's snapshot record.

    std::string path = "";                                              // Repository-relative path
    std::array<uint8_t, 32> sha256_before = {};                         // Content hash before modification
    std::array<uint8_t, 32> sha256_after = {};                          // Content hash after modification
    uint64_t size_before = 0;                                           // File size before modification
    uint64_t size_after = 0;                                            // File size after modification
    std::chrono::system_clock::time_point modified_time = std::chrono::system_clock::now();  // When the snapshot was taken
    std::string agent_id = "";                                          // ID of the agent that created this snapshot
    std::string task_id = "";                                           // ID of the task/operation
};

} // namespace kartgib
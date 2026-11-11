// snapshot/JournalEntry.hpp
//
// A write-ahead journal entry for crash recovery.
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

struct JournalEntry {
    // A write-ahead journal entry for crash recovery.

    std::string id = "";                                                    // Unique entry ID
    std::string snapshot_id = "";                                           // Associated snapshot ID
    std::string operation = "";                                             // Operation type: create, modify, delete, commit, rollback
    std::string file_path = "";                                             // Affected file path
    std::array<uint8_t, 32> sha256_before = {};                             // Hash before operation
    std::array<uint8_t, 32> sha256_after = {};                              // Hash after operation
    std::chrono::system_clock::time_point timestamp = std::chrono::system_clock::now();  // When the entry was written
    bool completed = false;                                                 // Whether the operation completed
};

} // namespace kartgib
// snapshot/SnapshotJournal.hpp
//
// Write-ahead journal for crash recovery.
//
// Every snapshot operation is journaled before execution. On startup,
// the journal is replayed to recover incomplete operations.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include "snapshot/SnapshotConfig.hpp"
#include "snapshot/JournalEntry.hpp"
#include "snapshot/SnapshotManifest.hpp"

namespace kartgib {

struct SnapshotConfig;
struct JournalEntry;
class SnapshotStorage;
struct SnapshotManifest;

class SnapshotJournal {
public:
    // Write-ahead journal for crash recovery.
    //
    // Every snapshot operation is journaled before execution. On startup,
    // the journal is replayed to recover incomplete operations.

    bool Initialize(const SnapshotConfig& config);                                                    // Initialize journal at configured path
    bool Write(const JournalEntry& entry);                                                            // Append a journal entry (fsync'd)
    bool MarkComplete(const std::string& entry_id);                                                 // Mark a journal entry as completed
    std::vector<JournalEntry> GetPending();                                                           // Get all incomplete journal entries
    bool Recover(SnapshotStorage& storage, std::vector<SnapshotManifest>& manifests);                 // Recover from journal: replay or rollback incomplete ops
    void Truncate(std::chrono::system_clock::time_point before_time);                                 // Remove completed entries before a timestamp

private:
    std::filesystem::path journal_path_;
    std::filesystem::path journal_file_;
    std::ofstream journal_stream_;
    std::mutex journal_mutex_;

    void EnsureJournalFile();
    std::string SerializeEntry(const JournalEntry& entry);
    bool DeserializeEntry(const std::string& line, JournalEntry& entry);
};

} // namespace kartgib
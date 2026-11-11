// snapshot/SnapshotJournal.cpp
//
// Write-ahead journal for crash recovery.
//
// Every snapshot operation is journaled before execution. On startup,
// the journal is replayed to recover incomplete operations.

#include "snapshot/SnapshotJournal.hpp"
#include "snapshot/SnapshotStorage.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <mutex>
#include <windows.h>

namespace kartgib {

bool SnapshotJournal::Initialize(const SnapshotConfig& config) {
    journal_path_ = config.storage_path.empty() ? (config.repository_root / ".rawrxd" / "snapshots") : config.storage_path;
    journal_file_ = journal_path_ / "journal.log";

    std::error_code ec;
    std::filesystem::create_directories(journal_path_, ec);

    journal_stream_.open(journal_file_, std::ios::app | std::ios::out);
    return journal_stream_.is_open();
}

void SnapshotJournal::EnsureJournalFile() {
    if (!journal_stream_.is_open()) {
        journal_stream_.open(journal_file_, std::ios::app | std::ios::out);
    }
}

bool SnapshotJournal::Write(const JournalEntry& entry) {
    std::lock_guard<std::mutex> lock(journal_mutex_);
    EnsureJournalFile();

    std::string line = SerializeEntry(entry);
    journal_stream_ << line << '\n';
    journal_stream_.flush();

    // Force to disk on Windows using native handle
    #ifdef _WIN32
    HANDLE hFile = CreateFileA(journal_file_.string().c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
    }
    #else
    fsync(fileno(journal_stream_));
    #endif

    return journal_stream_.good();
}

std::string SnapshotJournal::SerializeEntry(const JournalEntry& entry) {
    std::ostringstream oss;

    auto time_t = std::chrono::system_clock::to_time_t(entry.timestamp);
    std::stringstream timeStr;
    timeStr << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");

    auto sha256ToHex = [](const std::array<uint8_t, 32>& arr) -> std::string {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (uint8_t b : arr) {
            hex << std::setw(2) << static_cast<int>(b);
        }
        return hex.str();
    };

    oss << entry.id << '|'
        << entry.snapshot_id << '|'
        << entry.operation << '|'
        << entry.file_path << '|'
        << sha256ToHex(entry.sha256_before) << '|'
        << sha256ToHex(entry.sha256_after) << '|'
        << timeStr.str() << '|'
        << (entry.completed ? "1" : "0");

    return oss.str();
}

bool SnapshotJournal::DeserializeEntry(const std::string& line, JournalEntry& entry) {
    if (line.empty()) return false;

    std::vector<std::string> parts;
    std::string part;
    std::istringstream iss(line);
    while (std::getline(iss, part, '|')) {
        parts.push_back(part);
    }

    if (parts.size() != 8) return false;

    entry.id = parts[0];
    entry.snapshot_id = parts[1];
    entry.operation = parts[2];
    entry.file_path = parts[3];

    auto hexToSha256 = [](const std::string& hex, std::array<uint8_t, 32>& arr) -> bool {
        if (hex.size() != 64) return false;
        for (size_t i = 0; i < 32; ++i) {
            std::string byteStr = hex.substr(i * 2, 2);
            arr[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }
        return true;
    };

    if (!hexToSha256(parts[4], entry.sha256_before)) return false;
    if (!hexToSha256(parts[5], entry.sha256_after)) return false;

    // Parse timestamp
    std::tm tm = {};
    std::istringstream timeIn(parts[6]);
    timeIn >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (timeIn.fail()) return false;
    entry.timestamp = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    entry.completed = (parts[7] == "1");
    return true;
}

bool SnapshotJournal::MarkComplete(const std::string& entry_id) {
    std::lock_guard<std::mutex> lock(journal_mutex_);

    // Read all entries
    std::vector<std::string> lines;
    std::ifstream in(journal_file_);
    std::string line;
    while (std::getline(in, line)) {
        lines.push_back(line);
    }
    in.close();

    // Rewrite with updated entry
    std::filesystem::path tmpPath = journal_file_;
    tmpPath += ".tmp";
    std::ofstream out(tmpPath);
    if (!out) return false;

    bool found = false;
    for (const auto& l : lines) {
        JournalEntry entry;
        if (DeserializeEntry(l, entry) && entry.id == entry_id) {
            entry.completed = true;
            out << SerializeEntry(entry) << '\n';
            found = true;
        } else {
            out << l << '\n';
        }
    }
    out.close();

    if (!found) {
        std::error_code ec;
        std::filesystem::remove(tmpPath, ec);
        return false;
    }

    std::error_code ec;
    std::filesystem::rename(tmpPath, journal_file_, ec);
    if (ec) return false;

    // Reopen stream
    journal_stream_.close();
    journal_stream_.open(journal_file_, std::ios::app | std::ios::out);
    return true;
}

std::vector<JournalEntry> SnapshotJournal::GetPending() {
    std::lock_guard<std::mutex> lock(journal_mutex_);
    std::vector<JournalEntry> pending;

    std::ifstream in(journal_file_);
    std::string line;
    while (std::getline(in, line)) {
        JournalEntry entry;
        if (DeserializeEntry(line, entry) && !entry.completed) {
            pending.push_back(entry);
        }
    }

    return pending;
}

bool SnapshotJournal::Recover(SnapshotStorage& storage, std::vector<SnapshotManifest>& manifests) {
    std::vector<JournalEntry> pending;
    {
        std::lock_guard<std::mutex> lock(journal_mutex_);
        std::ifstream in(journal_file_);
        std::string line;
        while (std::getline(in, line)) {
            JournalEntry entry;
            if (DeserializeEntry(line, entry) && !entry.completed) {
                pending.push_back(entry);
            }
        }
    }

    // For each incomplete entry, determine if we should rollback or complete
    for (const auto& entry : pending) {
        if (entry.operation == "create" || entry.operation == "modify" || entry.operation == "capture") {
            // Check if the after-state exists in storage
            std::string sha256_after_hex;
            {
                std::ostringstream hex;
                hex << std::hex << std::setfill('0');
                for (uint8_t b : entry.sha256_after) {
                    hex << std::setw(2) << static_cast<int>(b);
                }
                sha256_after_hex = hex.str();
            }

            if (storage.Exists(sha256_after_hex)) {
                // Operation completed but not marked - mark it complete
                MarkComplete(entry.id);
            } else {
                // Operation didn't complete - restore before state
                std::string sha256_before_hex;
                {
                    std::ostringstream hex;
                    hex << std::hex << std::setfill('0');
                    for (uint8_t b : entry.sha256_before) {
                        hex << std::setw(2) << static_cast<int>(b);
                    }
                    sha256_before_hex = hex.str();
                }

                if (storage.Exists(sha256_before_hex)) {
                    std::filesystem::path dest = entry.file_path;
                    storage.RetrieveToFile(sha256_before_hex, dest);
                }
                MarkComplete(entry.id);
            }
        } else if (entry.operation == "delete") {
            // Delete operation - restore the file
            std::string sha256_before_hex;
            {
                std::ostringstream hex;
                hex << std::hex << std::setfill('0');
                for (uint8_t b : entry.sha256_before) {
                    hex << std::setw(2) << static_cast<int>(b);
                }
                sha256_before_hex = hex.str();
            }

            if (storage.Exists(sha256_before_hex)) {
                std::filesystem::path dest = entry.file_path;
                storage.RetrieveToFile(sha256_before_hex, dest);
            }
            MarkComplete(entry.id);
        } else if (entry.operation == "commit" || entry.operation == "rollback") {
            // Transaction-level operations - mark complete
            MarkComplete(entry.id);
        }
    }

    return true;
}

void SnapshotJournal::Truncate(std::chrono::system_clock::time_point before_time) {
    std::lock_guard<std::mutex> lock(journal_mutex_);

    std::vector<std::string> lines;
    std::ifstream in(journal_file_);
    std::string line;
    while (std::getline(in, line)) {
        JournalEntry entry;
        if (DeserializeEntry(line, entry) && entry.completed && entry.timestamp >= before_time) {
            lines.push_back(line);
        }
    }
    in.close();

    std::filesystem::path tmpPath = journal_file_;
    tmpPath += ".tmp";
    std::ofstream out(tmpPath);
    for (const auto& l : lines) {
        out << l << '\n';
    }
    out.close();

    std::error_code ec;
    std::filesystem::rename(tmpPath, journal_file_, ec);
    if (!ec) {
        journal_stream_.close();
        journal_stream_.open(journal_file_, std::ios::app | std::ios::out);
    }
}

} // namespace kartgib
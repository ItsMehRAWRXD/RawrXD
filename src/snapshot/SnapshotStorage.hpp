// snapshot/SnapshotStorage.hpp
//
// Content-addressed storage with deduplication, quotas, and garbage collection.
//
// Uses SHA-256 for content addressing. Identical file contents across
// snapshots are stored once. Implements LRU eviction with configurable
// quotas and retention policies.
//
// GENERATED SCAFFOLD. The structure is real; the bodies marked
// TODO(impl) are not. See tools/scaffold.py --status.

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>
#include <unordered_map>
#include "snapshot/SnapshotConfig.hpp"
#include "snapshot/SnapshotManifest.hpp"
#include "snapshot/FileSnapshot.hpp"

namespace kartgib {

struct SnapshotConfig;

class SnapshotStorage {
public:
    // Content-addressed storage with deduplication, quotas, and garbage collection.
    //
    // Uses SHA-256 for content addressing. Identical file contents across
    // snapshots are stored once. Implements LRU eviction with configurable
    // quotas and retention policies.

    bool Initialize(const SnapshotConfig& config);                                     // Initialize storage at configured path
    std::string Store(const std::vector<uint8_t>& data);                               // Store data content-addressed; returns SHA-256 hex
    std::string StoreFile(const std::filesystem::path& path);                          // Store a file content-addressed; returns SHA-256 hex
    bool Retrieve(const std::string& sha256, std::vector<uint8_t>& out);               // Retrieve data by SHA-256 hex
    bool RetrieveToFile(const std::string& sha256, const std::filesystem::path& destination);  // Retrieve data to a file path
    bool Exists(const std::string& sha256);                                            // Check if content exists in storage
    uint64_t GetSize(const std::string& sha256);                                       // Get stored content size
    uint32_t GetRefCount(const std::string& sha256);                                   // Get reference count for deduplicated content
    void IncRef(const std::string& sha256);                                            // Increment reference count
    void DecRef(const std::string& sha256);                                            // Decrement reference count; may trigger GC
    uint64_t GarbageCollect();                                                         // Run garbage collection; returns bytes freed
    bool EnforceQuota();                                                               // Enforce storage quota via LRU eviction
    std::string GetStats();                                                            // Get storage statistics as JSON

private:
    std::filesystem::path storage_root_;
    std::filesystem::path objects_dir_;
    std::filesystem::path refs_dir_;
    uint64_t max_storage_bytes_ = 0;
    uint32_t max_snapshots_ = 0;
    uint32_t retention_days_ = 0;

    struct ObjectInfo {
        uint64_t size = 0;
        uint32_t ref_count = 0;
        std::chrono::system_clock::time_point last_access;
    };
    std::unordered_map<std::string, ObjectInfo> object_index_;

    void LoadIndex();
    void SaveIndex();
    std::string ComputeSHA256(const std::vector<uint8_t>& data);
    std::string ComputeSHA256File(const std::filesystem::path& path);
    bool WriteFileAtomic(const std::filesystem::path& path, const std::vector<uint8_t>& data);
    bool WriteFileAtomic(const std::filesystem::path& path, const std::string& data);
};

} // namespace kartgib
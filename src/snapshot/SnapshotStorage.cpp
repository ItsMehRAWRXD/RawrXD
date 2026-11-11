// snapshot/SnapshotStorage.cpp
//
// Content-addressed storage with deduplication, quotas, and garbage collection.
//
// Uses SHA-256 for content addressing. Identical file contents across
// snapshots are stored once. Implements LRU eviction with configurable
// quotas and retention policies.

#include "snapshot/SnapshotStorage.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <mutex>
#include <windows.h>
#include <wincrypt.h>

namespace kartgib {

bool SnapshotStorage::Initialize(const SnapshotConfig& config) {
    storage_root_ = config.storage_path.empty() ? (config.repository_root / ".rawrxd" / "snapshots") : config.storage_path;
    objects_dir_ = storage_root_ / "objects";
    refs_dir_ = storage_root_ / "refs";

    max_storage_bytes_ = config.max_storage_gb * 1024ULL * 1024ULL * 1024ULL;
    max_snapshots_ = config.max_snapshots;
    retention_days_ = config.retention_days;

    std::error_code ec;
    std::filesystem::create_directories(objects_dir_, ec);
    std::filesystem::create_directories(refs_dir_, ec);

    LoadIndex();
    return true;
}

std::string SnapshotStorage::ComputeSHA256(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, data.data(), static_cast<DWORD>(data.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashLen = 32;
    std::vector<BYTE> hash(hashLen);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < hashLen; ++i) {
            oss << std::setw(2) << static_cast<int>(hash[i]);
        }
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::string SnapshotStorage::ComputeSHA256File(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";

    std::vector<uint8_t> buffer(64 * 1024);
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContext(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (!CryptHashData(hHash, buffer.data(), static_cast<DWORD>(bytesRead), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }
    }

    DWORD hashLen = 32;
    std::vector<BYTE> hash(hashLen);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (DWORD i = 0; i < hashLen; ++i) {
            oss << std::setw(2) << static_cast<int>(hash[i]);
        }
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

std::string SnapshotStorage::Store(const std::vector<uint8_t>& data) {
    std::string sha256 = ComputeSHA256(data);
    if (sha256.empty()) return "";

    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    std::error_code ec;
    std::filesystem::create_directories(objPath.parent_path(), ec);

    if (!std::filesystem::exists(objPath)) {
        WriteFileAtomic(objPath, data);
    }

    auto& info = object_index_[sha256];
    info.size = data.size();
    info.last_access = std::chrono::system_clock::now();
    if (info.ref_count == 0) info.ref_count = 1;

    SaveIndex();
    return sha256;
}

std::string SnapshotStorage::StoreFile(const std::filesystem::path& path) {
    std::string sha256 = ComputeSHA256File(path);
    if (sha256.empty()) return "";

    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    std::error_code ec;
    std::filesystem::create_directories(objPath.parent_path(), ec);

    if (!std::filesystem::exists(objPath)) {
        std::ifstream file(path, std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        WriteFileAtomic(objPath, data);
    }

    auto& info = object_index_[sha256];
    info.size = std::filesystem::file_size(path);
    info.last_access = std::chrono::system_clock::now();
    if (info.ref_count == 0) info.ref_count = 1;

    SaveIndex();
    return sha256;
}

bool SnapshotStorage::WriteFileAtomic(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
    std::filesystem::path tmpPath = path;
    tmpPath += ".tmp." + std::to_string(GetCurrentProcessId()) + "." + std::to_string(rand());

    std::ofstream out(tmpPath, std::ios::binary);
    if (!out) return false;
    out.write(reinterpret_cast<const char*>(data.data()), data.size());
    out.flush();
    out.close();

    std::error_code ec;
    std::filesystem::rename(tmpPath, path, ec);
    return !ec;
}

bool SnapshotStorage::WriteFileAtomic(const std::filesystem::path& path, const std::string& data) {
    std::filesystem::path tmpPath = path;
    tmpPath += ".tmp." + std::to_string(GetCurrentProcessId()) + "." + std::to_string(rand());

    std::ofstream out(tmpPath);
    if (!out) return false;
    out << data;
    out.flush();
    out.close();

    std::error_code ec;
    std::filesystem::rename(tmpPath, path, ec);
    return !ec;
}

bool SnapshotStorage::Retrieve(const std::string& sha256, std::vector<uint8_t>& out) {
    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    if (!std::filesystem::exists(objPath)) return false;

    std::ifstream file(objPath, std::ios::binary);
    if (!file) return false;

    out.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto it = object_index_.find(sha256);
    if (it != object_index_.end()) {
        it->second.last_access = std::chrono::system_clock::now();
    }

    return true;
}

bool SnapshotStorage::RetrieveToFile(const std::string& sha256, const std::filesystem::path& destination) {
    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    if (!std::filesystem::exists(objPath)) return false;

    std::error_code ec;
    std::filesystem::copy_file(objPath, destination, std::filesystem::copy_options::overwrite_existing, ec);
    return !ec;
}

bool SnapshotStorage::Exists(const std::string& sha256) {
    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    return std::filesystem::exists(objPath);
}

uint64_t SnapshotStorage::GetSize(const std::string& sha256) {
    auto it = object_index_.find(sha256);
    if (it != object_index_.end()) return it->second.size;

    std::filesystem::path objPath = objects_dir_ / sha256.substr(0, 2) / sha256.substr(2);
    if (std::filesystem::exists(objPath)) {
        return std::filesystem::file_size(objPath);
    }
    return 0;
}

uint32_t SnapshotStorage::GetRefCount(const std::string& sha256) {
    auto it = object_index_.find(sha256);
    if (it != object_index_.end()) return it->second.ref_count;
    return 0;
}

void SnapshotStorage::IncRef(const std::string& sha256) {
    auto it = object_index_.find(sha256);
    if (it != object_index_.end()) {
        it->second.ref_count++;
        it->second.last_access = std::chrono::system_clock::now();
    }
}

void SnapshotStorage::DecRef(const std::string& sha256) {
    auto it = object_index_.find(sha256);
    if (it != object_index_.end() && it->second.ref_count > 0) {
        it->second.ref_count--;
    }
}

void SnapshotStorage::LoadIndex() {
    std::filesystem::path indexPath = storage_root_ / "index.json";
    if (!std::filesystem::exists(indexPath)) return;

    std::ifstream file(indexPath);
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Simple JSON parsing for the index
    size_t pos = content.find('{');
    while (pos != std::string::npos && pos < content.size()) {
        size_t endPos = content.find('}', pos);
        if (endPos == std::string::npos) break;

        std::string obj = content.substr(pos, endPos - pos + 1);
        size_t hashStart = obj.find('"');
        if (hashStart != std::string::npos) {
            size_t hashEnd = obj.find('"', hashStart + 1);
            if (hashEnd != std::string::npos) {
                std::string hash = obj.substr(hashStart + 1, hashEnd - hashStart - 1);
                if (hash.size() == 64) {
                    ObjectInfo info;
                    size_t sizePos = obj.find("\"size\":");
                    if (sizePos != std::string::npos) {
                        size_t sizeEnd = obj.find(',', sizePos);
                        std::string sizeStr = obj.substr(sizePos + 7, sizeEnd - sizePos - 7);
                        info.size = std::stoull(sizeStr);
                    }
                    size_t refPos = obj.find("\"ref_count\":");
                    if (refPos != std::string::npos) {
                        size_t refEnd = obj.find(',', refPos);
                        std::string refStr = obj.substr(refPos + 12, refEnd - refPos - 12);
                        info.ref_count = static_cast<uint32_t>(std::stoul(refStr));
                    }
                    size_t accessPos = obj.find("\"last_access\":\"");
                    if (accessPos != std::string::npos) {
                        size_t accessEnd = obj.find('"', accessPos + 15);
                        info.last_access = std::chrono::system_clock::now();
                    }
                    object_index_[hash] = info;
                }
            }
        }
        pos = content.find('{', endPos + 1);
    }
}

void SnapshotStorage::SaveIndex() {
    std::filesystem::path indexPath = storage_root_ / "index.json";
    std::filesystem::path tmpPath = indexPath;
    tmpPath += ".tmp";

    std::ofstream out(tmpPath);
    if (!out) return;

    out << "{\n";
    bool first = true;
    for (const auto& [hash, info] : object_index_) {
        if (!first) out << ",\n";
        first = false;

        auto time_t = std::chrono::system_clock::to_time_t(info.last_access);
        std::stringstream timeStr;
        timeStr << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");

        out << "  \"" << hash << "\": {\n";
        out << "    \"size\": " << info.size << ",\n";
        out << "    \"ref_count\": " << info.ref_count << ",\n";
        out << "    \"last_access\": \"" << timeStr.str() << "\"\n";
        out << "  }";
    }
    out << "\n}\n";
    out.close();

    std::error_code ec;
    std::filesystem::rename(tmpPath, indexPath, ec);
}

uint64_t SnapshotStorage::GarbageCollect() {
    uint64_t freed = 0;
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(24 * retention_days_);

    std::vector<std::string> toRemove;
    for (const auto& [hash, info] : object_index_) {
        if (info.ref_count == 0 && info.last_access < cutoff) {
            toRemove.push_back(hash);
        }
    }

    for (const auto& hash : toRemove) {
        std::filesystem::path objPath = objects_dir_ / hash.substr(0, 2) / hash.substr(2);
        if (std::filesystem::exists(objPath)) {
            freed += object_index_[hash].size;
            std::error_code ec;
            std::filesystem::remove(objPath, ec);
        }
        object_index_.erase(hash);
    }

    // Clean up empty directories
    for (const auto& dir : std::filesystem::directory_iterator(objects_dir_)) {
        if (std::filesystem::is_directory(dir) && std::filesystem::is_empty(dir)) {
            std::error_code ec;
            std::filesystem::remove(dir, ec);
        }
    }

    SaveIndex();
    return freed;
}

bool SnapshotStorage::EnforceQuota() {
    uint64_t totalSize = 0;
    for (const auto& [hash, info] : object_index_) {
        if (info.ref_count > 0) {
            totalSize += info.size;
        }
    }

    if (totalSize <= max_storage_bytes_) return true;

    // LRU eviction: sort by last_access, remove oldest unreferenced first
    std::vector<std::pair<std::string, ObjectInfo>> candidates;
    for (const auto& [hash, info] : object_index_) {
        if (info.ref_count == 0) {
            candidates.emplace_back(hash, info);
        }
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const auto& a, const auto& b) {
            return a.second.last_access < b.second.last_access;
        });

    uint64_t freed = 0;
    for (const auto& [hash, info] : candidates) {
        if (totalSize - freed <= max_storage_bytes_) break;

        std::filesystem::path objPath = objects_dir_ / hash.substr(0, 2) / hash.substr(2);
        if (std::filesystem::exists(objPath)) {
            freed += info.size;
            std::error_code ec;
            std::filesystem::remove(objPath, ec);
        }
        object_index_.erase(hash);
    }

    SaveIndex();
    return (totalSize - freed) <= max_storage_bytes_;
}

std::string SnapshotStorage::GetStats() {
    uint64_t totalObjects = object_index_.size();
    uint64_t totalSize = 0;
    uint64_t referencedObjects = 0;
    uint64_t referencedSize = 0;

    for (const auto& [hash, info] : object_index_) {
        totalSize += info.size;
        if (info.ref_count > 0) {
            referencedObjects++;
            referencedSize += info.size;
        }
    }

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"total_objects\": " << totalObjects << ",\n";
    oss << "  \"total_size_bytes\": " << totalSize << ",\n";
    oss << "  \"referenced_objects\": " << referencedObjects << ",\n";
    oss << "  \"referenced_size_bytes\": " << referencedSize << ",\n";
    oss << "  \"deduplication_ratio\": " << (totalObjects > 0 ? (double)referencedObjects / totalObjects : 0.0) << ",\n";
    oss << "  \"max_storage_gb\": " << (max_storage_bytes_ / (1024ULL * 1024ULL * 1024ULL)) << ",\n";
    oss << "  \"storage_root\": \"" << storage_root_.string() << "\"\n";
    oss << "}";
    return oss.str();
}

} // namespace kartgib
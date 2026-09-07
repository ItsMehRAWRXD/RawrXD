// vwa/VwaPhysical.hpp — pluggable physical read (memory or file)
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace vwa {

struct IPhysicalBackend {
    virtual ~IPhysicalBackend() = default;
    virtual bool Read(uint32_t shard, uint64_t off, uint64_t n, void* dst) = 0;
};

// In-process shard image — cert / no-disk path ("regardless physical read").
class MemoryBackend final : public IPhysicalBackend {
public:
    void MapShard(uint32_t shard, const void* data, uint64_t size) {
        shards_[shard] = {static_cast<const uint8_t*>(data), size};
    }
    void OwnShard(uint32_t shard, std::vector<uint8_t> bytes) {
        owned_[shard] = std::move(bytes);
        auto& v = owned_[shard];
        shards_[shard] = {v.data(), v.size()};
    }
    bool Read(uint32_t shard, uint64_t off, uint64_t n, void* dst) override {
        auto it = shards_.find(shard);
        if (it == shards_.end()) return false;
        if (off > it->second.size || n > it->second.size - off) return false;
        std::memcpy(dst, it->second.data + off, static_cast<size_t>(n));
        return true;
    }
private:
    struct View { const uint8_t* data; uint64_t size; };
    std::unordered_map<uint32_t, View> shards_;
    std::unordered_map<uint32_t, std::vector<uint8_t>> owned_;
};

class FileBackend final : public IPhysicalBackend {
public:
    bool OpenShard(uint32_t shard, const char* path) {
#ifdef _WIN32
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        files_[shard] = h;
        return true;
#else
        (void)shard; (void)path; return false;
#endif
    }
    ~FileBackend() override {
#ifdef _WIN32
        for (auto& kv : files_) CloseHandle(kv.second);
#endif
    }
    bool Read(uint32_t shard, uint64_t off, uint64_t n, void* dst) override {
#ifdef _WIN32
        auto it = files_.find(shard);
        if (it == files_.end()) return false;
        OVERLAPPED ov{};
        ov.Offset = static_cast<DWORD>(off);
        ov.OffsetHigh = static_cast<DWORD>(off >> 32);
        DWORD got = 0;
        if (!ReadFile(it->second, dst, static_cast<DWORD>(n), &got, &ov))
            return false;
        return got == n;
#else
        (void)shard; (void)off; (void)n; (void)dst; return false;
#endif
    }
private:
#ifdef _WIN32
    std::unordered_map<uint32_t, HANDLE> files_;
#endif
};

} // namespace vwa
} // namespace Deep2

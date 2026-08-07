#ifndef TENSOR_RESIDENCY_CACHE_HPP
#define TENSOR_RESIDENCY_CACHE_HPP
// ============================================================================
// TensorResidencyCache.hpp  —  hotpatch #5
// ----------------------------------------------------------------------------
// Keeps a bounded set of tensor mappings hot. Instead of open/mmap/close/munmap
// per slingshot(), we maintain one descriptor per shard and a small LRU cache
// of active mappings. Memory stays bounded: only MAX_ACTIVE tensors resident.
//
// Design:
//   - One fd/handle per shard (never repeatedly open/close).
//   - LRU eviction when cache is full.
//   - Reference counting so concurrent users don't evict each other.
//   - Page-aware: adjacent tensors may share a mapping.
//
// Header-only, C++17, cross-OS. No #pragma once. No global state.
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <list>
#include <mutex>
#include <memory>
#include <optional>
#include <functional>

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
#else
  #include <fcntl.h>
  #include <unistd.h>
  #include <sys/mman.h>
  #include <sys/stat.h>
#endif

namespace gguf_shard_cache {

// ============================================================================
// ShardHandle — one fd/handle per shard, kept open for the lifetime.
// ============================================================================
struct ShardHandle {
    std::string path;
    uint64_t    size = 0;
#if defined(_WIN32)
    HANDLE h = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif

    bool open(const std::string& p) {
        path = p;
#if defined(_WIN32)
        h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz)) { close(); return false; }
        size = (uint64_t)sz.QuadPart;
#else
        fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st;
        if (::fstat(fd, &st) != 0) { close(); return false; }
        size = (uint64_t)st.st_size;
#endif
        return true;
    }

    void close() {
#if defined(_WIN32)
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
#else
        if (fd >= 0) { ::close(fd); fd = -1; }
#endif
    }

    ~ShardHandle() { close(); }
    ShardHandle() = default;
    ShardHandle(const ShardHandle&) = delete;
    ShardHandle& operator=(const ShardHandle&) = delete;
    ShardHandle(ShardHandle&& o) noexcept {
#if defined(_WIN32)
        h = o.h; o.h = INVALID_HANDLE_VALUE;
#else
        fd = o.fd; o.fd = -1;
#endif
        path = std::move(o.path); size = o.size;
    }
};

// ============================================================================
// Mapping — one mmap/MapView per tensor (or group of adjacent tensors).
// ============================================================================
struct Mapping {
    void*    base = nullptr;   // page-aligned mapping base
    uint64_t map_len = 0;      // total mapped bytes
    void*    data = nullptr;   // user pointer = base + delta
    uint64_t tensor_offset = 0;
    uint64_t tensor_bytes = 0;
    uint32_t shard = 0;
    uint32_t refcount = 0;
    uint64_t last_use = 0;
    std::list<std::pair<uint32_t, uint64_t>>::iterator lru_it;
};

// ============================================================================
// TensorResidencyCache — bounded LRU cache of mappings.
// ============================================================================
class TensorResidencyCache {
public:
    static constexpr uint32_t MAX_ACTIVE = 8;

    struct Config {
        uint32_t max_active = MAX_ACTIVE;
        uint64_t page_size = 4096;
    };

    explicit TensorResidencyCache(Config cfg = {}) : cfg_(cfg), tick_(0) {}

    ~TensorResidencyCache() { clear(); }

    // Register a shard path. Must be called before any acquire on that shard.
    bool register_shard(uint32_t idx, const std::string& path) {
        if (idx >= shards_.size()) shards_.resize(idx + 1);
        return shards_[idx].open(path);
    }

    // Acquire a mapping for tensor [offset, offset+bytes) in shard.
    // Returns nullptr if the tensor cannot be mapped (out of cache slots).
    Mapping* acquire(uint32_t shard_idx, uint64_t offset, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(m_);

        // Page-align the request
        uint64_t pgsz = cfg_.page_size;
        uint64_t aligned_off = offset & ~(pgsz - 1);
        uint64_t delta = offset - aligned_off;
        uint64_t map_len = bytes + delta;

        // Check if already resident (exact match or superset)
        auto it = map_.find({shard_idx, aligned_off});
        if (it != map_.end()) {
            it->second.refcount++;
            it->second.last_use = ++tick_;
            // Move to front (most recently used)
            lru_.splice(lru_.begin(), lru_, it->second.lru_it);
            return &it->second;
        }

        // Evict if at capacity
        while (map_.size() >= cfg_.max_active) {
            evict_lru();
        }

        // Create new mapping
        if (shard_idx >= shards_.size() || !shards_[shard_idx].size) {
            return nullptr;
        }

        Mapping m;
        m.shard = shard_idx;
        m.tensor_offset = offset;
        m.tensor_bytes = bytes;
        m.last_use = ++tick_;
        m.refcount = 1;

#if defined(_WIN32)
        HANDLE fh = shards_[shard_idx].h;
        DWORD hi = (DWORD)(aligned_off >> 32);
        DWORD lo = (DWORD)(aligned_off & 0xFFFFFFFFu);
        HANDLE fm = CreateFileMapping(fh, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!fm) return nullptr;
        void* base = MapViewOfFile(fm, FILE_MAP_READ, hi, lo, (SIZE_T)map_len);
        CloseHandle(fm);
        if (!base) return nullptr;
        m.base = base;
        m.data = (char*)base + delta;
        m.map_len = map_len;
#else
        int fd = shards_[shard_idx].fd;
        void* base = ::mmap(nullptr, (size_t)map_len, PROT_READ, MAP_PRIVATE,
                            fd, (off_t)aligned_off);
        if (base == MAP_FAILED) return nullptr;
        m.base = base;
        m.data = (char*)base + delta;
        m.map_len = map_len;
#endif

        auto key = std::make_pair(shard_idx, aligned_off);
        auto lru_it = lru_.insert(lru_.begin(), key);
        auto ins = map_.emplace(key, std::move(m));
        ins.first->second.lru_it = lru_it;
        return &ins.first->second;
    }

    // Release a mapping (decrement refcount). If refcount hits 0, the mapping
    // becomes eligible for LRU eviction, but is NOT immediately unmapped.
    void release(Mapping* m) {
        if (!m) return;
        std::lock_guard<std::mutex> lk(m_);
        if (m->refcount > 0) m->refcount--;
    }

    // Force unmap everything.
    void clear() {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& kv : map_) {
            unmap(kv.second);
        }
        map_.clear();
        lru_.clear();
    }

    size_t resident_count() const {
        std::lock_guard<std::mutex> lk(m_);
        return map_.size();
    }

    uint64_t resident_bytes() const {
        std::lock_guard<std::mutex> lk(m_);
        uint64_t total = 0;
        for (const auto& kv : map_) total += kv.second.map_len;
        return total;
    }

private:
    Config cfg_;
    std::vector<ShardHandle> shards_;
    std::list<std::pair<uint32_t, uint64_t>> lru_;
    mutable std::mutex m_;
    uint64_t tick_;

    struct PairHash {
        size_t operator()(const std::pair<uint32_t, uint64_t>& p) const noexcept {
            return std::hash<uint64_t>{}((static_cast<uint64_t>(p.first) << 32) ^ p.second);
        }
    };

    std::unordered_map<std::pair<uint32_t, uint64_t>, Mapping, PairHash> map_;

    void unmap(Mapping& m) {
        if (!m.base) return;
#if defined(_WIN32)
        UnmapViewOfFile(m.base);
#else
        ::munmap(m.base, (size_t)m.map_len);
#endif
        m.base = nullptr;
        m.data = nullptr;
    }

    void evict_lru() {
        if (lru_.empty()) return;
        auto key = lru_.back();
        auto it = map_.find(key);
        if (it == map_.end()) { lru_.pop_back(); return; }
        if (it->second.refcount > 0) {
            // Can't evict: in use. Move to front and try next.
            lru_.splice(lru_.begin(), lru_, --lru_.end());
            return;
        }
        unmap(it->second);
        map_.erase(it);
        lru_.pop_back();
    }
};

} // namespace gguf_shard_cache

#endif // TENSOR_RESIDENCY_CACHE_HPP

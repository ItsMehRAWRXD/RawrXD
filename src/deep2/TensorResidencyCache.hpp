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
#include <limits>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <list>
#include <mutex>
#include <memory>
#include <optional>
#include <functional>

#if defined(_WIN32)
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
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

struct MappingKey {
    uint32_t shard = 0;
    uint64_t aligned_offset = 0;
    uint64_t map_length = 0;
    uint64_t tensor_offset = 0;

    bool operator==(const MappingKey& other) const noexcept {
        return shard == other.shard && aligned_offset == other.aligned_offset &&
               map_length == other.map_length && tensor_offset == other.tensor_offset;
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
    std::list<MappingKey>::iterator lru_it;
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
        // Hard resident mapping budget. Zero preserves the historical
        // max_active-only behavior. Pinned mappings are never evicted to make
        // room; acquisition fails closed when the budget cannot be met.
        uint64_t max_resident_bytes = 0;
    };

    explicit TensorResidencyCache(Config cfg = {}) : cfg_(cfg), tick_(0) {
#if defined(_WIN32)
        // MapViewOfFile requires alignment to the system allocation granularity
        // (typically 64 KiB), not the 4 KiB page size. Using page_size for
        // alignment on Windows can cause MapViewOfFile to fail with
        // ERROR_INVALID_PARAMETER even when the requested range is valid.
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        cfg_.page_size = (uint64_t)si.dwAllocationGranularity;
#endif
    }

    ~TensorResidencyCache() { clear(); }

    // Register a shard path. Must be called before any acquire on that shard.
    bool register_shard(uint32_t idx, const std::string& path) {
        if (idx >= shards_.size()) shards_.resize(idx + 1);
        return shards_[idx].open(path);
    }

    // Acquire a mapping for tensor [offset, offset+bytes) in shard.
    // Returns nullptr if the tensor cannot be mapped (out of cache slots,
    // shard not registered, or requested range outside shard file bounds).
    Mapping* acquire(uint32_t shard_idx, uint64_t offset, uint64_t bytes) {
        std::lock_guard<std::mutex> lk(m_);

        // Validate shard exists and is registered
        if (shard_idx >= shards_.size() || !shards_[shard_idx].size) {
            return nullptr;
        }

        // Bounds check: requested range must be within shard file (no overflow)
        if (offset > shards_[shard_idx].size ||
            bytes > shards_[shard_idx].size - offset) {
            return nullptr;
        }

        // Page-align the request (allocation granularity on Windows, page size on Unix)
        uint64_t pgsz = cfg_.page_size;
        uint64_t aligned_off = offset & ~(pgsz - 1);
        uint64_t delta = offset - aligned_off;
        if (bytes > (std::numeric_limits<uint64_t>::max)() - delta) return nullptr;
        uint64_t map_len = bytes + delta;
#if defined(_WIN32)
        if (map_len > static_cast<uint64_t>((std::numeric_limits<SIZE_T>::max)())) return nullptr;
#else
        if (map_len > static_cast<uint64_t>((std::numeric_limits<size_t>::max)())) return nullptr;
#endif

        // Reuse any resident view at this aligned offset that covers the
        // request.  Multiple tensors can begin in the same allocation-granule
        // window with different lengths; a smaller pinned view must never be
        // unmapped just because a later tensor needs a larger view.
        for (auto it = map_.begin(); it != map_.end(); ++it) {
            if (it->first.shard != shard_idx || it->first.aligned_offset != aligned_off ||
                it->first.tensor_offset != offset || delta + bytes > it->second.map_len)
                continue;
            it->second.refcount++;
            it->second.last_use = ++tick_;
            lru_.splice(lru_.begin(), lru_, it->second.lru_it);
            return &it->second;
        }
        // Enforce both the entry count and the optional byte budget before
        // creating a new mapping. The mapped length includes the alignment
        // delta, so this is the exact resident charge, not tensor_bytes alone.
        const auto over_budget = [&]() {
            if (cfg_.max_resident_bytes == 0) return false;
            const uint64_t resident = total_resident_bytes_locked();
            return resident > cfg_.max_resident_bytes ||
                   map_len > cfg_.max_resident_bytes - resident;
        };
        if (cfg_.max_resident_bytes != 0 &&
            over_budget()) {
            size_t attempts = map_.size();
            while (attempts-- > 0 &&
                   (map_.size() >= cfg_.max_active ||
                    over_budget())) {
                evict_lru();
            }
        } else {
            size_t attempts = map_.size();
            while (attempts-- > 0 && map_.size() >= cfg_.max_active) evict_lru();
        }
        if (map_.size() >= cfg_.max_active ||
            (cfg_.max_resident_bytes != 0 &&
             over_budget())) {
            return nullptr;  // pinned entries or hard budget prevent admission
        }

        // Create new mapping
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

        MappingKey key{shard_idx, aligned_off, map_len, offset};
        auto lru_it = lru_.insert(lru_.begin(), key);
        auto ins = map_.emplace(key, std::move(m));
        if (!ins.second) {
            unmap(ins.first->second);
            lru_.erase(lru_it);
            return nullptr;
        }
        resident_bytes_ += ins.first->second.map_len;
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
        return total_resident_bytes_locked();
    }

    // Charge a bounded non-mapped buffer (for example, browser evidence
    // retained by HEXMag) against the same hard residency budget used by
    // tensor mappings.  A zero budget intentionally rejects external
    // charges: callers must opt into a finite REAP budget before retaining
    // data.  The caller must release exactly the amount it reserved.
    bool reserve_external(uint64_t bytes) {
        if (bytes == 0) return false;
        std::lock_guard<std::mutex> lk(m_);
        if (cfg_.max_resident_bytes == 0) return false;
        const uint64_t resident = total_resident_bytes_locked();
        if (bytes > cfg_.max_resident_bytes ||
            resident > cfg_.max_resident_bytes - bytes) {
            return false;
        }
        external_resident_bytes_ += bytes;
        return true;
    }

    void release_external(uint64_t bytes) {
        if (bytes == 0) return;
        std::lock_guard<std::mutex> lk(m_);
        external_resident_bytes_ = bytes >= external_resident_bytes_
            ? 0 : external_resident_bytes_ - bytes;
    }

    uint64_t external_resident_bytes() const {
        std::lock_guard<std::mutex> lk(m_);
        return external_resident_bytes_;
    }

    uint64_t resident_budget_bytes() const {
        std::lock_guard<std::mutex> lk(m_);
        return cfg_.max_resident_bytes;
    }

private:
    Config cfg_;
    std::vector<ShardHandle> shards_;
    std::list<MappingKey> lru_;
    mutable std::mutex m_;
    uint64_t tick_;
    uint64_t resident_bytes_ = 0;
    uint64_t external_resident_bytes_ = 0;

    uint64_t total_resident_bytes_locked() const {
        if (external_resident_bytes_ >
            (std::numeric_limits<uint64_t>::max)() - resident_bytes_) {
            return (std::numeric_limits<uint64_t>::max)();
        }
        return resident_bytes_ + external_resident_bytes_;
    }

    struct PairHash {
        size_t operator()(const MappingKey& key) const noexcept {
            size_t h = std::hash<uint64_t>{}((static_cast<uint64_t>(key.shard) << 32) ^ key.aligned_offset);
            h ^= std::hash<uint64_t>{}(key.map_length) + static_cast<size_t>(0x9e3779b97f4a7c15ull) +
                 (h << 6) + (h >> 2);
            h ^= std::hash<uint64_t>{}(key.tensor_offset) + static_cast<size_t>(0x517cc1b727220a95ull) +
                 (h << 6) + (h >> 2);
            return h;
        }
    };

    std::unordered_map<MappingKey, Mapping, PairHash> map_;
    void unmap(Mapping& m) {
        if (!m.base) return;
 #if defined(_WIN32)
        UnmapViewOfFile(m.base);
#else
        ::munmap(m.base, (size_t)m.map_len);
#endif
        if (m.map_len <= resident_bytes_) resident_bytes_ -= m.map_len;
        else resident_bytes_ = 0;
        m.base = nullptr;
        m.data = nullptr;
        m.map_len = 0;
    }

    // Evict the least recently used mapping. Returns true if an entry was
    // evicted, false if no entry could be evicted (all pinned or empty).
    bool evict_lru() {
        if (lru_.empty()) return false;
        auto key = lru_.back();
        auto it = map_.find(key);
        if (it == map_.end()) { lru_.pop_back(); return true; }
        if (it->second.refcount > 0) {
            // Can't evict: in use. Move to front (MRU) — stays resident.
            lru_.splice(lru_.begin(), lru_, --lru_.end());
            return false;
        }
        unmap(it->second);
        map_.erase(it);
        lru_.pop_back();
        return true;
    }
};

} // namespace gguf_shard_cache

#endif // TENSOR_RESIDENCY_CACHE_HPP

// RawrXD_WeightResidencyPool.hpp — Production multi-tensor residency
// Header-only, zero-allocation on hot path, LRU eviction with pin semantics.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <functional>

#ifdef _WIN32
#include <stdlib.h>
#define RAWRXD_ALIGNED_ALLOC(align, size) _aligned_malloc(size, align)
#define RAWRXD_ALIGNED_FREE(ptr) _aligned_free(ptr)
#else
#define RAWRXD_ALIGNED_ALLOC(align, size) aligned_alloc(align, size)
#define RAWRXD_ALIGNED_FREE(ptr) free(ptr)
#endif

namespace rawrxd {

struct ResidentWeight {
    std::string name;
    float* data = nullptr;
    size_t bytes = 0;
    size_t last_used = 0;
    uint32_t refs = 0;
    bool pinned = false;
    bool resident = false;
};

class WeightResidencyPool {
public:
    explicit WeightResidencyPool(size_t max_bytes) : max_bytes_(max_bytes) {}

    ~WeightResidencyPool() {
        for (auto& [name, w] : weights_) {
            if (w.data) RAWRXD_ALIGNED_FREE(w.data);
        }
    }

    // Fast-path: O(1) lookup. Returns nullptr on miss.
    ResidentWeight* acquire(const std::string& name) {
        auto it = weights_.find(name);
        if (it == weights_.end() || !it->second.resident) {
            misses_.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        hits_.fetch_add(1, std::memory_order_relaxed);
        it->second.last_used = ++clock_;
        it->second.refs++;
        touch_lru(name);
        return &it->second;
    }

    // Slow-path: commit newly dequantized weight to residency.
    bool commit(const std::string& name, float* src, size_t bytes) {
        if (bytes > max_bytes_) return false; // Never fit
        
        // Evict until space available (unless pinned blocks us)
        while (resident_bytes_ + bytes > max_bytes_) {
            if (!evict_lru()) break; // All pinned or empty
        }
        if (resident_bytes_ + bytes > max_bytes_) return false;

        auto it = weights_.find(name);
        if (it == weights_.end()) {
            ResidentWeight w;
            w.name = name;
            w.bytes = bytes;
            w.data = (float*)RAWRXD_ALIGNED_ALLOC(64, bytes);
            if (!w.data) return false;
            std::memcpy(w.data, src, bytes);
            w.resident = true;
            w.last_used = ++clock_;
            w.refs = 0;  // No active references until acquire()
            
            weights_[name] = std::move(w);
            lru_.push_back(name);
            lru_pos_[name] = --lru_.end();
            resident_bytes_ += bytes;
            commits_.fetch_add(1, std::memory_order_relaxed);
            return true;
        } else {
            // Re-commit (update data)
            if (it->second.data && it->second.bytes != bytes) {
                RAWRXD_ALIGNED_FREE(it->second.data);
                it->second.data = (float*)RAWRXD_ALIGNED_ALLOC(64, bytes);
            }
            if (!it->second.data) it->second.data = (float*)RAWRXD_ALIGNED_ALLOC(64, bytes);
            std::memcpy(it->second.data, src, bytes);
            it->second.bytes = bytes;
            it->second.resident = true;
            it->second.last_used = ++clock_;
            it->second.refs = 0;  // Reset refs on re-commit
            resident_bytes_ += bytes;
            commits_.fetch_add(1, std::memory_order_relaxed);
            touch_lru(name);
            return true;
        }
    }

    void release(const std::string& name) {
        auto it = weights_.find(name);
        if (it != weights_.end() && it->second.refs > 0) {
            it->second.refs--;
        }
    }

    void pin(const std::string& name) {
        auto it = weights_.find(name);
        if (it != weights_.end()) it->second.pinned = true;
    }

    void unpin(const std::string& name) {
        auto it = weights_.find(name);
        if (it != weights_.end()) it->second.pinned = false;
    }

    // Prefetch hint: pin layer N+1 while computing layer N
    void prefetch_layer(int layer_idx, const std::vector<std::string>& tensor_names,
                        std::function<float*(const std::string&, size_t*)> loader) {
        for (const auto& t : tensor_names) {
            if (acquire(t)) continue; // Already resident
            size_t bytes = 0;
            float* tmp = loader(t, &bytes);
            if (tmp) {
                commit(t, tmp, bytes);
                pin(t); // Keep it for next iteration
            }
        }
    }

    size_t resident_bytes() const { return resident_bytes_; }
    size_t hits() const { return hits_.load(); }
    size_t misses() const { return misses_.load(); }
    size_t commits() const { return commits_.load(); }
    float hit_rate() const {
        size_t h = hits_.load(), m = misses_.load();
        return (h + m) > 0 ? (float)h / (float)(h + m) : 0.0f;
    }

private:
    void touch_lru(const std::string& name) {
        auto it = lru_pos_.find(name);
        if (it != lru_pos_.end()) {
            lru_.splice(lru_.end(), lru_, it->second);
            it->second = --lru_.end();
        }
    }

    bool evict_lru() {
        for (auto it = lru_.begin(); it != lru_.end(); ++it) {
            auto w_it = weights_.find(*it);
            if (w_it != weights_.end() && w_it->second.refs == 0 && !w_it->second.pinned) {
                resident_bytes_ -= w_it->second.bytes;
                RAWRXD_ALIGNED_FREE(w_it->second.data);
                w_it->second.data = nullptr;
                w_it->second.resident = false;
                w_it->second.bytes = 0;
                lru_pos_.erase(*it);
                lru_.erase(it);
                return true;
            }
        }
        return false; // Everything pinned or referenced
    }

    static void* aligned_alloc(size_t align, size_t size) {
        #ifdef _WIN32
        return _aligned_malloc(size, align);
        #else
        void* p = nullptr;
        posix_memalign(&p, align, size);
        return p;
        #endif
    }

    static void aligned_free(void* p) {
        #ifdef _WIN32
        _aligned_free(p);
        #else
        free(p);
        #endif
    }

    size_t max_bytes_;
    size_t resident_bytes_ = 0;
    size_t clock_ = 0;
    std::atomic<size_t> hits_{0};
    std::atomic<size_t> misses_{0};
    std::atomic<size_t> commits_{0};

    std::unordered_map<std::string, ResidentWeight> weights_;
    std::list<std::string> lru_;
    std::unordered_map<std::string, std::list<std::string>::iterator> lru_pos_;
};

} // namespace rawrxd

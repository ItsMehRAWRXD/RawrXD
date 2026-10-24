// Deep2Q4KColumnSlices.hpp -- immutable quantized dual-GPU column splits.
// No Qt, Vulkan, external libraries, or run-time dependencies beyond C++20.
// Snapshots keep weight buffers alive across concurrent cache rebuilds.
#pragma once
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace Deep2 {
struct Q4KColumnSlices {
    uint32_t cols0 = 0, cols1 = 0;
    std::vector<uint8_t> w0, w1;
};

class Q4KColumnSliceCache {
public:
    using Snapshot = std::shared_ptr<const Q4KColumnSlices>;

    // Cache only a bounded working set; active GPU callers own snapshots.
    static constexpr size_t kMaxCachedBytes = 256ull * 1024ull * 1024ull;
    explicit Q4KColumnSliceCache(size_t maxCachedBytes = kMaxCachedBytes) noexcept
        : maxCachedBytes_(maxCachedBytes) {}

    Snapshot get(const void* source, size_t availableBytes, size_t rows,
                 size_t cols, uint32_t requestedBlocks0) {
        constexpr size_t blockColumns = 256, blockBytes = 144;
        if (!source || !rows || !cols || cols % blockColumns != 0 ||
            cols > std::numeric_limits<uint32_t>::max()) return {};
        const size_t blocks = cols / blockColumns;
        if (blocks < 2 || requestedBlocks0 == 0 ||
            requestedBlocks0 >= blocks ||
            blocks > std::numeric_limits<size_t>::max() / blockBytes) return {};
        const size_t rowBytes = blocks * blockBytes;
        if (rows > std::numeric_limits<size_t>::max() / rowBytes ||
            rows * rowBytes > availableBytes) return {};
        const size_t bytes0 = (size_t)requestedBlocks0 * blockBytes;
        const size_t bytes1 = rowBytes - bytes0;

        // Do not hold the cache mutex while copying megabytes of Q4_K data.
        // Capture the generation so clear() cannot resurrect stale weights.
        size_t generation = 0;
        {
            std::unique_lock<std::mutex> guard(mu_);
            generation = generation_;
            auto it = cache_.find(source);
            if (it != cache_.end() && it->second.rows == rows &&
                it->second.cols == cols && it->second.bytes == availableBytes &&
                it->second.snapshot) {
                const uint32_t old = it->second.blocks0;
                const bool near = blocks >= 64 &&
                    (old == requestedBlocks0 + 1 || old + 1 == requestedBlocks0);
                if (old == requestedBlocks0 || near) return it->second.snapshot;
            }
            // Single-flight repacking: only one caller copies a given source.
            // Other weights may repack concurrently without holding mu_.
            while (inflight_.find(source) != inflight_.end()) {
                cv_.wait(guard);
                if (generation != generation_) return {};
                it = cache_.find(source);
                if (it != cache_.end() && it->second.rows == rows &&
                    it->second.cols == cols && it->second.bytes == availableBytes &&
                    it->second.snapshot) {
                    const uint32_t old = it->second.blocks0;
                    const bool near = blocks >= 64 &&
                        (old == requestedBlocks0 + 1 || old + 1 == requestedBlocks0);
                    if (old == requestedBlocks0 || near) return it->second.snapshot;
                }
            }
            // Reserve before publishing in-flight state. Allocation failure
            // must not leave waiters blocked on a key with no active owner.
            inflight_.insert(source);
        }

        Snapshot fresh;
        try {
            auto packed = std::make_shared<Q4KColumnSlices>();
            packed->cols0 = requestedBlocks0 * static_cast<uint32_t>(blockColumns);
            packed->cols1 = static_cast<uint32_t>(cols) - packed->cols0;
            packed->w0.resize(rows * bytes0);
            packed->w1.resize(rows * bytes1);
            const auto* raw = static_cast<const uint8_t*>(source);
            for (size_t row = 0; row < rows; ++row) {
                std::memcpy(packed->w0.data() + row * bytes0,
                            raw + row * rowBytes, bytes0);
                std::memcpy(packed->w1.data() + row * bytes1,
                            raw + row * rowBytes + bytes0, bytes1);
            }
            fresh = std::move(packed);
        } catch (...) {
            std::lock_guard<std::mutex> guard(mu_);
            inflight_.erase(source);
            cv_.notify_all();
            throw;
        }
        {
            std::lock_guard<std::mutex> guard(mu_);
            if (generation != generation_) {
                inflight_.erase(source);
                cv_.notify_all();
                return {};
            }
            // Keep the reservation until publication succeeds; on allocation
            // failure wake waiters so another caller can retry safely.
            try {
                // An oversized tensor is still returned to this caller, but
                // never retained in the cache. This prevents a model reload
                // from accumulating unbounded host-side packed duplicates.
                const size_t packedBytes = fresh->w0.size() + fresh->w1.size();
                if (packedBytes <= maxCachedBytes_) {
                    auto existing = cache_.find(source);
                    if (existing != cache_.end()) {
                        cachedBytes_ -= existing->second.snapshot->w0.size()
                                      + existing->second.snapshot->w1.size();
                        cache_.erase(existing);
                    }
                    while (cachedBytes_ > maxCachedBytes_ - packedBytes &&
                           !cache_.empty()) {
                        auto victim = cache_.begin();
                        cachedBytes_ -= victim->second.snapshot->w0.size()
                                      + victim->second.snapshot->w1.size();
                        cache_.erase(victim);
                    }
                    cache_[source] = Entry{rows, cols, availableBytes, requestedBlocks0, fresh};
                    cachedBytes_ += packedBytes;
                }
                ++rebuilds_;
            } catch (...) {
                inflight_.erase(source);
                cv_.notify_all();
                throw;
            }
            inflight_.erase(source);
            cv_.notify_all();
        }
        return fresh;
    }

    void clear() noexcept {
        std::lock_guard<std::mutex> guard(mu_);
        ++generation_;
        cache_.clear();
        cachedBytes_ = 0;
        cv_.notify_all();
    }
    size_t cachedBytes() const noexcept {
        std::lock_guard<std::mutex> guard(mu_);
        return cachedBytes_;
    }
    size_t rebuilds() const noexcept {
        std::lock_guard<std::mutex> guard(mu_);
        return rebuilds_;
    }

private:
    struct Entry {
        size_t rows, cols, bytes;
        uint32_t blocks0;
        Snapshot snapshot;
    };
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::unordered_set<const void*> inflight_;
    std::unordered_map<const void*, Entry> cache_;
    size_t maxCachedBytes_ = kMaxCachedBytes;
    size_t cachedBytes_ = 0;
    size_t rebuilds_ = 0;
    size_t generation_ = 0;
};
} // namespace Deep2
